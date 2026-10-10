"""AWS EC2 containment: quarantine an instance, and snapshot it first.

API reference (read before writing this client, and the source of every
action name and parameter below):
https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Operations.html

What this is for
----------------
Depth 5.5. The endpoint verbs in this service all assume an EDR agent. A
compromised cloud instance frequently has no agent on it at all — that is
often how it got compromised — and the control plane is the only way to
reach it.

Three verbs, and the order they belong in
------------------------------------------
* **Snapshot the volumes** (`CreateSnapshot`). Evidence first. Quarantining
  an instance does not destroy memory or disk, but an incident that ends in
  a terminate does, and a snapshot taken before containment costs nothing
  and is occasionally the whole investigation.
* **Quarantine** (`ModifyInstanceAttribute`, replacing the instance's
  security groups with one that permits nothing). Deliberately *not*
  `StopInstances`: stopping a machine discards its memory, ends every
  forensic option that needs a running system, and is the one containment
  action an attacker's persistence often survives better than the responder
  does. Replacing the groups cuts the network and leaves the system intact.
* **Release** (`ModifyInstanceAttribute` with the original groups). The
  reverse is real, and it needs the original group list — which is why the
  quarantine call returns it and the executor records it.

What is deliberately absent
---------------------------
`TerminateInstances` and `StopInstances`. Terminate is irreversible and
destroys the evidence; stop destroys memory. Neither belongs behind an
automation.

Verification
------------
The quarantine is followed by `DescribeInstances` and the observed group set
is returned, so "contained" means the control plane was re-read.

**No call has been made against live AWS from this repository.** The tests
drive the real signing and parsing against recorded EC2 payloads through
`httpx.MockTransport`, and the capability contracts say so.
"""

from __future__ import annotations

import re
from typing import Any
from xml.etree import ElementTree

import httpx
import structlog

from app.clients import aws_sigv4

logger = structlog.get_logger()

_SERVICE = "ec2"
_VERSION = "2016-11-15"

#: EC2 identifiers are a fixed shape. Validated rather than escaped, for the
#: reason the IAM client records: an escaped value that reaches EC2 and
#: matches nothing reports success for a containment that never happened.
_INSTANCE_ID = re.compile(r"^i-[0-9a-f]{8,32}$")
_GROUP_ID = re.compile(r"^sg-[0-9a-f]{8,32}$")
_VOLUME_ID = re.compile(r"^vol-[0-9a-f]{8,32}$")


class Ec2ActionError(RuntimeError):
    """The action could not be performed. Never a silent partial success."""


def _require(pattern: re.Pattern[str], value: str, what: str) -> str:
    cleaned = (value or "").strip()
    if not pattern.match(cleaned):
        raise Ec2ActionError(f"{what} {value!r} is not a well-formed EC2 identifier; it was refused rather than sent")
    return cleaned


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


class AWSEc2Client:
    """Signed EC2 Query-protocol calls, credentials scoped to the request."""

    def __init__(
        self,
        access_key_id: str,
        secret_access_key: str,
        *,
        region: str = "us-east-1",
        session_token: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 20.0,
    ) -> None:
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key
        self._region = region
        self._session_token = session_token
        self._transport = transport
        self._timeout = timeout

    @property
    def host(self) -> str:
        return f"{_SERVICE}.{self._region}.amazonaws.com"

    async def _call(self, action: str, params: dict[str, str]) -> ElementTree.Element:
        body = aws_sigv4.form_body({**params, "Action": action, "Version": _VERSION})
        headers = aws_sigv4.sign(
            access_key_id=self._access_key_id,
            secret_access_key=self._secret_access_key,
            session_token=self._session_token,
            region=self._region,
            service=_SERVICE,
            host=self.host,
            payload=body,
            content_type=aws_sigv4.FORM_CONTENT_TYPE,
        )
        async with httpx.AsyncClient(transport=self._transport, timeout=self._timeout) as http:
            response = await http.post(f"https://{self.host}/", content=body.encode("utf-8"), headers=headers)

        if response.status_code >= 400:
            raise Ec2ActionError(f"EC2 {action} failed: HTTP {response.status_code} {_error_detail(response.text)}")
        try:
            return ElementTree.fromstring(response.text)
        except ElementTree.ParseError as exc:
            raise Ec2ActionError(f"EC2 {action} returned a body that is not XML: {exc}") from exc

    async def describe_instance(self, instance_id: str) -> dict[str, Any]:
        """State, security groups and volumes for one instance.

        Raises rather than returning an empty record when the instance is not
        found: "we could not see it" and "it has no groups" lead to opposite
        conclusions about whether a host is contained.
        """
        instance = _require(_INSTANCE_ID, instance_id, "instance id")
        root = await self._call("DescribeInstances", {"InstanceId.1": instance})

        groups: list[str] = []
        volumes: list[str] = []
        state = ""
        found = False
        for element in root.iter():
            name = _local(element.tag)
            if name == "instanceId" and (element.text or "").strip() == instance:
                found = True
            elif name == "groupId" and (element.text or "").strip():
                groups.append(element.text.strip())
            elif name == "volumeId" and (element.text or "").strip():
                volumes.append(element.text.strip())
            elif name == "name" and (element.text or "").strip() and not state:
                state = element.text.strip()
        if not found:
            raise Ec2ActionError(f"EC2 DescribeInstances returned no record for {instance}")
        return {"instance_id": instance, "state": state, "security_groups": sorted(set(groups)), "volume_ids": sorted(set(volumes))}

    async def quarantine_instance(self, instance_id: str, quarantine_group_id: str) -> dict[str, Any]:
        """Replace the instance's security groups with one that permits nothing.

        The groups it had are read **first** and returned, because they are
        the only way back: `ModifyInstanceAttribute` replaces the whole set
        and AWS keeps no history of what it was.
        """
        instance = _require(_INSTANCE_ID, instance_id, "instance id")
        group = _require(_GROUP_ID, quarantine_group_id, "quarantine security group id")

        before = await self.describe_instance(instance)
        await self._call("ModifyInstanceAttribute", {"InstanceId": instance, "GroupId.1": group})
        after = await self.describe_instance(instance)
        return {
            "instance_id": instance,
            "quarantine_group_id": group,
            "original_security_groups": before["security_groups"],
            "observed_security_groups": after["security_groups"],
            "verified": after["security_groups"] == [group],
        }

    async def release_instance(self, instance_id: str, security_group_ids: list[str]) -> dict[str, Any]:
        """Put the original security groups back.

        Refuses an empty list rather than treating it as "remove everything":
        `ModifyInstanceAttribute` with no groups is rejected by EC2 anyway,
        and an empty list here almost always means the original set was never
        recorded — in which case the honest answer is to say so.
        """
        instance = _require(_INSTANCE_ID, instance_id, "instance id")
        groups = [_require(_GROUP_ID, value, "security group id") for value in security_group_ids]
        if not groups:
            raise Ec2ActionError(
                f"releasing {instance} needs the security groups it had before quarantine, and none were supplied. "
                f"The quarantine action records them in its result; without them the original access cannot be restored."
            )
        await self._call("ModifyInstanceAttribute", {"InstanceId": instance, **{f"GroupId.{i}": g for i, g in enumerate(groups, 1)}})
        after = await self.describe_instance(instance)
        return {
            "instance_id": instance,
            "restored_security_groups": groups,
            "observed_security_groups": after["security_groups"],
            "verified": sorted(after["security_groups"]) == sorted(groups),
        }

    async def snapshot_volumes(self, instance_id: str, *, description: str = "") -> dict[str, Any]:
        """Snapshot every volume attached to the instance.

        One `CreateSnapshot` per volume rather than
        `CreateSnapshots` (the instance-level call), because the latter is
        unavailable in several partitions and its failure mode there is a
        403 that reads like a permissions problem.
        """
        instance = _require(_INSTANCE_ID, instance_id, "instance id")
        record = await self.describe_instance(instance)
        if not record["volume_ids"]:
            raise Ec2ActionError(f"EC2 instance {instance} has no attached volumes to snapshot")

        note = description.strip() or f"AiSOC evidence capture for {instance}"
        snapshots: list[dict[str, str]] = []
        for volume_id in record["volume_ids"]:
            root = await self._call(
                "CreateSnapshot",
                {"VolumeId": _require(_VOLUME_ID, volume_id, "volume id"), "Description": note[:255]},
            )
            snapshot_id = next((e.text.strip() for e in root.iter() if _local(e.tag) == "snapshotId" and e.text), "")
            if not snapshot_id:
                raise Ec2ActionError(f"EC2 CreateSnapshot for {volume_id} returned no snapshotId")
            snapshots.append({"volume_id": volume_id, "snapshot_id": snapshot_id})
        return {"instance_id": instance, "snapshots": snapshots, "verified": len(snapshots) == len(record["volume_ids"])}


def _error_detail(body: str) -> str:
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return body[:200]
    code = next((e.text for e in root.iter() if _local(e.tag) == "Code" and e.text), "")
    message = next((e.text for e in root.iter() if _local(e.tag) == "Message" and e.text), "")
    return f"{code}: {message}".strip(": ") or body[:200]


__all__ = ["AWSEc2Client", "Ec2ActionError"]
