"""Google Cloud containment: service accounts, their keys, and instances.

API references (read before writing this client, and the source of every
path and field below):
  IAM service accounts — https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts
  IAM keys            — https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys
  Compute instances   — https://cloud.google.com/compute/docs/reference/rest/v1/instances
  Compute disks       — https://cloud.google.com/compute/docs/reference/rest/v1/disks/createSnapshot

What this is for
----------------
Depth 5.5. A service account key is the GCP equivalent of a leaked AWS access
key and is the credential most often found in a public repository, and
nothing in this platform could touch one. The same for a compromised
instance: Compute Engine instances frequently run no agent.

Four verbs
----------
* **Disable a service account** (`:disable`). The whole identity stops
  authenticating; reversible with `:enable`, which is why both ship.
* **Disable one key** (`keys/{id}:disable`). Narrower, and the right action
  when one key leaked and the account is otherwise fine. Google added these
  two endpoints precisely so that responding to a leaked key does not mean
  deleting it and losing the audit trail.
* **Quarantine an instance** — replace its network tags with one tag, so the
  deny-all firewall rule an operator pre-creates for that tag is the only
  rule that matches. Deliberately not `instances/stop`: stopping discards
  memory and ends every forensic option that needs a running system.
* **Snapshot its disks** (`disks/{disk}/createSnapshot`). Evidence before
  containment.

The quarantine needs something the operator built
--------------------------------------------------
A network tag does nothing on its own; the firewall rule that denies traffic
for that tag has to exist in the VPC. The client cannot create it — doing so
would mean writing firewall rules into a customer's project from an
automation — so the executor's contract says the rule is a prerequisite and
the result records the tag that was applied. The alternative, silently
applying a tag that matches no rule, would report containment and change
nothing, which is the single worst outcome available here.

**No call has been made against live GCP from this repository.** There is no
funded project here; the tests drive the real token exchange and parsing
against recorded payloads through `httpx.MockTransport`.
"""

from __future__ import annotations

import base64
import json
import re
import time
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_TOKEN_URI = "https://oauth2.googleapis.com/token"
#: Project-level containment needs the full platform scope; there is no
#: narrower published scope that covers both IAM admin and Compute admin.
#: Named here so an operator reading the client knows what the key they
#: mint has to be able to do.
_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

_IAM_BASE = "https://iam.googleapis.com/v1"
_COMPUTE_BASE = "https://compute.googleapis.com/compute/v1"

#: GCP resource names are a closed character set, and these are interpolated
#: into a URL path. Validated rather than escaped: a path segment that
#: escapes to something harmless still addresses the wrong resource, and on
#: a containment verb "we disabled something else" is worse than an error.
_PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_SERVICE_ACCOUNT = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.(iam\.)?gserviceaccount\.com$")
_KEY_ID = re.compile(r"^[0-9a-f]{10,80}$")
_NAME = re.compile(r"^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$")
_ZONE = re.compile(r"^[a-z]+-[a-z]+[0-9]-[a-z]$")


class GcpActionError(RuntimeError):
    """The action could not be performed. Never a silent partial success."""


def _require(pattern: re.Pattern[str], value: str, what: str) -> str:
    cleaned = (value or "").strip()
    if not pattern.match(cleaned):
        raise GcpActionError(f"{what} {value!r} is not a well-formed GCP identifier; it was refused rather than sent")
    return cleaned


class _GoogleCloudAuth:
    """Service-account JWT exchanged for an access token.

    Signed inline rather than through `google-auth`, matching
    `google_workspace_client.py`: the claim set is fixed and the crypto is
    one RSA-SHA256 signature, and adding an SDK for it would be a dependency
    this service does not otherwise need.

    No `sub` claim, which is the difference from the Workspace client next
    door. Workspace impersonates a human administrator through domain-wide
    delegation; a Google Cloud service account acts as itself, and adding a
    `sub` there produces an `unauthorized_client` an operator reads as a
    wrong key.
    """

    def __init__(self, service_account_key: dict[str, Any] | str) -> None:
        if isinstance(service_account_key, str):
            try:
                service_account_key = json.loads(service_account_key)
            except json.JSONDecodeError as exc:
                raise GcpActionError(f"gcp_service_account_key is not valid JSON: {exc}") from exc
        if not isinstance(service_account_key, dict):
            raise GcpActionError(f"gcp_service_account_key must be a JSON object, got {type(service_account_key).__name__}")
        for field in ("client_email", "private_key"):
            if not service_account_key.get(field):
                raise GcpActionError(f"gcp_service_account_key is missing {field!r}, so no token can be minted")
        self._key = service_account_key
        self._token: str | None = None
        self._expiry = 0.0

    async def token(self, http: httpx.AsyncClient) -> str:
        if self._token and time.time() < self._expiry:
            return self._token

        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        now = int(time.time())

        def _b64(blob: dict) -> str:
            return base64.urlsafe_b64encode(json.dumps(blob, separators=(",", ":")).encode()).rstrip(b"=").decode()

        signing_input = (
            f"{_b64({'alg': 'RS256', 'typ': 'JWT'})}."
            f"{_b64({'iss': self._key['client_email'], 'scope': _SCOPE, 'aud': _TOKEN_URI, 'iat': now, 'exp': now + 3600})}"
        ).encode()
        private_key = serialization.load_pem_private_key(self._key["private_key"].encode(), password=None)
        signature = base64.urlsafe_b64encode(private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())).rstrip(b"=").decode()

        response = await http.post(
            _TOKEN_URI,
            data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": f"{signing_input.decode()}.{signature}"},
        )
        if response.status_code >= 400:
            raise GcpActionError(f"GCP token exchange failed: HTTP {response.status_code} {response.text[:200]}")
        body = response.json()
        self._token = str(body["access_token"])
        self._expiry = time.time() + int(body.get("expires_in", 3600)) - 60
        return self._token


class GcpClient:
    """IAM and Compute containment for one project.

    One class rather than two because the two share a token and a project,
    and a caller holding two objects that must agree about both is a caller
    who will eventually let them disagree.
    """

    def __init__(
        self,
        *,
        project_id: str,
        service_account_key: dict[str, Any] | str,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 25.0,
    ) -> None:
        self._project = _require(_PROJECT, project_id, "project id")
        self._auth = _GoogleCloudAuth(service_account_key)
        self._transport = transport
        self._timeout = timeout

    async def _request(self, method: str, url: str, *, json_body: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(transport=self._transport, timeout=self._timeout) as http:
            token = await self._auth.token(http)
            response = await http.request(
                method,
                url,
                json=json_body,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
        if response.status_code >= 400:
            raise GcpActionError(f"GCP {method} {url.split('?', 1)[0]} failed: HTTP {response.status_code} {response.text[:300]}")
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise GcpActionError(f"GCP {method} returned a body that is not JSON: {exc}") from exc

    # ── Service accounts ────────────────────────────────────────────────────

    def _sa_name(self, email: str) -> str:
        return f"projects/{self._project}/serviceAccounts/{_require(_SERVICE_ACCOUNT, email, 'service account')}"

    async def set_service_account_disabled(self, email: str, *, disabled: bool) -> dict[str, Any]:
        """`:disable` or `:enable`, then read the account back.

        Both endpoints answer `{}` on success, so without the read "the
        account is disabled" would be a restatement of the request.
        """
        name = self._sa_name(email)
        await self._request("POST", f"{_IAM_BASE}/{name}:{'disable' if disabled else 'enable'}", json_body={})
        observed = await self.service_account_disabled(email)
        return {"service_account": email, "requested_disabled": disabled, "observed_disabled": observed, "verified": observed == disabled}

    async def service_account_disabled(self, email: str) -> bool | None:
        """Whether the account is disabled right now, or None if unreadable.

        `disabled` is **absent** from the response for an enabled account
        rather than present and false, so a reader that uses `.get("disabled")`
        without a default would read `None` and a caller comparing it to
        `False` would conclude the account is in neither state.
        """
        record = await self._request("GET", f"{_IAM_BASE}/{self._sa_name(email)}")
        if not record:
            return None
        return bool(record.get("disabled", False))

    async def set_service_account_key_disabled(self, email: str, key_id: str, *, disabled: bool) -> dict[str, Any]:
        """Disable or enable one key, leaving the identity itself working."""
        name = f"{self._sa_name(email)}/keys/{_require(_KEY_ID, key_id, 'service account key id')}"
        await self._request("POST", f"{_IAM_BASE}/{name}:{'disable' if disabled else 'enable'}", json_body={})
        record = await self._request("GET", f"{_IAM_BASE}/{name}")
        observed = bool(record.get("disabled", False))
        return {
            "service_account": email,
            "key_id": key_id,
            "requested_disabled": disabled,
            "observed_disabled": observed,
            "verified": observed == disabled,
        }

    # ── Compute instances ───────────────────────────────────────────────────

    def _instance_url(self, zone: str, instance: str, suffix: str = "") -> str:
        return (
            f"{_COMPUTE_BASE}/projects/{self._project}/zones/{_require(_ZONE, zone, 'zone')}"
            f"/instances/{_require(_NAME, instance, 'instance name')}{suffix}"
        )

    async def describe_instance(self, zone: str, instance: str) -> dict[str, Any]:
        """Status, network tags (with their fingerprint) and attached disks.

        The fingerprint matters: `setTags` requires the one read here, and
        Compute rejects a write carrying a stale one. That is a feature —
        it is how two concurrent responders do not silently overwrite each
        other — so it is read immediately before the write rather than
        cached.
        """
        record = await self._request("GET", self._instance_url(zone, instance))
        tags = record.get("tags") or {}
        return {
            "instance": instance,
            "zone": zone,
            "status": record.get("status", ""),
            "tags": list(tags.get("items") or []),
            "tags_fingerprint": tags.get("fingerprint", ""),
            "disks": [d.get("source", "").rsplit("/", 1)[-1] for d in record.get("disks") or [] if d.get("source")],
        }

    async def quarantine_instance(self, zone: str, instance: str, quarantine_tag: str) -> dict[str, Any]:
        """Replace the instance's network tags with the quarantine tag.

        The tags it had are read first and returned: `setTags` replaces the
        whole list and Compute keeps no history of what it was, so without
        this the instance cannot be put back.
        """
        tag = _require(_NAME, quarantine_tag, "quarantine network tag")
        before = await self.describe_instance(zone, instance)
        await self._request(
            "POST",
            self._instance_url(zone, instance, "/setTags"),
            json_body={"items": [tag], "fingerprint": before["tags_fingerprint"]},
        )
        after = await self.describe_instance(zone, instance)
        return {
            "instance": instance,
            "zone": zone,
            "quarantine_tag": tag,
            "original_tags": before["tags"],
            "observed_tags": after["tags"],
            "verified": after["tags"] == [tag],
        }

    async def release_instance(self, zone: str, instance: str, tags: list[str]) -> dict[str, Any]:
        """Put the original network tags back.

        An empty list is accepted here, unlike the EC2 equivalent: an
        instance with no network tags is an ordinary and valid state in
        Compute Engine, whereas an instance with no security groups is not a
        state EC2 has.
        """
        restored = [_require(_NAME, value, "network tag") for value in tags]
        before = await self.describe_instance(zone, instance)
        await self._request(
            "POST",
            self._instance_url(zone, instance, "/setTags"),
            json_body={"items": restored, "fingerprint": before["tags_fingerprint"]},
        )
        after = await self.describe_instance(zone, instance)
        return {
            "instance": instance,
            "zone": zone,
            "restored_tags": restored,
            "observed_tags": after["tags"],
            "verified": sorted(after["tags"]) == sorted(restored),
        }

    async def snapshot_instance_disks(self, zone: str, instance: str, *, description: str = "") -> dict[str, Any]:
        """Snapshot every disk attached to the instance. Evidence first."""
        record = await self.describe_instance(zone, instance)
        if not record["disks"]:
            raise GcpActionError(f"GCP instance {instance} in {zone} has no attached disks to snapshot")

        note = (description.strip() or f"AiSOC evidence capture for {instance}")[:255]
        stamp = int(time.time())
        snapshots: list[dict[str, str]] = []
        for index, disk in enumerate(record["disks"]):
            # Snapshot names are a GCP resource name, so they go through the
            # same validator as everything else and are built rather than
            # taken from input.
            name = _require(_NAME, f"aisoc-{instance}-{stamp}-{index}"[:62].rstrip("-"), "snapshot name")
            await self._request(
                "POST",
                f"{_COMPUTE_BASE}/projects/{self._project}/zones/{zone}/disks/{_require(_NAME, disk, 'disk name')}/createSnapshot",
                json_body={"name": name, "description": note},
            )
            snapshots.append({"disk": disk, "snapshot": name})
        return {"instance": instance, "zone": zone, "snapshots": snapshots, "verified": len(snapshots) == len(record["disks"])}


__all__ = ["GcpClient", "GcpActionError"]
