"""AWS IAM containment: deactivate a key, revoke role sessions, deny a principal.

API reference (read before writing this client, and the source of every
action name and parameter below):
https://docs.aws.amazon.com/IAM/latest/APIReference/API_Operations.html

What this is for
----------------
Depth 5.5. A leaked access key and a stolen role session are the two ways a
cloud estate is actually taken, and neither had an arm. The platform could
isolate a laptop and could do nothing about the credential that was being
used from the other side of the world.

Three verbs, and why these three
---------------------------------
* **Deactivate an access key** (`UpdateAccessKey`, `Status=Inactive`). The
  narrowest possible action: it stops that one credential and touches
  nothing else the principal owns. Reversible by setting `Active` again,
  which is why the reverse is implemented here rather than described.
  Deleting the key would be irreversible and would destroy the evidence of
  what it was used for.
* **Revoke active role sessions** (`PutRolePolicy`). There is no AWS API that
  invalidates an issued STS token — this is the documented technique, and it
  is worth knowing *why* it is a policy rather than a call: an inline deny on
  the role with a `DateLessThan` condition on `aws:TokenIssueTime` makes
  every session minted before this moment unusable while leaving new ones to
  work. The console's "Revoke sessions" button writes exactly this policy.
  Reference:
  https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html
* **Deny a principal** (`AttachUserPolicy` with `AWSDenyAll`). AWS has no
  "disable user": the managed `AWSDenyAll` policy is how an account is
  stopped without deleting it. Reversible by detaching.

What is deliberately absent
---------------------------
`DeleteAccessKey`, `DeleteLoginProfile` and `DeleteUser`. Each is
irreversible, each destroys evidence an investigation needs, and none of
them does anything the three above do not.

Verification
------------
Each write is followed by the matching read (`ListAccessKeys`,
`GetRolePolicy`, `ListAttachedUserPolicies`) and the observed state is
returned to the caller, so "succeeded" means the estate was re-read rather
than that AWS accepted a request.

**No call has been made against live AWS from this repository.** There is no
funded account here; the tests drive the real signing and parsing against
recorded IAM payloads through `httpx.MockTransport`, and the capability
contracts say so rather than implying a live verification that has not
happened.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from typing import Any
from xml.etree import ElementTree

import httpx
import structlog

from app.clients import aws_sigv4

logger = structlog.get_logger()

_SERVICE = "iam"
#: IAM is a global service and signs against us-east-1 whatever region the
#: estate runs in. Hardcoding it is correct rather than lazy; parameterising
#: it would produce signatures AWS rejects for every non-default region.
_REGION = "us-east-1"
_HOST = "iam.amazonaws.com"
_VERSION = "2010-05-08"

#: The AWS-managed policy that denies everything. An ARN rather than an
#: inline document: it is maintained by AWS, it is the same in every
#: partition-matching account, and an inline copy would be one more thing to
#: keep correct.
DENY_ALL_POLICY_ARN = "arn:aws:iam::aws:policy/AWSDenyAll"

#: The inline policy name the AWS console itself uses for session revocation.
#: Matching it means an operator who looks at the role in the console sees
#: the policy they expect, and a second revocation replaces rather than
#: stacks.
REVOKE_POLICY_NAME = "AWSRevokeOlderSessions"

#: IAM names are a closed character set and these values are interpolated
#: into a policy document and a request. Validated rather than escaped: an
#: escaped value that reaches IAM and matches nothing reports success for a
#: revocation that never happened, which on a containment action is worse
#: than an error.
_IAM_NAME = re.compile(r"^[\w+=,.@-]{1,128}$")
_ACCESS_KEY_ID = re.compile(r"^[A-Z0-9]{16,128}$")


class IamActionError(RuntimeError):
    """The action could not be performed. Never a silent partial success."""


def _require(pattern: re.Pattern[str], value: str, what: str) -> str:
    cleaned = (value or "").strip()
    if not pattern.match(cleaned):
        raise IamActionError(f"{what} {value!r} is not a well-formed IAM identifier; it was refused rather than sent")
    return cleaned


def _text(root: ElementTree.Element, path: str) -> str:
    """One element's text from an IAM Query-protocol response.

    IAM responses are namespaced XML. Matching on the local name rather than
    registering the namespace keeps the parsing working across the two
    namespace URIs IAM has used.
    """
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == path:
            return (element.text or "").strip()
    return ""


class AWSIamClient:
    """Signed IAM Query-protocol calls, credentials scoped to the request.

    Credentials are per-call rather than per-process, like every other client
    in this directory: a multi-tenant deployment routes two tenants to two
    AWS accounts in one process, and a client holding one account's key would
    make that impossible.
    """

    def __init__(
        self,
        access_key_id: str,
        secret_access_key: str,
        *,
        session_token: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 20.0,
    ) -> None:
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key
        self._session_token = session_token
        self._transport = transport
        self._timeout = timeout

    async def _call(self, action: str, params: dict[str, str], *, now: dt.datetime | None = None) -> ElementTree.Element:
        body = aws_sigv4.form_body({**params, "Action": action, "Version": _VERSION})
        headers = aws_sigv4.sign(
            access_key_id=self._access_key_id,
            secret_access_key=self._secret_access_key,
            session_token=self._session_token,
            region=_REGION,
            service=_SERVICE,
            host=_HOST,
            payload=body,
            content_type=aws_sigv4.FORM_CONTENT_TYPE,
            now=now,
        )
        async with httpx.AsyncClient(transport=self._transport, timeout=self._timeout) as http:
            response = await http.post(f"https://{_HOST}/", content=body.encode("utf-8"), headers=headers)

        if response.status_code >= 400:
            # IAM puts a machine-readable code in the body. Surfaced rather
            # than the status alone, because `AccessDenied` and
            # `NoSuchEntity` send an operator to completely different places.
            detail = _error_detail(response.text)
            raise IamActionError(f"IAM {action} failed: HTTP {response.status_code} {detail}")
        try:
            return ElementTree.fromstring(response.text)
        except ElementTree.ParseError as exc:
            raise IamActionError(f"IAM {action} returned a body that is not XML: {exc}") from exc

    # ── Access keys ─────────────────────────────────────────────────────────

    async def set_access_key_status(self, user_name: str, access_key_id: str, *, status: str) -> dict[str, Any]:
        """`UpdateAccessKey`, then read the key back.

        The read is the point. `UpdateAccessKey` answers 200 with an empty
        body, so without `ListAccessKeys` afterwards "the key is inactive" is
        a restatement of the request rather than an observation.
        """
        if status not in {"Active", "Inactive"}:
            raise IamActionError(f"access key status must be Active or Inactive, not {status!r}")
        user = _require(_IAM_NAME, user_name, "user name")
        key = _require(_ACCESS_KEY_ID, access_key_id, "access key id")

        await self._call("UpdateAccessKey", {"UserName": user, "AccessKeyId": key, "Status": status})
        observed = await self.access_key_status(user, key)
        return {
            "user_name": user,
            "access_key_id": key,
            "requested_status": status,
            "observed_status": observed,
            "verified": observed == status,
        }

    async def access_key_status(self, user_name: str, access_key_id: str) -> str | None:
        """The key's current status, or None when the key is not there."""
        root = await self._call("ListAccessKeys", {"UserName": _require(_IAM_NAME, user_name, "user name")})
        for member in root.iter():
            if member.tag.rsplit("}", 1)[-1] != "member":
                continue
            if _text(member, "AccessKeyId") == access_key_id:
                return _text(member, "Status") or None
        return None

    # ── Role sessions ───────────────────────────────────────────────────────

    async def revoke_role_sessions(self, role_name: str, *, issued_before: dt.datetime | None = None) -> dict[str, Any]:
        """Deny every session minted before now, by inline policy.

        The cutoff is this moment by default. An explicit `issued_before` is
        accepted because an incident timeline sometimes says "everything
        after 02:14 is suspect" and a narrower revocation disrupts fewer
        people.
        """
        role = _require(_IAM_NAME, role_name, "role name")
        cutoff = (issued_before or dt.datetime.now(dt.UTC)).astimezone(dt.UTC)
        document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": ["*"],
                    "Resource": ["*"],
                    "Condition": {"DateLessThan": {"aws:TokenIssueTime": cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")}},
                }
            ],
        }
        await self._call(
            "PutRolePolicy",
            {"RoleName": role, "PolicyName": REVOKE_POLICY_NAME, "PolicyDocument": json.dumps(document, separators=(",", ":"))},
        )
        observed = await self.role_policy_present(role)
        return {"role_name": role, "issued_before": cutoff.isoformat(), "policy_name": REVOKE_POLICY_NAME, "verified": observed}

    async def restore_role_sessions(self, role_name: str) -> dict[str, Any]:
        """Remove the revocation policy. The reverse, and it is a real one."""
        role = _require(_IAM_NAME, role_name, "role name")
        await self._call("DeleteRolePolicy", {"RoleName": role, "PolicyName": REVOKE_POLICY_NAME})
        return {"role_name": role, "policy_name": REVOKE_POLICY_NAME, "verified": not await self.role_policy_present(role)}

    async def role_policy_present(self, role_name: str) -> bool:
        """Whether the revocation policy is attached right now."""
        try:
            root = await self._call("GetRolePolicy", {"RoleName": role_name, "PolicyName": REVOKE_POLICY_NAME})
        except IamActionError as exc:
            # `NoSuchEntity` is the answer "it is not attached", not a
            # failure. Anything else is a failure and is re-raised, because
            # reporting an unreadable estate as "not contained" is the same
            # defect as reporting it as "contained".
            if "NoSuchEntity" in str(exc):
                return False
            raise
        return _text(root, "PolicyName") == REVOKE_POLICY_NAME

    # ── Principals ──────────────────────────────────────────────────────────

    async def deny_user(self, user_name: str) -> dict[str, Any]:
        """Attach `AWSDenyAll`. AWS's nearest equivalent to disabling a user."""
        user = _require(_IAM_NAME, user_name, "user name")
        await self._call("AttachUserPolicy", {"UserName": user, "PolicyArn": DENY_ALL_POLICY_ARN})
        return {"user_name": user, "policy_arn": DENY_ALL_POLICY_ARN, "verified": await self.user_denied(user)}

    async def allow_user(self, user_name: str) -> dict[str, Any]:
        """Detach `AWSDenyAll`, restoring whatever the principal had before."""
        user = _require(_IAM_NAME, user_name, "user name")
        await self._call("DetachUserPolicy", {"UserName": user, "PolicyArn": DENY_ALL_POLICY_ARN})
        return {"user_name": user, "policy_arn": DENY_ALL_POLICY_ARN, "verified": not await self.user_denied(user)}

    async def user_denied(self, user_name: str) -> bool:
        """Whether `AWSDenyAll` is attached to this principal right now."""
        root = await self._call("ListAttachedUserPolicies", {"UserName": user_name})
        return any(
            member.tag.rsplit("}", 1)[-1] == "member" and _text(member, "PolicyArn") == DENY_ALL_POLICY_ARN for member in root.iter()
        )


def _error_detail(body: str) -> str:
    """IAM's own error code and message, when the body carries one."""
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return body[:200]
    code = _text(root, "Code")
    message = _text(root, "Message")
    return f"{code}: {message}".strip(": ") or body[:200]


__all__ = ["AWSIamClient", "IamActionError", "DENY_ALL_POLICY_ARN", "REVOKE_POLICY_NAME"]
