"""Cloud control-plane arms: AWS, Azure and Google Cloud.

Depth plan 5.5, the half the plan puts first — "the cloud and SaaS
containment the reference platform automates, where the vendor's API allows
it".

The gap these close
-------------------
Every containment verb in this service assumed an agent on a machine. An
estate is more often taken through a credential: a leaked access key, a
stolen role session, a consented OAuth application, a workload identity with
a secret in a repository. None of those had an arm, so the honest answer to
"somebody is using this access key from another continent" was a ticket.

Two rules every arm here follows, both inherited from `vendor_breadth.py`
and both about not lying:

**A failure is reported, never absorbed.** An executor returns FAILED with
the vendor's own message rather than a success meaning "we asked".

**Credentials absent is not the same as the action failing.** Missing
configuration says so explicitly, because "we could not reach the vendor"
and "the vendor refused" send an operator to different places.

And one that is new here:

**The result carries what the vendor said afterwards.** Every client method
behind these arms performs its write and then re-reads the resource, so
`details.vendor_response.verified` is an observation rather than a
restatement of the request. It is not a `PostActionVerifier` probe — that
registry is keyed by `ActionType` and none of these verbs has one — and each
capability contract says exactly that rather than claiming a probe it does
not have.

What has not been verified
--------------------------
**No call has been made against live AWS, Azure or Google Cloud from this
repository.** There is no funded account for any of the three here. Every
arm is driven end to end against recorded vendor-shaped payloads through
`httpx.MockTransport` in
`services/actions/tests/test_cloud_arms_vendor_smoke.py`, which exercises
the real signing, the real request construction and the real parsing — and
that is a different claim from "it worked against the vendor", which nobody
here can make yet.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import structlog

from app.clients.factories import (
    _aws_ec2_client,
    _aws_iam_client,
    _entra_client,
    _gcp_client,
)
from app.live_actions.capability_contracts import apply_contract
from app.live_actions.executor import LiveActionExecutor
from app.live_actions.models import LiveActionRequest, LiveActionResult, LiveActionStatus

logger = structlog.get_logger(__name__)


def _result(
    executor: LiveActionExecutor,
    request: LiveActionRequest,
    status: LiveActionStatus,
    summary: str,
    *,
    details: dict[str, Any] | None = None,
    error: str | None = None,
) -> LiveActionResult:
    return LiveActionResult(
        request_id=request.request_id,
        status=status,
        capability=executor.capability,
        vendor_id=executor.vendor_id,
        summary=summary,
        details=details or {},
        error=error,
    )


async def _run(
    executor: LiveActionExecutor,
    request: LiveActionRequest,
    vendor: str,
    factory: Callable[[dict[str, Any]], Any],
    call: Callable[[Any, str, dict[str, Any]], Awaitable[dict[str, Any]]],
    summary: str,
) -> LiveActionResult:
    """Shared execute body: dry-run, credentials, call, error handling.

    The dry-run check comes **before** the factory, so a preview cannot
    construct a client and therefore cannot reach the vendor. That ordering
    is the fix for a defect this repository has already shipped twice in
    opposite directions: a strip list that did not match what the factory
    read, so a "dry run" called the customer's Splunk; and a preview that
    stripped credentials into a simulation branch an executor did not have,
    so every dry run reported a message sent that was never sent.
    """
    params: dict[str, Any] = request.params or {}
    target = str(request.target or "")

    if request.dry_run:
        return _result(
            executor,
            request,
            LiveActionStatus.SIMULATED,
            f"would {executor.capability} {target} on {vendor}",
            details={"would_run": executor.capability, "target": target, "vendor": vendor},
        )

    client = factory(params)
    if client is None:
        return _result(
            executor,
            request,
            LiveActionStatus.FAILED,
            f"{vendor} credentials not configured",
            error=(
                f"{vendor} credentials are not configured, so {executor.capability} "
                f"was not attempted. This is not a statement about the target."
            ),
        )

    try:
        response = await call(client, target, params)
    except Exception as exc:  # noqa: BLE001 - a vendor error is FAILED, never silent
        logger.warning(
            "cloud_action.failed",
            vendor=executor.vendor_id,
            capability=executor.capability,
            error=str(exc),
        )
        return _result(
            executor,
            request,
            LiveActionStatus.FAILED,
            f"{vendor} {executor.capability} failed",
            error=f"{vendor} {executor.capability} failed: {exc}",
        )

    # A write the vendor accepted and the read-back contradicts is a failure.
    # Reporting it as a success is the precise shape of "a SOC comes to
    # believe a host is contained when it is not", and the client went to the
    # trouble of re-reading specifically so this branch can exist.
    if isinstance(response, dict) and response.get("verified") is False:
        return _result(
            executor,
            request,
            LiveActionStatus.FAILED,
            f"{vendor} accepted {executor.capability} for {target} and the read-back disagrees",
            details={"target": target, "vendor_response": response},
            error=(
                f"{vendor} accepted the request and a re-read of {target} does not show the "
                f"expected state. The action is reported as failed rather than as a success "
                f"nobody checked."
            ),
        )

    return _result(
        executor,
        request,
        LiveActionStatus.SUCCEEDED,
        summary.format(target=target),
        details={"target": target, "vendor_response": response},
    )


def _str(params: dict[str, Any], *names: str, default: str = "") -> str:
    for name in names:
        value = params.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return default


def _str_list(params: dict[str, Any], *names: str) -> list[str]:
    for name in names:
        value = params.get(name)
        if isinstance(value, list | tuple):
            return [str(item).strip() for item in value if str(item).strip()]
        if isinstance(value, str) and value.strip():
            return [part.strip() for part in value.split(",") if part.strip()]
    return []


# ─── AWS IAM ─────────────────────────────────────────────────────────────────
#
# The target is the access key id or the principal, depending on the verb,
# because that is what an analyst is looking at when they decide.


@apply_contract
class AwsIamDeactivateAccessKey(LiveActionExecutor):
    vendor_id = "aws_iam"
    capability = "deactivate_access_key"
    description = "Set an AWS access key to Inactive, stopping that one credential."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "AWS IAM",
            _aws_iam_client,
            lambda c, t, p: c.set_access_key_status(_str(p, "aws_user_name", "user_name", "user"), t, status="Inactive"),
            "access key {target} deactivated",
        )


@apply_contract
class AwsIamActivateAccessKey(LiveActionExecutor):
    vendor_id = "aws_iam"
    capability = "activate_access_key"
    description = "Set an AWS access key back to Active."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "AWS IAM",
            _aws_iam_client,
            lambda c, t, p: c.set_access_key_status(_str(p, "aws_user_name", "user_name", "user"), t, status="Active"),
            "access key {target} reactivated",
        )


@apply_contract
class AwsIamRevokeRoleSessions(LiveActionExecutor):
    vendor_id = "aws_iam"
    capability = "revoke_role_sessions"
    description = "Deny every STS session for a role issued before now, by inline policy."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "AWS IAM",
            _aws_iam_client,
            lambda c, t, p: c.revoke_role_sessions(t),
            "sessions issued before now revoked for role {target}",
        )


@apply_contract
class AwsIamRestoreRoleSessions(LiveActionExecutor):
    vendor_id = "aws_iam"
    capability = "restore_role_sessions"
    description = "Remove the AWSRevokeOlderSessions policy from a role."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "AWS IAM",
            _aws_iam_client,
            lambda c, t, p: c.restore_role_sessions(t),
            "session revocation lifted on role {target}",
        )


@apply_contract
class AwsIamDisableUser(LiveActionExecutor):
    vendor_id = "aws_iam"
    capability = "disable_user"
    description = "Attach AWSDenyAll to an IAM user. AWS's nearest equivalent to disabling an account."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "AWS IAM", _aws_iam_client, lambda c, t, p: c.deny_user(t), "{target} denied all actions")


@apply_contract
class AwsIamEnableUser(LiveActionExecutor):
    vendor_id = "aws_iam"
    capability = "enable_user"
    description = "Detach AWSDenyAll from an IAM user."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "AWS IAM", _aws_iam_client, lambda c, t, p: c.allow_user(t), "deny policy removed from {target}")


# ─── AWS EC2 ─────────────────────────────────────────────────────────────────


@apply_contract
class AwsEc2QuarantineInstance(LiveActionExecutor):
    vendor_id = "aws_ec2"
    capability = "quarantine_instance"
    description = "Replace an EC2 instance's security groups with a quarantine group."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "AWS EC2",
            _aws_ec2_client,
            lambda c, t, p: c.quarantine_instance(t, _str(p, "quarantine_security_group_id", "quarantine_group_id")),
            "{target} quarantined",
        )


@apply_contract
class AwsEc2ReleaseInstance(LiveActionExecutor):
    vendor_id = "aws_ec2"
    capability = "release_instance"
    description = "Restore an EC2 instance's original security groups."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "AWS EC2",
            _aws_ec2_client,
            lambda c, t, p: c.release_instance(t, _str_list(p, "security_group_ids", "original_security_groups")),
            "{target} released from quarantine",
        )


@apply_contract
class AwsEc2CaptureForensics(LiveActionExecutor):
    vendor_id = "aws_ec2"
    capability = "capture_forensics"
    description = "Snapshot every EBS volume attached to an instance."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "AWS EC2",
            _aws_ec2_client,
            lambda c, t, p: c.snapshot_volumes(t, description=_str(p, "description", "reason")),
            "volumes snapshotted for {target}",
        )


@apply_contract
class AwsEc2GetHost(LiveActionExecutor):
    vendor_id = "aws_ec2"
    capability = "get_host"
    description = "Read an EC2 instance's state, security groups and volumes."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "AWS EC2", _aws_ec2_client, lambda c, t, p: c.describe_instance(t), "instance record for {target}")


# ─── Microsoft Entra workload identities ─────────────────────────────────────


@apply_contract
class EntraDisableServicePrincipal(LiveActionExecutor):
    vendor_id = "azure_entra"
    capability = "disable_service_principal"
    description = "Stop an Entra workload identity authenticating, leaving its registration and audit trail intact."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Entra",
            _entra_client,
            lambda c, t, p: c.set_service_principal_enabled(t, enabled=False),
            "service principal {target} disabled",
        )


@apply_contract
class EntraEnableServicePrincipal(LiveActionExecutor):
    vendor_id = "azure_entra"
    capability = "enable_service_principal"
    description = "Re-enable an Entra workload identity."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Entra",
            _entra_client,
            lambda c, t, p: c.set_service_principal_enabled(t, enabled=True),
            "service principal {target} re-enabled",
        )


@apply_contract
class EntraRevokeOAuthGrant(LiveActionExecutor):
    vendor_id = "azure_entra"
    capability = "revoke_oauth_grant"
    description = "Delete every delegated permission grant an Entra application holds."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Entra",
            _entra_client,
            lambda c, t, p: c.revoke_oauth_grants(service_principal_id=t),
            "delegated grants revoked for {target}",
        )


# ─── Google Cloud ────────────────────────────────────────────────────────────


@apply_contract
class GcpDisableServiceAccount(LiveActionExecutor):
    vendor_id = "gcp"
    capability = "disable_service_account"
    description = "Stop a Google Cloud service account authenticating."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Google Cloud",
            _gcp_client,
            lambda c, t, p: c.set_service_account_disabled(t, disabled=True),
            "service account {target} disabled",
        )


@apply_contract
class GcpEnableServiceAccount(LiveActionExecutor):
    vendor_id = "gcp"
    capability = "enable_service_account"
    description = "Re-enable a Google Cloud service account."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Google Cloud",
            _gcp_client,
            lambda c, t, p: c.set_service_account_disabled(t, disabled=False),
            "service account {target} re-enabled",
        )


@apply_contract
class GcpDisableServiceAccountKey(LiveActionExecutor):
    vendor_id = "gcp"
    capability = "disable_service_account_key"
    description = "Disable one Google Cloud service account key, leaving the identity working."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Google Cloud",
            _gcp_client,
            lambda c, t, p: c.set_service_account_key_disabled(t, _str(p, "key_id", "gcp_key_id"), disabled=True),
            "key disabled on service account {target}",
        )


@apply_contract
class GcpEnableServiceAccountKey(LiveActionExecutor):
    vendor_id = "gcp"
    capability = "enable_service_account_key"
    description = "Re-enable one Google Cloud service account key."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Google Cloud",
            _gcp_client,
            lambda c, t, p: c.set_service_account_key_disabled(t, _str(p, "key_id", "gcp_key_id"), disabled=False),
            "key re-enabled on service account {target}",
        )


@apply_contract
class GcpQuarantineInstance(LiveActionExecutor):
    vendor_id = "gcp"
    capability = "quarantine_instance"
    description = "Replace a Compute Engine instance's network tags with a quarantine tag."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Google Cloud",
            _gcp_client,
            lambda c, t, p: c.quarantine_instance(_str(p, "zone", "gcp_zone"), t, _str(p, "quarantine_tag", "quarantine_network_tag")),
            "{target} quarantined",
        )


@apply_contract
class GcpReleaseInstance(LiveActionExecutor):
    vendor_id = "gcp"
    capability = "release_instance"
    description = "Restore a Compute Engine instance's original network tags."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Google Cloud",
            _gcp_client,
            lambda c, t, p: c.release_instance(_str(p, "zone", "gcp_zone"), t, _str_list(p, "network_tags", "original_tags")),
            "{target} released from quarantine",
        )


@apply_contract
class GcpCaptureForensics(LiveActionExecutor):
    vendor_id = "gcp"
    capability = "capture_forensics"
    description = "Snapshot every persistent disk attached to a Compute Engine instance."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Google Cloud",
            _gcp_client,
            lambda c, t, p: c.snapshot_instance_disks(_str(p, "zone", "gcp_zone"), t, description=_str(p, "description", "reason")),
            "disks snapshotted for {target}",
        )


@apply_contract
class GcpGetHost(LiveActionExecutor):
    vendor_id = "gcp"
    capability = "get_host"
    description = "Read a Compute Engine instance's status, network tags and disks."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Google Cloud",
            _gcp_client,
            lambda c, t, p: c.describe_instance(_str(p, "zone", "gcp_zone"), t),
            "instance record for {target}",
        )


CLOUD_ARM_EXECUTORS: tuple[type[LiveActionExecutor], ...] = (
    AwsIamDeactivateAccessKey,
    AwsIamActivateAccessKey,
    AwsIamRevokeRoleSessions,
    AwsIamRestoreRoleSessions,
    AwsIamDisableUser,
    AwsIamEnableUser,
    AwsEc2QuarantineInstance,
    AwsEc2ReleaseInstance,
    AwsEc2CaptureForensics,
    AwsEc2GetHost,
    EntraDisableServicePrincipal,
    EntraEnableServicePrincipal,
    EntraRevokeOAuthGrant,
    GcpDisableServiceAccount,
    GcpEnableServiceAccount,
    GcpDisableServiceAccountKey,
    GcpEnableServiceAccountKey,
    GcpQuarantineInstance,
    GcpReleaseInstance,
    GcpCaptureForensics,
    GcpGetHost,
)
