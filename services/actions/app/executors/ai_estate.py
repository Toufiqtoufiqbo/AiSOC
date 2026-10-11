"""Containment for the AI estate: provider keys, OAuth grants, gateway keys.

Depth plan 6.6.

Four verbs, and the reason there are four rather than three is the rule this
repository learned the hard way: **a declared reverse that is not in the
vocabulary is worse than none**, because the rollback path believes it has a
route back. `unisolate_host` once resolved to nothing. So
``block_ai_key_at_gateway`` ships with ``unblock_ai_key_at_gateway`` as a
first-class verb with its own executor, contract and probe.

What each one costs, which is what an approver is being asked to accept:

``revoke_provider_key``
    Deletes (OpenAI) or deactivates (Anthropic) the key. There is no
    un-delete and no un-archive that restores the secret. Whatever was using
    it stops, and somebody has to mint and redistribute a replacement.
    IRREVERSIBLE, MANDATORY_HUMAN.

``revoke_oauth_grant``
    Removes an application's standing access. Re-granting is a **user**
    action — they consent again in their own browser — so no API of ours can
    undo it. Workspace revokes per user, so containing an application across
    a domain is a loop over its grantees; Entra's delegated grant is one
    object. IRREVERSIBLE, MANDATORY_HUMAN.

``block_ai_key_at_gateway`` / ``unblock_ai_key_at_gateway``
    Stops every call a virtual key can make, without destroying it. One
    request back. This is the containment to reach for when you are not yet
    certain, and the only one of the three an approver can be told is
    undoable. SEVERE with a platform reverse, ANALYST.

**Off by default.** Every arm here refuses unless
``AISOC_AI_CONTAINMENT_ENABLED`` is set. A new reach-out capability that
ships on is one that can touch a customer's provider account the day they
upgrade, before anyone has decided it should. The refusal is a `FAILED`
result naming the variable, not a silent simulation, because a containment
that reports success while doing nothing is the worst outcome of the three.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

import structlog

from app.clients.ai_estate_client import (
    AIEstateError,
    AIGatewayKeyClient,
    AIOAuthGrantClient,
    AIProviderKeyClient,
)
from app.executors.base import _SIM_FUNNEL_CTA, BaseExecutor
from app.models.action import ActionRequest, ActionResult, ActionStatus, BlastRadius

logger = structlog.get_logger()

#: The flag. Unset means every arm here refuses.
ENABLE_FLAG = "AISOC_AI_CONTAINMENT_ENABLED"

_SIM_NOTE = (
    "Simulation mode — provide the provider or gateway credentials in the "
    "action parameters to enable live execution." + _SIM_FUNNEL_CTA
)


def containment_enabled() -> bool:
    """Whether AI-estate containment may reach a vendor at all.

    Default **off**, read at call time rather than at import so a deployment
    can turn it on without a restart and a test can turn it on for one case.
    """
    return os.getenv(ENABLE_FLAG, "").strip().lower() in ("1", "true", "yes", "on")


def _disabled(request: ActionRequest, blast: BlastRadius) -> ActionResult:
    return ActionResult(
        action_id=request.id,
        status=ActionStatus.FAILED,
        blast_radius=blast,
        error=(
            f"AI-estate containment is disabled. Set {ENABLE_FLAG}=1 to allow it. "
            f"Refused rather than simulated: a containment that reports success "
            f"while touching nothing is worse than one that refuses."
        ),
        completed_at=datetime.utcnow(),
    )


def _simulated(request: ActionRequest, blast: BlastRadius, note: str) -> ActionResult:
    return ActionResult(
        action_id=request.id,
        status=ActionStatus.COMPLETED,
        blast_radius=blast,
        output={"simulated": True, "note": note},
        completed_at=datetime.utcnow(),
    )


def _failed(request: ActionRequest, blast: BlastRadius, error: str) -> ActionResult:
    return ActionResult(
        action_id=request.id,
        status=ActionStatus.FAILED,
        blast_radius=blast,
        error=error,
        completed_at=datetime.utcnow(),
    )


def _provider_key_client(params: dict[str, Any]) -> AIProviderKeyClient | None:
    provider = str(params.get("ai_key_provider") or "").lower()
    admin_key = params.get("ai_provider_admin_key")
    if not (provider and admin_key):
        return None
    try:
        return AIProviderKeyClient(provider, str(admin_key), project_id=str(params.get("ai_provider_project_id") or ""))
    except AIEstateError:
        return None


def _grant_client(params: dict[str, Any]) -> AIOAuthGrantClient | None:
    provider = str(params.get("ai_grant_provider") or "").lower()
    token = params.get("ai_grant_access_token")
    if not (provider and token):
        return None
    try:
        return AIOAuthGrantClient(provider, str(token))
    except AIEstateError:
        return None


def _gateway_client(params: dict[str, Any]) -> AIGatewayKeyClient | None:
    base_url = params.get("ai_gateway_url")
    master_key = params.get("ai_gateway_master_key")
    if not (base_url and master_key):
        return None
    try:
        return AIGatewayKeyClient(str(base_url), str(master_key), verify_tls=bool(params.get("ai_gateway_verify_tls", True)))
    except AIEstateError:
        return None


class RevokeProviderKeyExecutor(BaseExecutor):
    """Revoke a model-provider API key.

    ``target`` is the vendor's key id, not the secret. The secret never
    reaches this service and could not be used to revoke itself anyway.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        blast = BlastRadius.CRITICAL
        if not containment_enabled():
            return _disabled(request, blast)
        client = _provider_key_client(request.parameters)
        if client is None:
            return _simulated(request, blast, _SIM_NOTE)
        try:
            output = await client.revoke_key(request.target)
        except AIEstateError as exc:
            logger.error("revoke_provider_key.failed", key_id=request.target, error=str(exc))
            return _failed(request, blast, str(exc))
        logger.info("revoke_provider_key.completed", provider=client.provider, key_id=request.target)
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=blast,
            output={"provider": client.provider, "key_id": request.target, **output},
            # Deliberately empty. There is no rollback for this verb and
            # populating this would make the rollback service believe there
            # is one.
            rollback_data={},
            completed_at=datetime.utcnow(),
        )


class RevokeOAuthGrantExecutor(BaseExecutor):
    """Revoke an AI application's OAuth grant.

    ``target`` is the application's client id. For Workspace the grantee's
    address must also be supplied, because that vendor revokes per user and
    a domain-wide containment is a loop the caller owns.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        blast = BlastRadius.HIGH
        if not containment_enabled():
            return _disabled(request, blast)
        client = _grant_client(request.parameters)
        if client is None:
            return _simulated(request, blast, _SIM_NOTE)
        user = str(request.parameters.get("ai_grant_user") or "")
        try:
            output = await client.revoke_grant(request.target, user=user)
        except AIEstateError as exc:
            logger.error("revoke_oauth_grant.failed", client_id=request.target, error=str(exc))
            return _failed(request, blast, str(exc))
        logger.info("revoke_oauth_grant.completed", provider=client.provider, client_id=request.target, scope=output.get("scope"))
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=blast,
            output=output,
            rollback_data={},
            completed_at=datetime.utcnow(),
        )


class BlockAIKeyAtGatewayExecutor(BaseExecutor):
    """Block a virtual key at a LiteLLM-compatible gateway.

    ``target`` is the virtual key. The reversible containment: one request
    undoes it, which is what lets the contract declare a platform reverse and
    name a verb that genuinely exists.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        blast = BlastRadius.HIGH
        if not containment_enabled():
            return _disabled(request, blast)
        client = _gateway_client(request.parameters)
        if client is None:
            return _simulated(request, blast, _SIM_NOTE)
        try:
            output = await client.block_key(request.target)
        except AIEstateError as exc:
            logger.error("block_ai_key_at_gateway.failed", error=str(exc))
            return _failed(request, blast, str(exc))
        logger.info("block_ai_key_at_gateway.completed")
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=blast,
            output={"blocked": True, **(output if isinstance(output, dict) else {})},
            # Enough to undo it, and nothing more: the key itself is the
            # target and is not copied into a stored rollback record.
            rollback_data={"reverse_capability": "unblock_ai_key_at_gateway"},
            completed_at=datetime.utcnow(),
        )


class UnblockAIKeyAtGatewayExecutor(BaseExecutor):
    """Unblock a virtual key: the rollback for the arm above.

    A first-class verb rather than a method on the one above, because a
    reverse that is not in the vocabulary cannot be dispatched under
    governance — which is how `unisolate_host`, the rollback for the most
    disruptive action in the product, once resolved to nothing.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        blast = BlastRadius.LOW
        if not containment_enabled():
            return _disabled(request, blast)
        client = _gateway_client(request.parameters)
        if client is None:
            return _simulated(request, blast, _SIM_NOTE)
        try:
            output = await client.unblock_key(request.target)
        except AIEstateError as exc:
            logger.error("unblock_ai_key_at_gateway.failed", error=str(exc))
            return _failed(request, blast, str(exc))
        logger.info("unblock_ai_key_at_gateway.completed")
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=blast,
            output={"blocked": False, **(output if isinstance(output, dict) else {})},
            completed_at=datetime.utcnow(),
        )
