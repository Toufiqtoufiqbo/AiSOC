"""AI-estate containment: the four verbs, their refusals and their probes.

Depth plan 6.6.

Every vendor payload below is the documented response shape, read from the
provider's current reference before it was used:

* OpenAI ``{"object": "organization.project.api_key.deleted", "deleted": true}``
* Anthropic ``{"id": …, "status": "inactive"}``
* Google ``DELETE /users/{user}/tokens/{clientId}`` and ``GET …/tokens``
* Graph ``DELETE /oauth2PermissionGrants/{id}`` → 204
* LiteLLM ``POST /key/block`` → ``{"blocked": true}``

Three properties get the most attention here, because each is a place this
repository has shipped the wrong answer before:

1. **Disabled means refused, not simulated.** `NotifySlackExecutor` reported
   `message_sent: true` on a send that never happened. A containment that
   reports success while touching nothing is worse than one that refuses.
2. **The probe reads the vendor back.** A 200 on a revoke is the vendor
   accepting the instruction, which is a different claim from the key having
   stopped working.
3. **Unreadable is `None`, never `False`.** Reporting "still active" when
   nobody knows sends an operator to repeat an irreversible containment.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
import respx
from app.clients.ai_estate_client import AIEstateError, AIGatewayKeyClient, AIOAuthGrantClient, AIProviderKeyClient
from app.executors.ai_estate import (
    ENABLE_FLAG,
    BlockAIKeyAtGatewayExecutor,
    RevokeOAuthGrantExecutor,
    RevokeProviderKeyExecutor,
    UnblockAIKeyAtGatewayExecutor,
)
from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
from app.live_actions.contract import ActionImpact, ApprovalRequirement, Reversal
from app.models.action import ActionRequest, ActionStatus, ActionType

AI_VERBS = (
    "revoke_provider_key",
    "revoke_oauth_grant",
    "block_ai_key_at_gateway",
    "unblock_ai_key_at_gateway",
)

GATEWAY_PARAMS = {"ai_gateway_url": "https://gw.example.com", "ai_gateway_master_key": "sk-master"}
PROVIDER_PARAMS = {"ai_key_provider": "openai", "ai_provider_admin_key": "sk-admin", "ai_provider_project_id": "proj_abc"}
GRANT_PARAMS = {"ai_grant_provider": "entra", "ai_grant_access_token": "ms-token"}


def request(target: str, params: dict[str, Any], action_type: ActionType) -> ActionRequest:
    return ActionRequest(
        id=uuid.uuid4(),
        incident_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        action_type=action_type,
        target=target,
        parameters=params,
        requested_by="analyst@example.com",
    )


@pytest.fixture
def armed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(ENABLE_FLAG, "1")
    return True


# ---------------------------------------------------------------------------
# Off by default
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("executor", "action_type", "params"),
    [
        (RevokeProviderKeyExecutor(), ActionType.REVOKE_PROVIDER_KEY, PROVIDER_PARAMS),
        (RevokeOAuthGrantExecutor(), ActionType.REVOKE_OAUTH_GRANT, GRANT_PARAMS),
        (BlockAIKeyAtGatewayExecutor(), ActionType.BLOCK_AI_KEY_AT_GATEWAY, GATEWAY_PARAMS),
        (UnblockAIKeyAtGatewayExecutor(), ActionType.UNBLOCK_AI_KEY_AT_GATEWAY, GATEWAY_PARAMS),
    ],
)
async def test_every_arm_refuses_when_the_flag_is_unset(
    monkeypatch: pytest.MonkeyPatch, executor: Any, action_type: ActionType, params: dict[str, Any]
):
    """Refused, and named — not simulated.

    The refusal is a FAILED result carrying the variable to set. A simulated
    success here is the `NotifySlackExecutor` failure with an irreversible
    verb behind it: the operator reads "contained" and stops looking.
    """
    monkeypatch.delenv(ENABLE_FLAG, raising=False)
    result = await executor.execute(request("x", params, action_type))
    assert result.status == ActionStatus.FAILED
    assert ENABLE_FLAG in (result.error or "")
    assert not result.output.get("simulated"), "a disabled containment reported a simulated success"


@pytest.mark.asyncio
async def test_an_armed_arm_with_no_credentials_simulates_rather_than_reaching_out(monkeypatch: pytest.MonkeyPatch):
    """The other direction. No credentials is the ordinary unconfigured state.

    Distinct from disabled, and the two must not collapse: one is "nobody has
    turned this on", the other is "it is on and not wired up".
    """
    monkeypatch.setenv(ENABLE_FLAG, "1")
    result = await BlockAIKeyAtGatewayExecutor().execute(request("sk-virtual", {}, ActionType.BLOCK_AI_KEY_AT_GATEWAY))
    assert result.status == ActionStatus.COMPLETED
    assert result.output["simulated"] is True


# ---------------------------------------------------------------------------
# The vendor paths
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_openai_project_key_is_deleted_at_the_documented_path(armed):
    route = respx.delete("https://api.openai.com/v1/organization/projects/proj_abc/api_keys/key_abc").respond(
        200, json={"object": "organization.project.api_key.deleted", "id": "key_abc", "deleted": True}
    )
    result = await RevokeProviderKeyExecutor().execute(request("key_abc", PROVIDER_PARAMS, ActionType.REVOKE_PROVIDER_KEY))
    assert result.status == ActionStatus.COMPLETED
    assert result.output["deleted"] is True
    assert route.called
    # Nothing to roll back, and the record must not imply there is: the
    # rollback service reads this, and a populated record would make it
    # believe a route home exists.
    assert result.rollback_data == {}


@respx.mock
@pytest.mark.asyncio
async def test_anthropic_key_is_deactivated_rather_than_deleted(armed):
    route = respx.post("https://api.anthropic.com/v1/organizations/api_keys/apikey_01").respond(
        200, json={"id": "apikey_01", "status": "inactive", "type": "api_key"}
    )
    params = {"ai_key_provider": "anthropic", "ai_provider_admin_key": "sk-ant-admin"}
    result = await RevokeProviderKeyExecutor().execute(request("apikey_01", params, ActionType.REVOKE_PROVIDER_KEY))
    assert result.status == ActionStatus.COMPLETED
    assert result.output["status"] == "inactive"
    # Two genuinely different vendor actions behind one verb, which is what a
    # capability contract is for.
    assert route.calls.last.request.method == "POST"


@respx.mock
@pytest.mark.asyncio
async def test_a_vendor_refusal_is_a_failure_rather_than_a_silent_success(armed):
    respx.delete(url__regex=r"https://api\.openai\.com/.*").respond(403, json={"error": "insufficient permissions"})
    result = await RevokeProviderKeyExecutor().execute(request("key_abc", PROVIDER_PARAMS, ActionType.REVOKE_PROVIDER_KEY))
    assert result.status == ActionStatus.FAILED
    assert "403" in (result.error or "")


@respx.mock
@pytest.mark.asyncio
async def test_entra_grant_is_looked_up_then_deleted(armed):
    lookup = respx.get(url__regex=r"https://graph\.microsoft\.com/v1\.0/oauth2PermissionGrants\?.*").respond(
        200, json={"value": [{"id": "grant-1", "clientId": "app-1", "consentType": "AllPrincipals"}]}
    )
    delete = respx.delete("https://graph.microsoft.com/v1.0/oauth2PermissionGrants/grant-1").respond(204)
    result = await RevokeOAuthGrantExecutor().execute(request("app-1", GRANT_PARAMS, ActionType.REVOKE_OAUTH_GRANT))
    assert result.status == ActionStatus.COMPLETED
    assert result.output["scope"] == "tenant"
    assert lookup.called and delete.called


@respx.mock
@pytest.mark.asyncio
async def test_workspace_revocation_is_per_user_and_says_so(armed):
    """Google revokes the tokens one user issued to one application.

    Containing an application across a domain is a loop over its grantees,
    and the result says which scope was achieved rather than implying the
    whole tenant was covered.
    """
    respx.delete("https://admin.googleapis.com/admin/directory/v1/users/ada@example.com/tokens/client-9").respond(204)
    params = {"ai_grant_provider": "google_workspace", "ai_grant_access_token": "g-token", "ai_grant_user": "ada@example.com"}
    result = await RevokeOAuthGrantExecutor().execute(request("client-9", params, ActionType.REVOKE_OAUTH_GRANT))
    assert result.status == ActionStatus.COMPLETED
    assert result.output["scope"] == "user ada@example.com"


@respx.mock
@pytest.mark.asyncio
async def test_workspace_revocation_without_a_user_fails_rather_than_guessing(armed):
    params = {"ai_grant_provider": "google_workspace", "ai_grant_access_token": "g-token"}
    result = await RevokeOAuthGrantExecutor().execute(request("client-9", params, ActionType.REVOKE_OAUTH_GRANT))
    assert result.status == ActionStatus.FAILED
    assert "user" in (result.error or "").lower()


@respx.mock
@pytest.mark.asyncio
async def test_gateway_block_and_unblock_round_trip(armed):
    block = respx.post("https://gw.example.com/key/block").respond(200, json={"key": "sk-virtual", "blocked": True})
    unblock = respx.post("https://gw.example.com/key/unblock").respond(200, json={"key": "sk-virtual", "blocked": False})

    blocked = await BlockAIKeyAtGatewayExecutor().execute(request("sk-virtual", GATEWAY_PARAMS, ActionType.BLOCK_AI_KEY_AT_GATEWAY))
    assert blocked.status == ActionStatus.COMPLETED
    assert blocked.output["blocked"] is True
    # The rollback record names the verb that undoes it, and that verb has an
    # executor. `unisolate_host` declared one and resolved to nothing.
    assert blocked.rollback_data["reverse_capability"] == "unblock_ai_key_at_gateway"

    lifted = await UnblockAIKeyAtGatewayExecutor().execute(request("sk-virtual", GATEWAY_PARAMS, ActionType.UNBLOCK_AI_KEY_AT_GATEWAY))
    assert lifted.status == ActionStatus.COMPLETED
    assert lifted.output["blocked"] is False
    assert block.called and unblock.called


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_the_key_probe_reads_the_vendor_rather_than_the_response():
    """Gone is 404; present is still active; unreadable is `None`."""
    client = AIProviderKeyClient("openai", "sk-admin", project_id="proj_abc")
    url = "https://api.openai.com/v1/organization/projects/proj_abc/api_keys/key_abc"

    respx.get(url).respond(404, json={"error": "not found"})
    assert await client.key_is_revoked("key_abc") is True

    respx.get(url).respond(200, json={"id": "key_abc", "object": "organization.project.api_key"})
    assert await client.key_is_revoked("key_abc") is False

    respx.get(url).respond(500, json={"error": "upstream"})
    # Not False. "Still active" when nobody knows sends an operator to repeat
    # an irreversible containment during an incident.
    assert await client.key_is_revoked("key_abc") is None


@respx.mock
@pytest.mark.asyncio
async def test_the_gateway_probe_treats_a_never_blocked_key_as_not_blocked():
    """Absent `blocked` means not blocked; an empty body means unknown.

    Conflating the two would make every first containment unverifiable,
    because a key that has never been blocked carries no flag at all.
    """
    client = AIGatewayKeyClient("https://gw.example.com", "sk-master")

    respx.get(url__regex=r"https://gw\.example\.com/key/info.*").respond(200, json={"info": {"key_name": "sk-v", "spend": 0.0}})
    assert await client.key_is_blocked("sk-v") is False

    respx.get(url__regex=r"https://gw\.example\.com/key/info.*").respond(200, json={"info": {"blocked": True}})
    assert await client.key_is_blocked("sk-v") is True

    respx.get(url__regex=r"https://gw\.example\.com/key/info.*").respond(503, text="down")
    assert await client.key_is_blocked("sk-v") is None


@respx.mock
@pytest.mark.asyncio
async def test_the_grant_probe_reports_unknown_when_the_directory_cannot_be_read():
    respx.get(url__regex=r"https://graph\.microsoft\.com/.*").respond(500, json={"error": "boom"})
    client = AIOAuthGrantClient("entra", "ms-token")
    assert await client.grant_is_revoked("app-1") is None


@pytest.mark.asyncio
async def test_an_unknown_provider_is_refused_at_construction():
    with pytest.raises(AIEstateError):
        AIProviderKeyClient("gemini", "k")
    with pytest.raises(AIEstateError):
        AIOAuthGrantClient("okta", "t")


# ---------------------------------------------------------------------------
# The contracts
# ---------------------------------------------------------------------------


def test_the_irreversible_pair_cannot_be_lifted_by_any_tier():
    """`MANDATORY_HUMAN` is a floor, not a high bar.

    Both verbs are irreversible by the **vendor's** design: neither returns
    the secret, and a re-granted OAuth consent is the user acting in their own
    browser.
    """
    for verb in ("revoke_provider_key", "revoke_oauth_grant"):
        contract = CAPABILITY_CONTRACTS[verb]
        assert contract.impact is ActionImpact.IRREVERSIBLE, verb
        assert contract.approval is ApprovalRequirement.MANDATORY_HUMAN, verb
        assert contract.reversal is Reversal.NONE, verb
        assert not contract.reverse_capability, f"{verb} names a reverse it does not have"


def test_the_reversible_verb_names_a_reverse_that_exists_and_points_back():
    """Both directions, and both must be dispatchable.

    A declared reverse that is not in the vocabulary is worse than none,
    because the rollback path believes it has a route — which is what
    `unisolate_host` was for a release.
    """
    block = CAPABILITY_CONTRACTS["block_ai_key_at_gateway"]
    unblock = CAPABILITY_CONTRACTS["unblock_ai_key_at_gateway"]

    assert block.reversal is Reversal.PLATFORM
    assert block.reverse_capability == "unblock_ai_key_at_gateway"
    assert unblock.reverse_capability == "block_ai_key_at_gateway"
    assert {"unblock_ai_key_at_gateway", "block_ai_key_at_gateway"} <= set(CAPABILITY_CONTRACTS)
    assert ActionType("unblock_ai_key_at_gateway")


def test_every_ai_verb_declares_a_verification_probe_and_has_one():
    """Unverifiable means not autonomous, and these are the tiers that bind.

    Checked against the registered probe table rather than the declaration
    alone: the contract once marked nine capabilities verified while three
    probes existed.
    """
    from app.services.verification import _DEFAULT_PROBES

    registered = {a.value for a in _DEFAULT_PROBES}
    for verb in AI_VERBS:
        assert CAPABILITY_CONTRACTS[verb].has_verification_probe is True, verb
        assert verb in registered, f"{verb} declares a probe that is not registered"


def test_revoking_a_provider_key_is_the_widest_blast_radius_of_the_four():
    """It is not one person's access; it is every process holding that key."""
    from app.models.action import ACTION_BLAST_RADIUS, BlastRadius

    assert ACTION_BLAST_RADIUS[ActionType.REVOKE_PROVIDER_KEY] is BlastRadius.CRITICAL
    assert ACTION_BLAST_RADIUS[ActionType.UNBLOCK_AI_KEY_AT_GATEWAY] is BlastRadius.LOW


def test_the_connectors_vocabulary_mirrors_these_verbs():
    """Two independently deployable services, one meaning.

    A verb present on one side only resolves to `executor_not_found` at
    dispatch, which reads as a missing integration rather than a missing enum
    member.
    """
    from pathlib import Path

    base = Path(__file__).resolve().parents[3] / "services/connectors/app/connectors/base.py"
    source = base.read_text(encoding="utf-8")
    for verb in AI_VERBS:
        assert f'= "{verb}"' in source, f"{verb} is missing from the connectors Capability enum"
