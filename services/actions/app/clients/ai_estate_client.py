"""Containment arms for the AI estate: keys, grants and gateways.

Depth plan 6.6.

Three clients, because the three things an AI containment can reach are
genuinely different and collapsing them would hide what each costs:

* :class:`AIProviderKeyClient` — revoke a model-provider API key. OpenAI
  deletes it; Anthropic sets its status to ``inactive``. **Neither is
  reversible**: there is no un-delete and no un-archive that restores the
  secret, so whoever was using the key needs a new one issued and
  redistributed. That is why the contract for this verb declares
  ``Reversal.NONE`` and ``ActionImpact.IRREVERSIBLE``.
* :class:`AIOAuthGrantClient` — revoke an application's OAuth grant in Google
  Workspace or Microsoft Entra. Also not reversible from this side: a
  delegated grant is re-created by the *user* consenting again, which no API
  of ours can do on their behalf.
* :class:`AIGatewayKeyClient` — block a virtual key at a LiteLLM-compatible
  gateway. This one **is** reversible, by unblocking, which is the whole
  reason it exists beside the other two: it is the containment to reach for
  when you are not yet certain, and the one an approver can be told has a
  route back.

Every endpoint below was read from the provider's current published
reference before it was used:

* ``DELETE /v1/organization/projects/{project}/api_keys/{key}`` and
  ``DELETE /v1/organization/admin_api_keys/{key}`` (OpenAI)
* ``POST /v1/organizations/api_keys/{id}`` with ``{"status": "inactive"}``
  (Anthropic admin API)
* ``DELETE /admin/directory/v1/users/{userKey}/tokens/{clientId}`` and
  ``GET .../tokens`` (Google Workspace Admin SDK Directory)
* ``DELETE /oauth2PermissionGrants/{id}`` → 204, and
  ``GET /oauth2PermissionGrants?$filter=clientId eq '…'`` (Microsoft Graph)
* ``POST /key/block``, ``POST /key/unblock`` → ``{"blocked": …}``, and
  ``GET /key/info?key=…`` (LiteLLM proxy)

Every client exposes a **read-back** alongside its write, because depth 6.6
is bound by "unverifiable means not autonomous": a verb at HIGH or SEVERE
impact needs a probe that confirms the effect rather than inferring it from
the vendor accepting the request. A client with only the write half would
make that probe impossible to write honestly.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_TIMEOUT = 20.0

OPENAI_BASE = "https://api.openai.com/v1"
ANTHROPIC_BASE = "https://api.anthropic.com/v1"
GOOGLE_DIRECTORY_BASE = "https://admin.googleapis.com/admin/directory/v1"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"

#: Providers whose keys this can revoke.
KEY_PROVIDERS: tuple[str, ...] = ("openai", "anthropic")

#: Directories whose OAuth grants this can revoke.
GRANT_PROVIDERS: tuple[str, ...] = ("google_workspace", "entra")


class AIEstateError(RuntimeError):
    """A containment arm could not reach, or was refused by, its vendor."""


class AIProviderKeyClient:
    """Revoke a model-provider API key, and read back whether it is gone."""

    def __init__(self, provider: str, admin_key: str, *, project_id: str = "") -> None:
        provider = (provider or "").lower()
        if provider not in KEY_PROVIDERS:
            raise AIEstateError(f"unknown key provider {provider!r} (need one of {', '.join(KEY_PROVIDERS)})")
        self._provider = provider
        self._admin_key = admin_key
        self._project_id = project_id

    @property
    def provider(self) -> str:
        return self._provider

    def _headers(self) -> dict[str, str]:
        if self._provider == "openai":
            return {"Authorization": f"Bearer {self._admin_key}", "Content-Type": "application/json"}
        return {
            "x-api-key": self._admin_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

    async def revoke_key(self, key_id: str) -> dict[str, Any]:
        """Delete (OpenAI) or deactivate (Anthropic) one key.

        There is no third option. Anthropic has no delete, and OpenAI has no
        deactivate, so this is two genuinely different vendor actions behind
        one verb — which is exactly what a capability contract is for.
        """
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            if self._provider == "openai":
                # A project key and an organization admin key live at
                # different paths, and only one of them is right for a given
                # key. The project is taken from configuration rather than
                # guessed from the key id, because guessing wrong deletes
                # nothing and reports a 404 that reads like the key is
                # already gone.
                if self._project_id:
                    url = f"{OPENAI_BASE}/organization/projects/{self._project_id}/api_keys/{key_id}"
                else:
                    url = f"{OPENAI_BASE}/organization/admin_api_keys/{key_id}"
                response = await client.delete(url, headers=self._headers())
            else:
                response = await client.post(
                    f"{ANTHROPIC_BASE}/organizations/api_keys/{key_id}",
                    headers=self._headers(),
                    json={"status": "inactive"},
                )
        if response.status_code >= 400:
            raise AIEstateError(f"{self._provider}: revoking {key_id} returned HTTP {response.status_code}: {response.text[:200]}")
        return response.json() if response.content else {"id": key_id, "revoked": True}

    async def key_is_revoked(self, key_id: str) -> bool | None:
        """Whether the key is gone or inactive. ``None`` means unknown.

        ``None`` rather than ``False`` on an unreadable vendor: a probe that
        cannot read must report *unverified*, and reporting "still active"
        would tell an operator their containment failed when nobody knows.
        """
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            if self._provider == "openai":
                url = (
                    f"{OPENAI_BASE}/organization/projects/{self._project_id}/api_keys/{key_id}"
                    if self._project_id
                    else f"{OPENAI_BASE}/organization/admin_api_keys/{key_id}"
                )
                response = await client.get(url, headers=self._headers())
                if response.status_code == 404:
                    return True
                if response.status_code >= 400:
                    return None
                return False
            response = await client.get(f"{ANTHROPIC_BASE}/organizations/api_keys/{key_id}", headers=self._headers())
        if response.status_code == 404:
            return True
        if response.status_code >= 400:
            return None
        status = str((response.json() or {}).get("status") or "").lower()
        if not status:
            return None
        return status in ("inactive", "archived", "expired")


class AIOAuthGrantClient:
    """Revoke an AI application's OAuth grant, and read back whether it is gone."""

    def __init__(self, provider: str, access_token: str) -> None:
        provider = (provider or "").lower()
        if provider not in GRANT_PROVIDERS:
            raise AIEstateError(f"unknown grant provider {provider!r} (need one of {', '.join(GRANT_PROVIDERS)})")
        self._provider = provider
        self._token = access_token

    @property
    def provider(self) -> str:
        return self._provider

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    async def revoke_grant(self, client_id: str, *, user: str = "") -> dict[str, Any]:
        """Revoke one application's access.

        Workspace revokes **per user**: the endpoint deletes the tokens one
        user issued to one application, so containing an application across a
        domain is a loop over its grantees and not a single call. Entra's
        delegated grant is a single object and deleting it revokes that grant
        outright. The difference is carried in the result rather than
        flattened, because "we revoked it" means different things.
        """
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            if self._provider == "google_workspace":
                if not user:
                    raise AIEstateError("google_workspace: revoking a grant needs the user whose tokens are being revoked")
                response = await client.delete(
                    f"{GOOGLE_DIRECTORY_BASE}/users/{user}/tokens/{client_id}",
                    headers=self._headers(),
                )
                scope = f"user {user}"
            else:
                grant_id = await self._entra_grant_id(client, client_id)
                if grant_id is None:
                    raise AIEstateError(f"entra: no delegated permission grant found for client {client_id}")
                response = await client.delete(f"{GRAPH_BASE}/oauth2PermissionGrants/{grant_id}", headers=self._headers())
                scope = "tenant"
        if response.status_code >= 400:
            raise AIEstateError(f"{self._provider}: revoking {client_id} returned HTTP {response.status_code}: {response.text[:200]}")
        return {"client_id": client_id, "revoked": True, "scope": scope, "provider": self._provider}

    async def _entra_grant_id(self, client: httpx.AsyncClient, client_id: str) -> str | None:
        response = await client.get(
            f"{GRAPH_BASE}/oauth2PermissionGrants",
            headers=self._headers(),
            params={"$filter": f"clientId eq '{client_id}'"},
        )
        if response.status_code >= 400:
            raise AIEstateError(f"entra: listing grants returned HTTP {response.status_code}: {response.text[:200]}")
        values = (response.json() or {}).get("value") or []
        for item in values:
            if isinstance(item, dict) and item.get("id"):
                return str(item["id"])
        return None

    async def grant_is_revoked(self, client_id: str, *, user: str = "") -> bool | None:
        """Whether the grant is gone. ``None`` means unknown."""
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            if self._provider == "google_workspace":
                if not user:
                    return None
                response = await client.get(f"{GOOGLE_DIRECTORY_BASE}/users/{user}/tokens", headers=self._headers())
                if response.status_code >= 400:
                    return None
                items = (response.json() or {}).get("items") or []
                return not any(str(item.get("clientId")) == client_id for item in items if isinstance(item, dict))
            try:
                return await self._entra_grant_id(client, client_id) is None
            except AIEstateError:
                return None


class AIGatewayKeyClient:
    """Block or unblock a virtual key at a LiteLLM-compatible gateway.

    The reversible containment. Blocking a key stops every call that key can
    make without destroying it, so the route back is one request — which is
    what lets the contract declare ``Reversal.PLATFORM`` and name a reverse
    capability that genuinely exists.
    """

    def __init__(self, base_url: str, master_key: str, *, verify_tls: bool = True) -> None:
        if not base_url:
            raise AIEstateError("gateway containment needs the gateway's base URL")
        self._base = base_url.rstrip("/")
        self._master_key = master_key
        self._verify = verify_tls

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._master_key}", "Content-Type": "application/json"}

    async def _post(self, path: str, key: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=self._verify) as client:
            response = await client.post(f"{self._base}{path}", headers=self._headers(), json={"key": key})
        if response.status_code >= 400:
            raise AIEstateError(f"gateway: {path} returned HTTP {response.status_code}: {response.text[:200]}")
        return response.json() if response.content else {}

    async def block_key(self, key: str) -> dict[str, Any]:
        return await self._post("/key/block", key)

    async def unblock_key(self, key: str) -> dict[str, Any]:
        return await self._post("/key/unblock", key)

    async def key_is_blocked(self, key: str) -> bool | None:
        """Whether the gateway currently refuses this key. ``None`` is unknown."""
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=self._verify) as client:
            response = await client.get(f"{self._base}/key/info", headers=self._headers(), params={"key": key})
        if response.status_code >= 400:
            return None
        body = response.json() or {}
        info = body.get("info") if isinstance(body.get("info"), dict) else body
        blocked = info.get("blocked")
        # The gateway omits `blocked` entirely for a key that has never been
        # blocked. Absent means not blocked; it does not mean unknown, and
        # conflating the two would make every first containment unverifiable.
        if blocked is None:
            return False if info else None
        return bool(blocked)
