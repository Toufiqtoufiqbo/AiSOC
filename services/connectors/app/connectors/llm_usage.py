"""AI control-plane audit across seven providers.

This is the **governance** surface for AI adoption: who minted an API key, who
was made an owner, who consented to an AI application reading a mailbox, and
which humans are using which assistant. It pairs with the `llm-*` and `ai-*`
detection rules, which fire on the emitted dotted `event_type`, and it feeds
the AI-estate inventory (depth plan 6.1), which turns those events into
`provider_key` and `oauth_grant` assets.

It is deliberately not the *runtime* surface. What an agent did once running —
which tools it called, against which resources — arrives through `ai_gateway`
and the `aisoc-ai-sdk`.

Seven providers, and why each endpoint is the one it is
------------------------------------------------------
Every endpoint below was read from the provider's current published reference
before it was used here, not recalled. Fetching them found one thing worth
carrying: the Gemini stream did not exist before 2025-06-20 and keeps a
rolling 180 days, so a tenant asking "what did we use last year" has no
answer from this source and the connector should not imply otherwise.

* **openai** — `GET /v1/organization/audit_logs`. Admin key, `effective_at`
  window.
* **anthropic** — `GET /v1/organizations/audit_logs`. Admin key.
* **google_workspace_gemini** — Admin SDK Reports,
  `applications/gemini_in_workspace_apps`. Who used Gemini in which Workspace
  app, through which feature. This is a *usage* stream, not a control-plane
  one, and it is the closest thing to "which humans are using an assistant"
  that any provider publishes.
* **google_workspace_oauth** — Admin SDK Reports, `applications/token`. The
  OAuth grant stream: `authorize`, `revoke`, `request`, `deny` and per-call
  `activity`, each carrying `client_id`, `app_name` and `scope`. This is
  where a third-party AI application acquiring mailbox or drive access
  appears.
* **m365_copilot** — Office 365 Management Activity API,
  `/subscriptions/content?contentType=Audit.General`. Copilot and AI
  application interactions arrive as `Operation: CopilotInteraction`,
  `ConnectedAIAppInteraction` or `AIAppInteraction`, with `AppIdentity`
  naming the specific assistant. The three record types are a real
  distinction and are preserved: the first is a Microsoft-developed Copilot,
  the second a custom or third-party app registered in the organisation, and
  the third a third-party AI app that is **not** deployed there — which is
  shadow AI by Microsoft's own definition.
* **entra_consent** — Graph `auditLogs/directoryAudits`. Consent grants and
  application-permission additions, which is where an AI application acquires
  standing access to a Microsoft estate.
* **github_copilot** — `GET /orgs/{org}/audit-log` filtered to Copilot
  actions, plus `GET /orgs/{org}/copilot/billing/seats` so a seat assigned
  and never used is still inventoried.

What this connector does not claim
----------------------------------
**No provider here has ever been exercised against a funded account from this
repository.** Every endpoint is verified against the vendor's published
reference and every fixture is built from the documented response shape; none
is a recording from a live tenant. `docs/connectors/llm_usage.md` states that
per provider rather than in a footnote, and the row in the claim matrix says
so too. "Not measured" is the honest value, and it is not the same as zero.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()

_LIMIT = 100

_OPENAI_BASE = "https://api.openai.com/v1/organization/audit_logs"
_ANTHROPIC_BASE = "https://api.anthropic.com/v1/organizations/audit_logs"
_GOOGLE_REPORTS_BASE = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications"
_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
_M365_ACTIVITY_BASE = "https://manage.office.com/api/v1.0"
_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_MS_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_GITHUB_BASE = "https://api.github.com"

#: Providers this connector can pull, in the order the console offers them.
PROVIDERS: tuple[str, ...] = (
    "openai",
    "anthropic",
    "google_workspace_gemini",
    "google_workspace_oauth",
    "m365_copilot",
    "entra_consent",
    "github_copilot",
)

#: Which credential shape each provider needs. Declared rather than inferred
#: so the connector can refuse a half-configured instance with a sentence an
#: operator can act on, instead of a 401 from a vendor that reads as "your
#: credentials are wrong".
PROVIDER_AUTH: dict[str, str] = {
    "openai": "api_key",
    "anthropic": "api_key",
    "google_workspace_gemini": "google_service_account",
    "google_workspace_oauth": "google_service_account",
    "m365_copilot": "microsoft_client_credentials",
    "entra_consent": "microsoft_client_credentials",
    "github_copilot": "github_token",
}

#: What each provider's stream is, in one word. Carried onto every event
#: because a *usage* record and a *control-plane* record mean different things
#: to a detection: one says a human used an assistant, the other says somebody
#: changed what an assistant may do.
PROVIDER_STREAM: dict[str, str] = {
    "openai": "control_plane",
    "anthropic": "control_plane",
    "google_workspace_gemini": "usage",
    "google_workspace_oauth": "oauth_grant",
    "m365_copilot": "usage",
    "entra_consent": "oauth_grant",
    "github_copilot": "control_plane",
}

# event_type fragment -> severity floor. Lowercase, matched as a substring on
# the dotted event type.
_HIGH = (
    "api_key.created",
    "member.added",
    "invite",
    "service_account.created",
    "copilot.seat",
    # `google_workspace_oauth.authorize`, matched as a substring. Written
    # this way rather than as "token.authorize" because the dotted event type
    # carries the provider name, not the Workspace application name.
    "oauth.authorize",
    "consent to application",
)
_CRITICAL = (
    "logging",
    "mfa",
    # An application permission is admin consent to act without a user. It is
    # the shape every malicious-OAuth campaign ends with, so it is the one
    # directory event that outranks a key being minted.
    "add app role assignment",
    "add delegated permission grant",
)

#: Microsoft record types that carry an AI interaction. The third is the one
#: that matters most and is easiest to miss: by Microsoft's own definition it
#: is a third-party AI app that is **not** deployed in the organisation.
_M365_AI_RECORD_TYPES = frozenset({"CopilotInteraction", "ConnectedAIAppInteraction", "AIAppInteraction", "TeamCopilotInteraction"})

#: Entra activities that grant an application standing access.
_ENTRA_CONSENT_ACTIVITIES = (
    "consent to application",
    "add app role assignment",
    "add delegated permission grant",
    "add owner to application",
    "add service principal",
)


class LlmUsageConnector(BaseConnector):
    """AI control-plane and assistant-usage audit, across seven providers."""

    connector_id = "llm_usage"
    connector_name = "AI / LLM Usage Audit"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Pull AI control-plane and assistant-usage audit from OpenAI, "
                "Anthropic, Gemini in Google Workspace, Microsoft 365 Copilot, "
                "Microsoft Entra consent events, Google Workspace OAuth grants "
                "and GitHub Copilot. Feeds the llm-* and ai-* detection rules "
                "and the AI estate inventory."
            ),
            docs_url="/docs/connectors/llm_usage",
            fields=[
                Field(
                    "provider",
                    "select",
                    "Provider",
                    options=[
                        {"value": "openai", "label": "OpenAI (organization audit log)"},
                        {"value": "anthropic", "label": "Anthropic (admin audit log)"},
                        {"value": "google_workspace_gemini", "label": "Gemini in Google Workspace (usage)"},
                        {"value": "google_workspace_oauth", "label": "Google Workspace OAuth grants"},
                        {"value": "m365_copilot", "label": "Microsoft 365 Copilot (interactions)"},
                        {"value": "entra_consent", "label": "Microsoft Entra (application consent)"},
                        {"value": "github_copilot", "label": "GitHub Copilot (audit + seats)"},
                    ],
                    help_text=(
                        "Each provider needs a different credential — see the fields below. "
                        "An instance configured for the wrong one is refused at save rather "
                        "than failing later as a vendor 401."
                    ),
                ),
                Field(
                    "api_key",
                    "secret",
                    "Admin / audit API key",
                    required=False,
                    help_text="OpenAI and Anthropic only.",
                ),
                Field(
                    "service_account_json",
                    "secret",
                    "Google service account JSON key",
                    required=False,
                    help_text=(
                        "Both Google providers. Needs domain-wide delegation with the "
                        "admin.reports.audit.readonly scope, and a super-admin to impersonate."
                    ),
                ),
                Field(
                    "admin_email",
                    "string",
                    "Google super-admin email",
                    required=False,
                    placeholder="audit-bot@example.com",
                    help_text="Both Google providers: the admin the service account impersonates.",
                ),
                Field(
                    "tenant_id",
                    "string",
                    "Microsoft tenant ID",
                    required=False,
                    placeholder="00000000-0000-0000-0000-000000000000",
                ),
                Field("client_id", "string", "Microsoft application (client) ID", required=False),
                Field("client_secret", "secret", "Microsoft client secret", required=False),
                Field("github_org", "string", "GitHub organisation", required=False),
                Field(
                    "github_token",
                    "secret",
                    "GitHub token",
                    required=False,
                    help_text="Needs read:audit_log and manage_billing:copilot (or read:org for seats).",
                ),
            ],
            oauth=OAuthHints(
                supported_in_hosted=False,
                authorize_url=None,
                token_url=_MS_TOKEN_URL.format(tenant_id="{tenant_id}"),
                scopes=["https://graph.microsoft.com/.default", "admin.reports.audit.readonly"],
            ),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_AUDIT, Capability.READ_AUDIT_TRAIL)

    def __init__(
        self,
        provider: str,
        api_key: str = "",
        service_account_json: str = "",
        admin_email: str = "",
        tenant_id: str = "",
        client_id: str = "",
        client_secret: str = "",
        github_org: str = "",
        github_token: str = "",
        **_: Any,
    ) -> None:
        provider = (provider or "").lower()
        if provider not in PROVIDERS:
            raise ValueError(f"llm_usage: unknown provider '{provider}' (need one of {', '.join(PROVIDERS)})")
        self._provider = provider
        self._api_key = api_key
        self._service_account_json = service_account_json
        self._admin_email = admin_email
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._github_org = github_org
        self._github_token = github_token
        self._access_token: str | None = None
        self._token_expiry = 0.0

        missing = self._missing_credentials()
        if missing:
            # Refused here rather than at the first poll. A half-configured
            # instance that saves cleanly and then answers 401 reads to an
            # operator as "my vendor credentials are wrong", which sends them
            # to the wrong place entirely.
            raise ValueError(f"llm_usage: provider '{provider}' needs {', '.join(missing)}")

    def _missing_credentials(self) -> list[str]:
        shape = PROVIDER_AUTH[self._provider]
        if shape == "api_key":
            return [] if self._api_key else ["api_key"]
        if shape == "google_service_account":
            return [
                name
                for name, value in (("service_account_json", self._service_account_json), ("admin_email", self._admin_email))
                if not value
            ]
        if shape == "microsoft_client_credentials":
            return [
                name
                for name, value in (
                    ("tenant_id", self._tenant_id),
                    ("client_id", self._client_id),
                    ("client_secret", self._client_secret),
                )
                if not value
            ]
        return [name for name, value in (("github_org", self._github_org), ("github_token", self._github_token)) if not value]

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    async def _google_token(self) -> str:
        """Service-account JWT bearer, the same flow `google_workspace` uses."""
        if self._access_token and time.time() < self._token_expiry - 60:
            return self._access_token
        from app.connectors.google_workspace import GoogleWorkspaceConnector  # noqa: PLC0415 — see below

        # Imported inside the method, deliberately: `google_workspace` pulls in
        # `cryptography` for the RS256 assertion, and a module-scope import
        # would make every deployment that never configures a Google provider
        # carry that dependency at import time.
        helper = GoogleWorkspaceConnector(
            admin_email=self._admin_email,
            service_account_json=self._service_account_json,
        )
        token = await helper._authenticate()  # noqa: SLF001 — one signing implementation, not two
        self._access_token = token
        self._token_expiry = time.time() + 3000
        return token

    async def _microsoft_token(self, scope: str) -> str:
        if self._access_token and time.time() < self._token_expiry - 60:
            return self._access_token
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                _MS_TOKEN_URL.format(tenant_id=self._tenant_id),
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "scope": scope,
                    "grant_type": "client_credentials",
                },
            )
            resp.raise_for_status()
            payload = resp.json()
        self._access_token = payload["access_token"]
        self._token_expiry = time.time() + int(payload.get("expires_in", 3600))
        return self._access_token

    async def _headers(self) -> dict[str, str]:
        if self._provider == "openai":
            return {"Authorization": f"Bearer {self._api_key}", "Accept": "application/json"}
        if self._provider == "anthropic":
            return {"x-api-key": self._api_key, "anthropic-version": "2023-06-01", "Accept": "application/json"}
        if self._provider.startswith("google_workspace"):
            return {"Authorization": f"Bearer {await self._google_token()}", "Accept": "application/json"}
        if self._provider == "m365_copilot":
            token = await self._microsoft_token("https://manage.office.com/.default")
            return {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        if self._provider == "entra_consent":
            token = await self._microsoft_token("https://graph.microsoft.com/.default")
            return {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        return {
            "Authorization": f"Bearer {self._github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    # ------------------------------------------------------------------
    # Requests
    # ------------------------------------------------------------------

    def _endpoint(self) -> str:
        if self._provider == "openai":
            return _OPENAI_BASE
        if self._provider == "anthropic":
            return _ANTHROPIC_BASE
        if self._provider == "google_workspace_gemini":
            return f"{_GOOGLE_REPORTS_BASE}/gemini_in_workspace_apps"
        if self._provider == "google_workspace_oauth":
            return f"{_GOOGLE_REPORTS_BASE}/token"
        if self._provider == "m365_copilot":
            return f"{_M365_ACTIVITY_BASE}/{self._tenant_id}/activity/feed/subscriptions/content"
        if self._provider == "entra_consent":
            return f"{_GRAPH_BASE}/auditLogs/directoryAudits"
        return f"{_GITHUB_BASE}/orgs/{self._github_org}/audit-log"

    def _params(self, since_seconds: int) -> dict[str, Any]:
        now = time.time()
        since = now - since_seconds
        if self._provider == "openai":
            return {"limit": _LIMIT, "effective_at[gte]": int(since)}
        if self._provider == "anthropic":
            return {"limit": _LIMIT}
        if self._provider.startswith("google_workspace"):
            params: dict[str, Any] = {"maxResults": _LIMIT, "startTime": _rfc3339(since)}
            if self._provider == "google_workspace_gemini":
                params["eventName"] = "feature_utilization"
            return params
        if self._provider == "m365_copilot":
            # The API caps a window at 24 hours and refuses a start more than
            # 7 days back; both are clamped rather than passed through, so a
            # long `since_seconds` degrades to the largest window the vendor
            # will serve instead of a 400 nobody reads.
            start = max(since, now - 7 * 86400)
            end = min(now, start + 86400)
            return {
                "contentType": "Audit.General",
                "startTime": _rfc3339(start),
                "endTime": _rfc3339(end),
            }
        if self._provider == "entra_consent":
            return {
                "$filter": f"activityDateTime ge {_rfc3339(since)}",
                "$top": _LIMIT,
                "$orderby": "activityDateTime desc",
            }
        return {"phrase": f"created:>={_rfc3339(since)} action:copilot", "per_page": _LIMIT}

    @staticmethod
    def _items(provider: str, body: Any) -> list[dict[str, Any]]:
        """Pull the records out of each vendor's own envelope.

        Four different shapes, which is why this is a table and not a
        `body["data"]`: Google wraps in `items`, Graph in `value`, GitHub
        returns a bare array, and the Microsoft activity feed returns a list
        of *blob references* rather than records — that last one is handled by
        the caller, because it needs a second request.
        """
        if isinstance(body, list):
            return [item for item in body if isinstance(item, dict)]
        if not isinstance(body, dict):
            return []
        for key in ("data", "items", "value", "audit_logs"):
            found = body.get(key)
            if isinstance(found, list):
                return [item for item in found if isinstance(item, dict)]
        return []

    async def test_connection(self) -> dict[str, Any]:
        try:
            headers = await self._headers()
            params = self._params(3600)
            if self._provider not in ("m365_copilot",):
                params = {**params, **({"limit": 1} if self._provider in ("openai", "anthropic") else {})}
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(self._endpoint(), headers=headers, params=params)
            if resp.status_code == 200:
                return {
                    "success": True,
                    "connector": self.connector_id,
                    "provider": self._provider,
                    "stream": PROVIDER_STREAM[self._provider],
                }
            return {
                "success": False,
                "connector": self.connector_id,
                "provider": self._provider,
                "error": f"HTTP {resp.status_code}: {resp.text[:200]}",
            }
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "connector": self.connector_id, "provider": self._provider, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            headers = await self._headers()
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(self._endpoint(), headers=headers, params=self._params(since_seconds))
                if resp.status_code != 200:
                    logger.warning("llm_usage.fetch_failed", provider=self._provider, status=resp.status_code)
                    return out
                records = self._items(self._provider, resp.json())

                if self._provider == "m365_copilot":
                    # The content endpoint returns blob references, not
                    # records. Each must be fetched; skipping this step is how
                    # a connector ends up reporting "no Copilot activity" on a
                    # tenant that has plenty.
                    records = await self._fetch_m365_blobs(client, headers, records)

                for record in records:
                    if self._include(record):
                        out.append(self.normalize(record))

                if self._provider == "github_copilot":
                    out.extend(await self._fetch_copilot_seats(client, headers))
        except Exception as exc:  # noqa: BLE001
            logger.warning("llm_usage.fetch_error", provider=self._provider, error=str(exc))
        return out

    async def _fetch_m365_blobs(
        self, client: httpx.AsyncClient, headers: dict[str, str], references: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for reference in references[:_LIMIT]:
            uri = reference.get("contentUri")
            if not isinstance(uri, str) or not uri:
                continue
            blob = await client.get(uri, headers=headers)
            if blob.status_code != 200:
                logger.warning("llm_usage.m365_blob_failed", status=blob.status_code)
                continue
            payload = blob.json()
            if isinstance(payload, list):
                records.extend(item for item in payload if isinstance(item, dict))
        return records

    async def _fetch_copilot_seats(self, client: httpx.AsyncClient, headers: dict[str, str]) -> list[dict[str, Any]]:
        """Seats, so an assigned-and-never-used licence is still inventoried.

        A seat is the AI estate's equivalent of a dormant account: it confers
        access whether or not anybody exercises it, and the audit log is
        silent about one nobody touches.
        """
        out: list[dict[str, Any]] = []
        resp = await client.get(
            f"{_GITHUB_BASE}/orgs/{self._github_org}/copilot/billing/seats",
            headers=headers,
            params={"per_page": _LIMIT},
        )
        if resp.status_code != 200:
            logger.warning("llm_usage.copilot_seats_failed", status=resp.status_code)
            return out
        body = resp.json() or {}
        for seat in body.get("seats") or []:
            if not isinstance(seat, dict):
                continue
            assignee = seat.get("assignee") or {}
            out.append(
                self.normalize(
                    {
                        "action": "copilot.seat.assigned",
                        "created_at": seat.get("created_at"),
                        "actor": assignee.get("login"),
                        "seat": seat,
                        "_aisoc_uid": f"copilot-seat-{assignee.get('login') or seat.get('id')}",
                    }
                )
            )
        return out

    def _include(self, raw: dict[str, Any]) -> bool:
        """Whether this record is about AI at all.

        Three of the seven streams carry far more than AI: the Microsoft
        activity feed is every Audit.General record in the tenant, the Entra
        directory audit is every directory change, and the Workspace token
        stream is every OAuth grant. Filtering here rather than downstream
        keeps the lake from absorbing an entire tenant's audit trail under an
        AI connector's name.
        """
        if self._provider == "m365_copilot":
            return str(raw.get("RecordType") or "") in _M365_AI_RECORD_TYPES or str(raw.get("Workload") or "") in {
                "Copilot",
                "ConnectedAIApp",
                "AIApp",
            }
        if self._provider == "entra_consent":
            activity = str(raw.get("activityDisplayName") or "").lower()
            return any(a in activity for a in _ENTRA_CONSENT_ACTIVITIES)
        return True

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    def _event_type(self, raw: dict[str, Any]) -> str:
        provider = self._provider
        if provider in ("openai", "anthropic"):
            vendor = raw.get("type") or raw.get("action") or raw.get("event_type") or "event"
        elif provider.startswith("google_workspace"):
            events = raw.get("events") or []
            first = events[0] if events and isinstance(events[0], dict) else {}
            vendor = first.get("name") or "event"
        elif provider == "m365_copilot":
            vendor = raw.get("Operation") or raw.get("RecordType") or "event"
        elif provider == "entra_consent":
            vendor = raw.get("activityDisplayName") or "event"
        else:
            vendor = raw.get("action") or "event"
        return f"{provider}.{str(vendor).strip().replace(' ', '_').lower()}"

    def _actor(self, raw: dict[str, Any]) -> str | None:
        provider = self._provider
        if provider in ("openai", "anthropic"):
            actor = raw.get("actor") or {}
            email = actor.get("email") if isinstance(actor, dict) else None
            return email or raw.get("actor_email")
        if provider.startswith("google_workspace"):
            actor = raw.get("actor") or {}
            return actor.get("email") if isinstance(actor, dict) else None
        if provider == "m365_copilot":
            return raw.get("UserId") or raw.get("UserKey")
        if provider == "entra_consent":
            initiated = raw.get("initiatedBy") or {}
            user = initiated.get("user") if isinstance(initiated, dict) else None
            if isinstance(user, dict) and user.get("userPrincipalName"):
                return user["userPrincipalName"]
            app = initiated.get("app") if isinstance(initiated, dict) else None
            return app.get("displayName") if isinstance(app, dict) else None
        actor = raw.get("actor")
        return actor if isinstance(actor, str) else None

    def _uid(self, raw: dict[str, Any]) -> str:
        for key in ("_aisoc_uid", "id", "_id", "document_id"):
            value = raw.get(key)
            if value:
                return str(value)
        if self._provider == "m365_copilot":
            return str(raw.get("Id") or "")
        etag = raw.get("etag")
        return str(etag) if etag else ""

    def _timestamp(self, raw: dict[str, Any]) -> Any:
        if self._provider.startswith("google_workspace"):
            identifier = raw.get("id") or {}
            if isinstance(identifier, dict) and identifier.get("time"):
                return identifier["time"]
        for key in ("effective_at", "occurred_at", "timestamp", "CreationTime", "activityDateTime", "created_at"):
            value = raw.get(key)
            if value:
                return value
        return None

    def _evidence(self, raw: dict[str, Any]) -> dict[str, Any]:
        """The fields the AI-estate inventory turns into assets.

        Scopes and application identity, lifted to a stable shape so 6.1's
        recorder does not need to know seven vendor envelopes. `scopes` in
        particular is what the inventory scores a broad grant on.
        """
        evidence: dict[str, Any] = {}
        provider = self._provider
        if provider.startswith("google_workspace"):
            events = raw.get("events") or []
            parameters = events[0].get("parameters") if events and isinstance(events[0], dict) else None
            for parameter in parameters or []:
                if not isinstance(parameter, dict):
                    continue
                name = parameter.get("name")
                value = parameter.get("value") or parameter.get("multiValue") or parameter.get("intValue")
                if name == "app_name":
                    # Same vendor key, two meanings. On the token stream it is
                    # the third-party application that was granted access; on
                    # the Gemini stream it is the Workspace surface the human
                    # used it from (gmail, docs, meet). Folding them together
                    # would put "gmail" in an application column.
                    if provider == "google_workspace_oauth":
                        evidence["application"] = value
                    else:
                        evidence["app_name"] = value
                elif name == "client_id":
                    evidence["client_id"] = value
                elif name == "scope":
                    evidence["scopes"] = value if isinstance(value, list) else [value]
                elif name in ("feature_source", "action", "event_category"):
                    evidence[name] = value
        elif provider == "m365_copilot":
            evidence["application"] = raw.get("AppIdentity")
            evidence["record_type"] = raw.get("RecordType")
            evidence["workload"] = raw.get("Workload")
            evidence["app_host"] = raw.get("AppHost")
        elif provider == "entra_consent":
            targets = raw.get("targetResources") or []
            first = targets[0] if targets and isinstance(targets[0], dict) else {}
            evidence["application"] = first.get("displayName")
            evidence["client_id"] = first.get("id")
            scopes: list[str] = []
            for prop in first.get("modifiedProperties") or []:
                label = str(prop.get("displayName", "")).lower() if isinstance(prop, dict) else ""
                # Microsoft labels this "ConsentAction.Permissions", not
                # "scope". Matching only on "scope" drops every consent
                # grant's scope list and leaves each one looking alike.
                if isinstance(prop, dict) and ("scope" in label or "permission" in label):
                    new_value = str(prop.get("newValue") or "").strip('"')
                    scopes.extend(s for s in new_value.replace(",", " ").split() if s)
            if scopes:
                evidence["scopes"] = scopes
        elif provider == "github_copilot":
            seat = raw.get("seat")
            if isinstance(seat, dict):
                evidence["application"] = "GitHub Copilot"
                evidence["plan_type"] = seat.get("plan_type")
                # Deliberately set even when null, and exempted from the
                # drop-nulls filter below. A seat nobody has used has no last
                # activity; omitting the key makes "never used" and "we did
                # not look" the same thing, and a dormant licence is exactly
                # the row this stream exists to surface.
                evidence["last_activity_at"] = seat.get("last_activity_at")
                return {**{k: v for k, v in evidence.items() if v is not None}, "last_activity_at": seat.get("last_activity_at")}
            else:
                evidence["repository"] = raw.get("repo")
        return {k: v for k, v in evidence.items() if v is not None}

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        event_type = self._event_type(raw)
        # Two spellings, because `_event_type` folds the vendor's spaces into
        # underscores and the tables below are written the way each vendor
        # writes them: OpenAI emits `api_key.created`, Entra emits
        # "Add app role assignment to service principal". Matching one form
        # silently drops the other, which is how the most serious directory
        # event in this connector scored `info`.
        spellings = (event_type.lower(), event_type.lower().replace("_", " "))
        severity = "info"
        if any(h in form for form in spellings for h in _HIGH):
            severity = "high"
        if any(c in form for form in spellings for c in _CRITICAL):
            severity = "critical"
        actor = self._actor(raw)
        evidence = self._evidence(raw)

        return {
            "source": self.connector_id,
            "category": self.connector_category,
            "severity": severity,
            "title": f"{self._provider} audit: {event_type.split('.', 1)[-1]}",
            "description": (f"provider={self._provider}; stream={PROVIDER_STREAM[self._provider]}; event_type={event_type}; actor={actor}"),
            "external_id": self._uid(raw),
            # The dotted event_type at the TOP LEVEL so the llm-* and ai-*
            # detection rules, which match on `event_type`, fire against the
            # namespace `DetectionEngine._raw_fields` builds.
            "event_type": event_type,
            "provider": self._provider,
            "stream": PROVIDER_STREAM[self._provider],
            "actor": actor,
            "actor_email": actor,
            "created_at": self._timestamp(raw),
            # The inventory reads these two by name.
            "application": evidence.get("application"),
            "scopes": evidence.get("scopes"),
            "evidence": evidence,
            # `raw_event`, not `raw`. The Go normalizer's isCanonicalEnvelope
            # check looks for `raw_event` + `source`; emitting `raw` missed it,
            # so these events fell through to the lenient fallback, borrowed the
            # splunk_enterprise profile, and were stamped Splunk / Network
            # Activity (class_uid 4001). Category 4 is not a finding, so the
            # promoter never turned any of them into an alert unless the
            # severity map happened to reach 4.
            "raw_event": raw,
        }


def _rfc3339(epoch: float) -> str:
    """UTC RFC 3339, which every one of the seven APIs accepts."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))
