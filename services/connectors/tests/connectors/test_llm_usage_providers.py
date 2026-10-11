"""The five providers depth plan 6.3 adds, against their published shapes.

Every payload here was built from the vendor's **current** reference, fetched
before it was used:

* Gemini in Workspace — `developers.google.com/workspace/admin/reports/v1/appendix/activity/gemini-in-workspace-apps`
* Workspace OAuth token audit — `.../appendix/activity/token`
* Microsoft 365 Copilot — `learn.microsoft.com/purview/audit-copilot` for the
  record shape, `learn.microsoft.com/office/office-365-management-api/...` for
  the two-step content endpoint
* Microsoft Entra — `learn.microsoft.com/graph/api/directoryaudit-list`
* GitHub Copilot — `docs.github.com/rest/copilot/copilot-user-management`

Two things these tests assert that a payload-only suite would not, and both
have caught real defects in this repository before:

**The request shape.** Across the five closed-finding readers, three had
hostname and username null not because the adapter was wrong but because the
*query* projected the fields away. A mock that answers whatever is asked
hides that forever, so each test below reads the recorded request back and
asserts the endpoint, and where it matters the filter.

**The filter.** Three of these streams carry far more than AI — the Microsoft
activity feed is every `Audit.General` record in the tenant, the Entra audit
is every directory change. A connector that ingested all of it would pull an
entire tenant's audit trail into the lake under an AI connector's name.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from app.connectors.llm_usage import PROVIDER_STREAM, PROVIDERS, LlmUsageConnector


_LADDER = {"info", "low", "medium", "high", "critical"}

def _google_creds() -> dict[str, str]:
    """A service account with a **real** RSA key.

    Generated rather than stubbed, because the Google providers build and sign
    an RS256 assertion locally before the token request goes out. A placeholder
    key makes the signing raise, `fetch_alerts` swallows it, and the test then
    passes or fails for a reason that has nothing to do with the connector —
    which is exactly how these two first appeared to return no events at all.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return {
        "service_account_json": json.dumps(
            {
                "type": "service_account",
                "client_email": "bot@p.iam.gserviceaccount.com",
                "private_key": pem,
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        ),
        "admin_email": "admin@example.com",
    }


GOOGLE_CREDS = _google_creds()
MS_CREDS = {"tenant_id": "11111111-1111-1111-1111-111111111111", "client_id": "app", "client_secret": "secret"}
GH_CREDS = {"github_org": "example-org", "github_token": "ghp_x"}


def _stub_google_token() -> None:
    respx.post("https://oauth2.googleapis.com/token").respond(200, json={"access_token": "g-token", "expires_in": 3600})


def _stub_ms_token() -> None:
    respx.post(url__regex=r"https://login\.microsoftonline\.com/.*/oauth2/v2\.0/token").respond(
        200, json={"access_token": "ms-token", "expires_in": 3600}
    )


def _assert_events(events: list[dict], expected_provider: str) -> None:
    assert events, f"{expected_provider}: fetch_alerts returned nothing from the mock server"
    for event in events:
        assert event["source"] == "llm_usage"
        assert event["severity"] in _LADDER, event["severity"]
        assert event["provider"] == expected_provider
        assert event["event_type"].startswith(f"{expected_provider}.")
        # `raw_event`, not `raw`: the Go normalizer's canonical-envelope check
        # looks for this key, and 26 connectors once missed it and were
        # misattributed to Splunk at a class the promoter never promotes.
        assert "raw_event" in event


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------


def test_every_provider_declares_a_stream():
    """A usage record and a control-plane record mean different things.

    One says a human used an assistant; the other says somebody changed what
    an assistant may do. Both directions, so a provider added without a
    stream — or a stream for a provider that does not exist — fails here.
    """
    assert set(PROVIDER_STREAM) == set(PROVIDERS)
    assert set(PROVIDER_STREAM.values()) <= {"control_plane", "usage", "oauth_grant"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider", "kwargs", "missing"),
    [
        ("google_workspace_gemini", {}, "service_account_json"),
        ("m365_copilot", {"tenant_id": "t"}, "client_id"),
        ("github_copilot", {"github_org": "o"}, "github_token"),
    ],
)
async def test_a_half_configured_provider_is_refused_at_save(provider: str, kwargs: dict, missing: str):
    """Refused here, not at the first poll.

    An instance that saves cleanly and then answers 401 reads to an operator
    as "my vendor credentials are wrong", which sends them to the wrong place
    entirely. The repository has shipped that exact failure before, as a bare
    "Connection test failed" on a 401 the console could not classify.
    """
    with pytest.raises(ValueError) as caught:
        LlmUsageConnector(provider=provider, **kwargs)
    assert missing in str(caught.value)


# ---------------------------------------------------------------------------
# Gemini in Google Workspace
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_gemini_in_workspace_usage():
    _stub_google_token()
    route = respx.get(url__regex=r"https://admin\.googleapis\.com/.*/gemini_in_workspace_apps.*").respond(
        200,
        json={
            "items": [
                {
                    "kind": "admin#reports#activity",
                    "id": {
                        "time": "2026-10-09T08:14:22.000Z",
                        "uniqueQualifier": "-1234567890",
                        "applicationName": "gemini_in_workspace_apps",
                    },
                    "actor": {"email": "ada@example.com", "profileId": "1122"},
                    "events": [
                        {
                            "type": "ai_usage_event",
                            "name": "feature_utilization",
                            "parameters": [
                                {"name": "action", "value": "conversation"},
                                {"name": "app_name", "value": "gmail"},
                                {"name": "event_category", "value": "active_conversations"},
                                {"name": "feature_source", "value": "side_panel"},
                            ],
                        }
                    ],
                }
            ]
        },
    )
    connector = LlmUsageConnector(provider="google_workspace_gemini", **GOOGLE_CREDS)
    events = await connector.fetch_alerts(3600)
    _assert_events(events, "google_workspace_gemini")

    assert events[0]["event_type"] == "google_workspace_gemini.feature_utilization"
    assert events[0]["actor"] == "ada@example.com"
    assert events[0]["created_at"] == "2026-10-09T08:14:22.000Z"
    assert events[0]["evidence"]["app_name"] == "gmail"
    assert events[0]["stream"] == "usage"

    # The request, not only the response. `eventName` is what keeps this to
    # the usage event rather than the whole application's stream.
    request = route.calls.last.request
    assert "gemini_in_workspace_apps" in str(request.url)
    assert "eventName=feature_utilization" in str(request.url)
    assert request.headers["Authorization"] == "Bearer g-token"


# ---------------------------------------------------------------------------
# Workspace OAuth grants
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_workspace_oauth_authorize_carries_its_scopes():
    """The scopes are the point.

    An AI note-taker granted `https://mail.google.com/` can read every message
    the grantee can, and the inventory scores a broad grant on exactly this
    field. Dropping it would leave every grant looking alike.
    """
    _stub_google_token()
    route = respx.get(url__regex=r"https://admin\.googleapis\.com/.*/applications/token.*").respond(
        200,
        json={
            "items": [
                {
                    "id": {"time": "2026-10-09T09:00:00.000Z", "applicationName": "token", "uniqueQualifier": "-999"},
                    "actor": {"email": "ada@example.com"},
                    "events": [
                        {
                            "type": "auth",
                            "name": "authorize",
                            "parameters": [
                                {"name": "app_name", "value": "Meeting Notetaker AI"},
                                {"name": "client_id", "value": "9988.apps.googleusercontent.com"},
                                {"name": "client_type", "value": "WEB"},
                                {"name": "scope", "multiValue": ["https://mail.google.com/", "https://www.googleapis.com/auth/drive"]},
                            ],
                        }
                    ],
                }
            ]
        },
    )
    connector = LlmUsageConnector(provider="google_workspace_oauth", **GOOGLE_CREDS)
    events = await connector.fetch_alerts(3600)
    _assert_events(events, "google_workspace_oauth")

    event = events[0]
    assert event["event_type"] == "google_workspace_oauth.authorize"
    assert event["application"] == "Meeting Notetaker AI"
    assert event["scopes"] == ["https://mail.google.com/", "https://www.googleapis.com/auth/drive"]
    assert event["evidence"]["client_id"] == "9988.apps.googleusercontent.com"
    # A grant is high, not info: it is the moment an application acquires
    # standing access to somebody's mail.
    assert event["severity"] == "high"
    assert "applications/token" in str(route.calls.last.request.url)


# ---------------------------------------------------------------------------
# Microsoft 365 Copilot
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_m365_copilot_follows_the_content_blob():
    """The content endpoint returns blob references, not records.

    A reader that normalizes the reference list reports "no Copilot activity"
    on a tenant that has plenty, and the shape of the two is similar enough
    that nothing would complain.
    """
    _stub_ms_token()
    content = respx.get(url__regex=r"https://manage\.office\.com/api/v1\.0/.*/activity/feed/subscriptions/content.*").respond(
        200,
        json=[
            {
                "contentUri": "https://manage.office.com/api/v1.0/t/activity/feed/audit/blob-1",
                "contentId": "blob-1",
                "contentType": "Audit.General",
                "contentCreated": "2026-10-09T10:00:00.000Z",
            }
        ],
    )
    blob = respx.get("https://manage.office.com/api/v1.0/t/activity/feed/audit/blob-1").respond(
        200,
        json=[
            {
                "Id": "f1a2",
                "CreationTime": "2026-10-09T09:58:00",
                "Operation": "CopilotInteraction",
                "RecordType": "CopilotInteraction",
                "Workload": "Copilot",
                "UserId": "ada@example.com",
                "AppIdentity": "Copilot.MicrosoftCopilot.BizChat",
                "AppHost": "BizChat",
            },
            # Not AI. Present on purpose: the feed is every Audit.General
            # record in the tenant, and a connector that ingested all of it
            # would pull the whole audit trail in under an AI connector's name.
            {
                "Id": "f1a3",
                "CreationTime": "2026-10-09T09:59:00",
                "Operation": "FileAccessed",
                "RecordType": "SharePointFileOperation",
                "Workload": "SharePoint",
                "UserId": "ada@example.com",
            },
        ],
    )
    connector = LlmUsageConnector(provider="m365_copilot", **MS_CREDS)
    events = await connector.fetch_alerts(3600)
    _assert_events(events, "m365_copilot")

    assert len(events) == 1, "a SharePoint file access was ingested as AI activity"
    assert events[0]["event_type"] == "m365_copilot.copilotinteraction"
    assert events[0]["actor"] == "ada@example.com"
    assert events[0]["evidence"]["application"] == "Copilot.MicrosoftCopilot.BizChat"
    assert events[0]["evidence"]["workload"] == "Copilot"

    assert blob.called, "the blob was never fetched, so only references were read"
    url = str(content.calls.last.request.url)
    assert "contentType=Audit.General" in url
    assert "startTime=" in url and "endTime=" in url


@respx.mock
@pytest.mark.asyncio
async def test_a_third_party_ai_app_not_deployed_in_the_tenant_is_kept():
    """`AIAppInteraction` is shadow AI by Microsoft's own definition.

    It is the record type that means a third-party AI application the
    organisation has *not* deployed, which is the single most interesting row
    in this stream and the one a `RecordType == "CopilotInteraction"` filter
    would silently drop.
    """
    _stub_ms_token()
    respx.get(url__regex=r"https://manage\.office\.com/api/v1\.0/.*/subscriptions/content.*").respond(
        200, json=[{"contentUri": "https://manage.office.com/api/v1.0/t/activity/feed/audit/b2"}]
    )
    respx.get("https://manage.office.com/api/v1.0/t/activity/feed/audit/b2").respond(
        200,
        json=[
            {
                "Id": "x1",
                "Operation": "AIAppInteraction",
                "RecordType": "AIAppInteraction",
                "Workload": "AIApp",
                "UserId": "ada@example.com",
                "AppIdentity": "AIApp.SaaS.SomeChatbot",
                "CreationTime": "2026-10-09T11:00:00",
            }
        ],
    )
    events = await LlmUsageConnector(provider="m365_copilot", **MS_CREDS).fetch_alerts(3600)
    assert [e["evidence"]["record_type"] for e in events] == ["AIAppInteraction"]


# ---------------------------------------------------------------------------
# Entra consent
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_entra_consent_to_an_ai_application():
    _stub_ms_token()
    route = respx.get(url__regex=r"https://graph\.microsoft\.com/v1\.0/auditLogs/directoryAudits.*").respond(
        200,
        json={
            "value": [
                {
                    "id": "Directory_ABC",
                    "category": "ApplicationManagement",
                    "result": "success",
                    "activityDisplayName": "Consent to application",
                    "activityDateTime": "2026-10-09T12:00:00Z",
                    "initiatedBy": {"user": {"userPrincipalName": "ada@example.com", "ipAddress": "203.0.113.10"}, "app": None},
                    "targetResources": [
                        {
                            "id": "aaaa-bbbb",
                            "displayName": "Meeting Notetaker AI",
                            "type": "ServicePrincipal",
                            "modifiedProperties": [
                                {
                                    "displayName": "ConsentAction.Permissions",
                                    "oldValue": None,
                                    "newValue": '"Mail.Read User.Read offline_access"',
                                }
                            ],
                        }
                    ],
                },
                # A directory change that is not about an application. The
                # stream is every directory audit in the tenant.
                {
                    "id": "Directory_XYZ",
                    "activityDisplayName": "Add member to group",
                    "activityDateTime": "2026-10-09T12:01:00Z",
                    "initiatedBy": {"user": {"userPrincipalName": "ada@example.com"}},
                    "targetResources": [],
                },
            ]
        },
    )
    events = await LlmUsageConnector(provider="entra_consent", **MS_CREDS).fetch_alerts(3600)
    _assert_events(events, "entra_consent")

    assert len(events) == 1, "a group membership change was ingested as an AI consent event"
    assert events[0]["application"] == "Meeting Notetaker AI"
    assert events[0]["scopes"] == ["Mail.Read", "User.Read", "offline_access"]
    assert events[0]["actor"] == "ada@example.com"
    # `$` is percent-encoded on the wire, so the assertion accepts both
    # spellings rather than pinning one and breaking on an httpx change.
    url = str(route.calls.last.request.url)
    assert "$filter=" in url or "%24filter=" in url


@respx.mock
@pytest.mark.asyncio
async def test_an_application_permission_grant_outranks_a_key_being_minted():
    """Admin consent to act without a user is the shape of every malicious-OAuth campaign."""
    _stub_ms_token()
    respx.get(url__regex=r"https://graph\.microsoft\.com/v1\.0/auditLogs/directoryAudits.*").respond(
        200,
        json={
            "value": [
                {
                    "id": "D1",
                    "activityDisplayName": "Add app role assignment to service principal",
                    "activityDateTime": "2026-10-09T13:00:00Z",
                    "initiatedBy": {"user": {"userPrincipalName": "admin@example.com"}},
                    "targetResources": [{"id": "s1", "displayName": "Summariser AI", "modifiedProperties": []}],
                }
            ]
        },
    )
    events = await LlmUsageConnector(provider="entra_consent", **MS_CREDS).fetch_alerts(3600)
    assert events[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# GitHub Copilot
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_github_copilot_audit_and_seats():
    """Seats as well as audit events.

    A seat is the AI estate's dormant account: it confers access whether or
    not anybody exercises it, and the audit log is silent about one nobody
    touches. Reading only the audit log would leave an assigned-and-never-used
    licence invisible.
    """
    audit = respx.get(url__regex=r"https://api\.github\.com/orgs/example-org/audit-log.*").respond(
        200,
        json=[
            {
                "_document_id": "abc123",
                "action": "copilot.cfb_seat_assigned",
                "actor": "ada",
                "created_at": 1760000000000,
                "org": "example-org",
            }
        ],
    )
    seats = respx.get(url__regex=r"https://api\.github\.com/orgs/example-org/copilot/billing/seats.*").respond(
        200,
        json={
            "total_seats": 1,
            "seats": [
                {
                    "created_at": "2026-09-01T00:00:00Z",
                    "last_activity_at": None,
                    "plan_type": "business",
                    "assignee": {"login": "dormant-dev", "type": "User"},
                }
            ],
        },
    )
    events = await LlmUsageConnector(provider="github_copilot", **GH_CREDS).fetch_alerts(3600)
    _assert_events(events, "github_copilot")

    kinds = {e["event_type"] for e in events}
    assert "github_copilot.copilot.cfb_seat_assigned" in kinds
    assert "github_copilot.copilot.seat.assigned" in kinds

    seat_event = next(e for e in events if e["event_type"].endswith("seat.assigned"))
    assert seat_event["actor"] == "dormant-dev"
    # Null rather than a zero date. A seat nobody has used has no last
    # activity, and inventing one would make a dormant licence look active.
    assert seat_event["evidence"]["last_activity_at"] is None

    assert seats.called
    # The filter is what keeps an AI connector from ingesting an entire
    # organisation's audit log.
    assert "action%3Acopilot" in str(audit.calls.last.request.url) or "action:copilot" in str(audit.calls.last.request.url)


@respx.mock
@pytest.mark.asyncio
async def test_a_seat_read_that_fails_does_not_lose_the_audit_events():
    """Partial coverage beats none, and the loss is logged rather than silent."""
    respx.get(url__regex=r"https://api\.github\.com/orgs/example-org/audit-log.*").respond(
        200, json=[{"_document_id": "d1", "action": "copilot.editor_signin", "actor": "ada", "created_at": 1760000000000}]
    )
    respx.get(url__regex=r"https://api\.github\.com/orgs/example-org/copilot/billing/seats.*").respond(403, json={"message": "Forbidden"})
    events = await LlmUsageConnector(provider="github_copilot", **GH_CREDS).fetch_alerts(3600)
    assert [e["event_type"] for e in events] == ["github_copilot.copilot.editor_signin"]


# ---------------------------------------------------------------------------
# The original two still work
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_openai_is_unchanged():
    respx.get(url__regex=r"https://api\.openai\.com/v1/organization/audit_logs.*").respond(
        200, json={"data": [{"id": "l1", "type": "api_key.created", "actor": {"email": "a@corp.com"}, "effective_at": 1760000000}]}
    )
    connector = LlmUsageConnector(provider="openai", api_key="k")
    assert (await connector.test_connection())["success"] is True
    events = await connector.fetch_alerts(300)
    _assert_events(events, "openai")
    assert events[0]["event_type"] == "openai.api_key.created"
    assert events[0]["severity"] == "high"


@respx.mock
@pytest.mark.asyncio
async def test_anthropic_is_unchanged():
    respx.get(url__regex=r"https://api\.anthropic\.com/v1/organizations/audit_logs.*").respond(
        200, json={"data": [{"id": "a1", "action": "member.added", "actor": {"email": "b@corp.com"}}]}
    )
    connector = LlmUsageConnector(provider="anthropic", api_key="k")
    events = await connector.fetch_alerts(300)
    _assert_events(events, "anthropic")
    assert events[0]["event_type"] == "anthropic.member.added"


@respx.mock
@pytest.mark.asyncio
async def test_a_vendor_error_is_survived_rather_than_raised():
    respx.get(url__regex=r"https://api\.openai\.com/.*").respond(500, json={"error": "boom"})
    assert await LlmUsageConnector(provider="openai", api_key="k").fetch_alerts(300) == []
