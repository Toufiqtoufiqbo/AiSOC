---
title: AI / LLM Usage Audit
description: AI control-plane and assistant-usage audit from seven providers — OpenAI, Anthropic, Gemini in Workspace, M365 Copilot, Entra consent, Workspace OAuth grants and GitHub Copilot.
---

# AI / LLM Usage Audit

The **AI / LLM Usage Audit** connector (`llm_usage`, category `saas`) is the
**governance** surface for AI adoption: who minted an API key, who was made an
owner, who consented to an AI application reading a mailbox, and which humans
are using which assistant. Each event normalizes into the AiSOC alert shape
with a dotted `event_type` the `llm-*` and `ai-*` detection rules match on, and
feeds the [AI estate inventory](../concepts/ai-estate-discovery.md), which turns
these events into `provider_key` and `oauth_grant` assets.

It is deliberately **not** the runtime surface. What an agent did once running
— which tools it called, against which resources — arrives through the
`ai_gateway` connector and the `aisoc-ai-sdk`.

## Providers, and the endpoint each one reads

Every endpoint below was read from the provider's current published reference
before it was implemented. Pick one provider per connector instance.

| Provider | Stream | Endpoint | Credential |
| --- | --- | --- | --- |
| `openai` | control plane | `GET https://api.openai.com/v1/organization/audit_logs` | Admin API key |
| `anthropic` | control plane | `GET https://api.anthropic.com/v1/organizations/audit_logs` | Admin API key |
| `google_workspace_gemini` | usage | `GET https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/gemini_in_workspace_apps` | Service account with domain-wide delegation + super-admin to impersonate |
| `google_workspace_oauth` | OAuth grants | `.../applications/token` | same |
| `m365_copilot` | usage | `GET https://manage.office.com/api/v1.0/{tenant}/activity/feed/subscriptions/content?contentType=Audit.General` | Entra app, client credentials, `ActivityFeed.Read` |
| `entra_consent` | OAuth grants | `GET https://graph.microsoft.com/v1.0/auditLogs/directoryAudits` | Entra app, client credentials, `AuditLog.Read.All` |
| `github_copilot` | control plane | `GET https://api.github.com/orgs/{org}/audit-log` + `.../copilot/billing/seats` | Token with `read:audit_log` and `manage_billing:copilot` |

**Stream is not cosmetic.** A *usage* record says a human used an assistant; a
*control-plane* record says somebody changed what an assistant may do; an
*OAuth grant* record says an application acquired standing access. The three
reach different detections, and the value is carried on every event.

## What has and has not been verified

:::caution No provider here has been exercised against a funded account
Every endpoint above is verified against the vendor's current published
reference, and every test fixture is built from the documented response shape.
**None is a recording from a live tenant**, because this repository has no
funded account with any of the seven. The per-provider state is stated rather
than averaged:

| Provider | Endpoint verified against vendor reference | Exercised against a live tenant |
| --- | --- | --- |
| `openai` | yes | **not measured** |
| `anthropic` | yes | **not measured** |
| `google_workspace_gemini` | yes | **not measured** |
| `google_workspace_oauth` | yes | **not measured** |
| `m365_copilot` | yes | **not measured** |
| `entra_consent` | yes | **not measured** |
| `github_copilot` | yes | **not measured** |

"Not measured" is not zero, and it is not a failure. It means nobody has run
it, which is a different statement from "it was run and did not work".
:::

## Three things worth knowing before you configure one

**Three of the streams carry far more than AI.** The Microsoft activity feed is
every `Audit.General` record in the tenant, the Entra directory audit is every
directory change, and the Workspace token stream is every OAuth grant. The
connector filters to AI records before emitting, so configuring it does not
pull an entire tenant's audit trail into the lake under an AI connector's name.

**The Microsoft content endpoint returns blob references, not records.** The
connector follows each one. A reader that normalized the reference list would
report "no Copilot activity" on a tenant that has plenty.

**The Gemini stream starts at 2025-06-20 and keeps a rolling 180 days.** A
question about AI usage before that date has no answer from this source.

## What you get

| Event family | Example `event_type` | Severity floor |
| --- | --- | --- |
| API key creation | `openai.api_key.created` | high |
| Owner/role grant | `anthropic.member.added` | high |
| Logging or MFA disabled | `openai.logging.setting.updated` | critical |
| OAuth grant to an application | `google_workspace_oauth.authorize` | high |
| Application permission granted in Entra | `entra_consent.add_app_role_assignment_to_service_principal` | critical |
| Copilot interaction | `m365_copilot.copilotinteraction` | info |
| Gemini used in a Workspace app | `google_workspace_gemini.feature_utilization` | info |
| Copilot seat assigned | `github_copilot.copilot.seat.assigned` | high |

A Copilot or Gemini interaction is `info` on purpose: a human using an approved
assistant is usage, not a finding. What makes it interesting is a detection
over the *pattern* — a spend anomaly, a first use from a new country — which is
what the `ai-*` rule pack is for.

## Setup

1. In **Connectors → Add connector**, choose **AI / LLM Usage Audit**.
2. Pick the **provider**. Each needs a different credential; the connector
   refuses a half-configured instance at save, naming the missing field,
   rather than letting it fail later as a vendor 401 that reads like your
   credentials are wrong.
3. Click **Test connection**, then **Save**. The scheduler polls on the
   default cadence.

Events flow through ingest → Kafka → fusion, where the `llm-*` and `ai-*`
detections fire, matching alerts are auto-triaged, and the AI estate inventory
records a `provider_key` or `oauth_grant` asset.

<!-- BEGIN GENERATED FIELD REFERENCE -->

## Configuration reference

{/* Generated by scripts/generate_connector_docs.py from the connector's
    schema(). Edit the schema, not this table. */}

| Field | Label | Type | Required | Default | Notes |
|-------|-------|------|----------|---------|-------|
| `provider` | Provider | select | yes | — | Each provider needs a different credential — see the fields below. An instance configured for the wrong one is refused at save rather than failing later as a vendor 401. · one of: `openai`, `anthropic`, `google_workspace_gemini`, `google_workspace_oauth`, `m365_copilot`, `entra_consent`, `github_copilot` |
| `api_key` | Admin / audit API key | secret | no | — | **encrypted at rest** · OpenAI and Anthropic only. |
| `service_account_json` | Google service account JSON key | secret | no | — | **encrypted at rest** · Both Google providers. Needs domain-wide delegation with the admin.reports.audit.readonly scope, and a super-admin to impersonate. |
| `admin_email` | Google super-admin email | string | no | — | Both Google providers: the admin the service account impersonates. |
| `tenant_id` | Microsoft tenant ID | string | no | — | — |
| `client_id` | Microsoft application (client) ID | string | no | — | — |
| `client_secret` | Microsoft client secret | secret | no | — | **encrypted at rest** |
| `github_org` | GitHub organisation | string | no | — | — |
| `github_token` | GitHub token | secret | no | — | **encrypted at rest** · Needs read:audit_log and manage_billing:copilot (or read:org for seats). |

:::note Credential handling
`api_key`, `service_account_json`, `client_secret`, `github_token` are encrypted at rest by the credential vault before the row is written, and decrypted only at poll time. The value is never logged and never returned by the API. See [credential vault](../operations/credentials.md).
:::

<!-- END GENERATED FIELD REFERENCE -->
