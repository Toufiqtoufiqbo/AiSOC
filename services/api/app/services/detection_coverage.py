"""Per-tenant detection coverage, and the gaps worth closing for *this* estate.

Depth plan 3.7 / gap-closure 9.1:

    For each tenant, rank ATT&CK techniques by relevance (techniques seen in
    the tenant's alerts, threat intel and KEV-linked activity, weighted by
    the log sources the tenant actually ingests). Compare them against the
    compiled executable ruleset, and show the gaps.

Why a global coverage number is the wrong question
---------------------------------------------------
The console already publishes "techniques tagged", computed across the whole
executable corpus. That number is the same for every tenant, and it is
reassuring in a way that is not useful: a tenant running only Okta and
Workspace gets credit for 1,687 Windows rules they will never fire, because
no connector of theirs emits a Windows process-creation event.

So coverage here means something narrower and checkable: **an executable rule
exists for this technique, and its log source is one this tenant actually
ingests.** A rule for a vendor the tenant has not connected is not coverage,
and counting it is how a coverage page comes to disagree with the alert queue.

Three states, not two
---------------------
The distinction that makes this actionable is between a gap you can close and
one you cannot, and collapsing them is what turns a coverage page into a list
nobody works:

``covered``
    An executable rule for the technique, on a source the tenant ingests.

``gap``
    The tenant has seen this technique *and* ingests a source that could
    carry a rule for it, and no such rule exists. This is the only state the
    drafting agent acts on.

``no_telemetry``
    Relevant to the tenant, but no connected source emits anything a rule
    could match. Drafting here would produce a rule matching on fields
    nothing emits — worse than no rule, because it raises the coverage figure
    while making the tenant no safer. Reported with the connector they would
    need, which is a sales-and-onboarding answer rather than a content one.

Evidence, not a score
---------------------
Every ranked technique carries the counts it was ranked on — alerts seen,
sources available, rules found. A bare relevance score is unarguable in the
bad sense: an analyst cannot tell whether a 0.8 came from forty alerts or
from one alert and a generous weight. The score is published beside its
inputs so the ranking can be disagreed with.

Nothing here drafts, promotes or writes a rule. It answers "what is missing,
for whom, and can it be fixed" — the proposal path
(`app/api/v1/endpoints/detection_proposals.py`) owns everything after that,
including the separation of duties that keeps an author from approving their
own rule.
"""

from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.connector import Connector
from app.services.builtin_rules import BuiltinCatalogueUnavailable, builtin_rules

#: `connector_type` → the `log_source.product` values its events carry.
#:
#: Needed because the two vocabularies are genuinely different: a tenant
#: connects `azure_entra`, and rules for it declare `product: azure`. Without
#: this map every tenant would read as having no telemetry for anything,
#: which is the failure mode that makes a coverage page worse than none.
#:
#: Unmapped connectors fall back to their own id with the trailing qualifier
#: stripped (`slack_audit` → `slack`), which is right far more often than it
#: is wrong; `test_detection_coverage.py` pins the ones where it is wrong.
CONNECTOR_PRODUCTS: dict[str, tuple[str, ...]] = {
    "aws_cloudtrail": ("aws",),
    "aws_cloudtrail_s3": ("aws",),
    "aws_guardduty": ("aws",),
    "aws_security_hub": ("aws",),
    "aws_vpc_flow": ("aws",),
    "azure_activity": ("azure",),
    "azure_defender": ("azure",),
    "azure_entra": ("azure", "identity"),
    "azure_event_hubs": ("azure",),
    "gcp_cloud_audit": ("gcp",),
    "gcp_pubsub": ("gcp",),
    "gcp_scc": ("gcp",),
    "gcp_service_account": ("gcp",),
    "kubernetes_audit": ("kubernetes",),
    "google_workspace": ("google-workspace",),
    "m365_audit": ("m365",),
    "slack_audit": ("slack",),
    "onepassword": ("1password",),
    "jira_connector": ("atlassian",),
    "confluence_audit": ("atlassian", "confluence"),
    "okta": ("okta", "identity"),
    "auth0": ("auth0", "identity"),
    "duo_security": ("duo", "identity"),
    "jumpcloud": ("identity",),
    "windows_event": ("windows",),
    "auditd": ("linux",),
    "osctrl": ("osquery",),
    "crowdstrike": ("edr",),
    "sentinelone": ("edr",),
    "carbon_black": ("edr",),
    "cortex_xdr": ("edr",),
    "trend_vision_one": ("edr",),
    "zeek_suricata": ("ndr",),
    "zscaler": ("proxy",),
    "cisco_umbrella": ("dns",),
    "cloudflare": ("cloudflare", "waf"),
    "cloudflare_zt": ("cloudflare",),
}


def products_for(connector_type: str) -> tuple[str, ...]:
    """The `log_source.product` values a connector's events carry."""
    mapped = CONNECTOR_PRODUCTS.get(connector_type)
    if mapped:
        return mapped
    # `slack_audit` → `slack`, `gcp_scc` → `gcp`. Right far more often than
    # wrong, and the map above carries the exceptions.
    stem = connector_type.split("_")[0]
    return (stem.replace("_", "-"),)


@dataclass(frozen=True)
class TechniqueCoverage:
    """One ATT&CK technique, and whether this tenant is covered for it."""

    technique: str
    #: `covered` | `gap` | `no_telemetry`
    state: str
    #: Alerts this tenant has seen carrying the technique. The main input to
    #: relevance, and published so the ranking can be argued with.
    alerts_seen: int
    #: Executable rules for the technique on a source this tenant ingests.
    rules_on_connected_sources: int
    #: Executable rules for the technique on any source at all. A technique
    #: with rules the tenant cannot use is a different problem from one with
    #: no rules anywhere, and the two need different answers.
    rules_anywhere: int
    #: Products this tenant ingests that carry rules for this technique.
    connected_products: tuple[str, ...]
    #: Products that carry rules for it and which the tenant does **not**
    #: ingest. For a `no_telemetry` row this is the answer: connect one.
    missing_products: tuple[str, ...]
    relevance: float


@dataclass(frozen=True)
class CoverageReport:
    techniques: tuple[TechniqueCoverage, ...]
    #: Products the tenant ingests, derived from enabled connectors that have
    #: actually delivered an event. A configured connector that has never
    #: delivered one is not telemetry, and treating it as such is how a
    #: coverage page reports readiness the estate does not have.
    connected_products: tuple[str, ...]
    #: Connectors enabled but not yet seen delivering an event. Named rather
    #: than silently dropped, because "you configured this and it is not
    #: working" is the most actionable line on the page.
    silent_connectors: tuple[str, ...]
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def gaps(self) -> tuple[TechniqueCoverage, ...]:
        """Only the ones the drafting agent may act on."""
        return tuple(t for t in self.techniques if t.state == "gap")


def _rule_index() -> tuple[dict[str, set[str]], bool]:
    """technique → the products that carry an executable rule for it.

    The second element is False when the compiled catalogue could not be
    read. That is reported rather than swallowed: "no rules found" and "the
    ruleset could not be loaded" produce the same empty dict and mean
    opposite things, and a coverage page that reports every technique as a
    gap because a file was missing is worse than one that says so.
    """
    try:
        rules = builtin_rules()
    except BuiltinCatalogueUnavailable:
        return {}, False

    index: dict[str, set[str]] = {}
    for rule in rules:
        product = (rule.product or "").strip().lower()
        for technique in rule.mitre_techniques:
            key = str(technique).strip().upper()
            if not key:
                continue
            index.setdefault(key, set())
            if product:
                index[key].add(product)
    return index, True


async def _connected(db: AsyncSession, tenant_id: uuid.UUID) -> tuple[set[str], tuple[str, ...]]:
    """(products actually delivering, connectors enabled but silent)."""
    rows = (await db.execute(select(Connector).where(Connector.tenant_id == tenant_id, Connector.is_enabled.is_(True)))).scalars().all()
    products: set[str] = set()
    silent: list[str] = []
    for row in rows:
        if row.last_event_at is None:
            silent.append(row.connector_type)
            continue
        products.update(products_for(row.connector_type))
    return products, tuple(sorted(set(silent)))


async def _techniques_seen(db: AsyncSession, tenant_id: uuid.UUID) -> Counter[str]:
    """How often each technique appears in this tenant's own alerts."""
    rows = (await db.execute(select(Alert.mitre_techniques).where(Alert.tenant_id == tenant_id))).scalars().all()
    seen: Counter[str] = Counter()
    for value in rows:
        if not isinstance(value, list):
            continue
        for technique in value:
            key = str(technique).strip().upper()
            if key:
                seen[key] += 1
    return seen


def _relevance(alerts_seen: int, has_telemetry: bool) -> float:
    """Rank by what this tenant has actually experienced.

    Deliberately simple and deliberately published alongside its inputs. A
    weighting nobody can reconstruct is a weighting nobody can challenge,
    and the thing being ranked here is "which gap should a human look at
    first", not a risk score.

    Saturating rather than linear: the difference between one alert and ten
    is large, and between one hundred and one thousand is not — both mean
    "this happens here". Telemetry availability is a multiplier rather than
    a filter so a `no_telemetry` row still sorts sensibly within its own
    state.
    """
    if alerts_seen <= 0:
        base = 0.0
    else:
        base = min(1.0, 0.3 + 0.7 * (min(alerts_seen, 50) / 50))
    return round(base if has_telemetry else base * 0.5, 4)


async def coverage_report(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    extra_techniques: dict[str, int] | None = None,
) -> CoverageReport:
    """Rank this tenant's techniques by relevance and classify each.

    `extra_techniques` folds in relevance from outside the alert table —
    threat intel and KEV-linked activity — as technique → weight. Passed in
    rather than read here so this module has one input shape and the callers
    that have those sources can supply them; a tenant with neither still
    gets a report from its own alerts.
    """
    index, catalogue_readable = _rule_index()
    products, silent = await _connected(db, tenant_id)
    seen = await _techniques_seen(db, tenant_id)
    for technique, weight in (extra_techniques or {}).items():
        key = str(technique).strip().upper()
        if key:
            seen[key] += int(weight)

    out: list[TechniqueCoverage] = []
    for technique, count in seen.items():
        rule_products = index.get(technique, set())
        on_connected = sorted(rule_products & products)
        missing = sorted(rule_products - products)

        if on_connected:
            state = "covered"
        elif rule_products:
            # Rules exist, but for vendors this tenant does not ingest.
            state = "no_telemetry"
        elif products:
            # No rule anywhere, and the tenant has sources that could carry
            # one. This is the only state worth drafting against.
            state = "gap"
        else:
            state = "no_telemetry"

        out.append(
            TechniqueCoverage(
                technique=technique,
                state=state,
                alerts_seen=count,
                rules_on_connected_sources=len(on_connected),
                rules_anywhere=len(rule_products),
                connected_products=tuple(on_connected),
                missing_products=tuple(missing),
                relevance=_relevance(count, state != "no_telemetry"),
            )
        )

    out.sort(key=lambda t: (-t.relevance, -t.alerts_seen, t.technique))
    counts = Counter(t.state for t in out)
    return CoverageReport(
        techniques=tuple(out),
        connected_products=tuple(sorted(products)),
        silent_connectors=silent,
        counts={
            "covered": counts.get("covered", 0),
            "gap": counts.get("gap", 0),
            "no_telemetry": counts.get("no_telemetry", 0),
            "techniques_ranked": len(out),
            # Surfaced so a caller can tell an empty report caused by a
            # quiet tenant from one caused by an unreadable ruleset.
            "catalogue_readable": int(catalogue_readable),
        },
    )


def as_dict(report: CoverageReport) -> dict[str, Any]:
    """The report as the API serialises it."""
    return {
        "connected_products": list(report.connected_products),
        "silent_connectors": list(report.silent_connectors),
        "counts": dict(report.counts),
        "techniques": [
            {
                "technique": t.technique,
                "state": t.state,
                "alerts_seen": t.alerts_seen,
                "rules_on_connected_sources": t.rules_on_connected_sources,
                "rules_anywhere": t.rules_anywhere,
                "connected_products": list(t.connected_products),
                "missing_products": list(t.missing_products),
                "relevance": t.relevance,
            }
            for t in report.techniques
        ],
    }
