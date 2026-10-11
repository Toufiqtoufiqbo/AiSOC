"""Per-tenant detection coverage, and the three states it refuses to merge.

Depth plan 3.7 / gap-closure 9.1. The assertions here are about the
distinctions that make a coverage page worth reading, because a coverage
number is easy to compute and easy to compute uselessly.

The one that matters most: **a rule for a vendor the tenant has not
connected is not coverage.** The console's existing "techniques tagged"
figure is the same for every tenant, so a tenant running only Okta and
Workspace gets credit for 1,687 Windows rules they can never fire. If this
module repeated that, it would publish a reassuring number that disagrees
with the alert queue.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from app.services import detection_coverage
from app.services.detection_coverage import (
    CONNECTOR_PRODUCTS,
    coverage_report,
    products_for,
)

TENANT = uuid.uuid4()


@dataclass
class _Rule:
    product: str
    mitre_techniques: tuple[str, ...]


@dataclass
class _Conn:
    connector_type: str
    last_event_at: datetime | None


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> _Result:
        return self

    def all(self) -> list[Any]:
        return self._rows


class _FakeDB:
    """Answers the two selects the module makes, in the order it makes them.

    Keyed on the model being selected rather than on call order, because a
    fake that answers by position silently returns connectors for the alert
    query the moment someone reorders two lines.
    """

    def __init__(self, connectors: list[_Conn], alert_techniques: list[list[str]]) -> None:
        self._connectors = connectors
        self._alerts = alert_techniques

    async def execute(self, statement: Any) -> _Result:
        text = str(statement).lower()
        if "connectors" in text:
            return _Result(list(self._connectors))
        return _Result(list(self._alerts))


@pytest.fixture
def rules(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        detection_coverage,
        "builtin_rules",
        lambda: (
            _Rule("aws", ("T1078.004",)),
            _Rule("windows", ("T1059.001",)),
            _Rule("okta", ("T1556.006",)),
        ),
    )


NOW = datetime(2026, 10, 11, tzinfo=UTC)


@pytest.mark.asyncio
async def test_a_rule_on_a_connected_source_is_coverage(rules: None) -> None:
    db = _FakeDB([_Conn("aws_cloudtrail", NOW)], [["T1078.004"]])
    report = await coverage_report(db, TENANT)
    row = next(t for t in report.techniques if t.technique == "T1078.004")
    assert row.state == "covered"
    assert row.connected_products == ("aws",)


@pytest.mark.asyncio
async def test_a_rule_for_an_unconnected_vendor_is_not_coverage(rules: None) -> None:
    """The whole point. An Okta-only tenant gets no credit for Windows rules.

    `T1059.001` has an executable rule, so a global coverage figure would
    call this tenant covered. They ingest nothing that could ever fire it.
    """
    db = _FakeDB([_Conn("okta", NOW)], [["T1059.001"]])
    report = await coverage_report(db, TENANT)
    row = next(t for t in report.techniques if t.technique == "T1059.001")
    assert row.state == "no_telemetry"
    assert row.rules_anywhere == 1
    assert row.rules_on_connected_sources == 0
    # The actionable half: say which connector would fix it.
    assert row.missing_products == ("windows",)


@pytest.mark.asyncio
async def test_a_technique_with_no_rule_anywhere_is_a_gap(rules: None) -> None:
    """The only state the drafting agent may act on."""
    db = _FakeDB([_Conn("aws_cloudtrail", NOW)], [["T1537"]])
    report = await coverage_report(db, TENANT)
    row = next(t for t in report.techniques if t.technique == "T1537")
    assert row.state == "gap"
    assert row.rules_anywhere == 0
    assert report.gaps == (row,)


@pytest.mark.asyncio
async def test_a_tenant_with_no_telemetry_has_no_gaps_to_draft(rules: None) -> None:
    """Drafting without telemetry produces rules matching on nothing.

    Worse than no rule: it raises the coverage figure while making the
    tenant no safer.
    """
    db = _FakeDB([], [["T1537"]])
    report = await coverage_report(db, TENANT)
    assert report.gaps == ()
    assert next(t for t in report.techniques if t.technique == "T1537").state == "no_telemetry"


@pytest.mark.asyncio
async def test_a_configured_connector_that_never_delivered_is_not_telemetry(rules: None) -> None:
    """Configured is not connected, and the difference is the useful line."""
    db = _FakeDB([_Conn("aws_cloudtrail", None)], [["T1078.004"]])
    report = await coverage_report(db, TENANT)
    assert report.connected_products == ()
    assert report.silent_connectors == ("aws_cloudtrail",)
    assert next(t for t in report.techniques if t.technique == "T1078.004").state == "no_telemetry"


@pytest.mark.asyncio
async def test_ranking_puts_what_the_tenant_actually_sees_first(rules: None) -> None:
    db = _FakeDB(
        [_Conn("aws_cloudtrail", NOW)],
        [["T1537"]] * 40 + [["T1190"]],
    )
    report = await coverage_report(db, TENANT)
    assert report.techniques[0].technique == "T1537"
    assert report.techniques[0].relevance > report.techniques[1].relevance


@pytest.mark.asyncio
async def test_every_row_carries_the_counts_it_was_ranked_on(rules: None) -> None:
    """A bare score is unarguable in the bad sense.

    An analyst cannot tell a 0.8 from forty alerts apart from a 0.8 from one
    alert and a generous weight, so the inputs travel with the number.
    """
    db = _FakeDB([_Conn("aws_cloudtrail", NOW)], [["T1537"], ["T1537"]])
    report = await coverage_report(db, TENANT)
    row = report.techniques[0]
    assert row.alerts_seen == 2
    assert row.rules_anywhere == 0
    assert 0.0 <= row.relevance <= 1.0


@pytest.mark.asyncio
async def test_threat_intel_relevance_can_be_folded_in(rules: None) -> None:
    """The plan ranks on intel and KEV too, not only on the alert table."""
    db = _FakeDB([_Conn("aws_cloudtrail", NOW)], [])
    report = await coverage_report(db, TENANT, extra_techniques={"T1190": 12})
    row = next(t for t in report.techniques if t.technique == "T1190")
    assert row.alerts_seen == 12
    assert row.state == "gap"


@pytest.mark.asyncio
async def test_an_unreadable_catalogue_is_reported_not_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    """ "No rules found" and "the ruleset would not load" mean opposite things.

    Both produce an empty index, and a page that calls every technique a gap
    because a file was missing is worse than one that says the file was
    missing.
    """

    def _boom() -> Any:
        raise detection_coverage.BuiltinCatalogueUnavailable("no compiled ruleset")

    monkeypatch.setattr(detection_coverage, "builtin_rules", _boom)
    db = _FakeDB([_Conn("aws_cloudtrail", NOW)], [["T1078.004"]])
    report = await coverage_report(db, TENANT)
    assert report.counts["catalogue_readable"] == 0


@pytest.mark.asyncio
async def test_a_quiet_tenant_gets_an_empty_report_not_a_confident_zero(rules: None) -> None:
    db = _FakeDB([], [])
    report = await coverage_report(db, TENANT)
    assert report.techniques == ()
    assert report.counts["techniques_ranked"] == 0
    # Readable, so the caller can tell this from the case above.
    assert report.counts["catalogue_readable"] == 1


def test_connector_products_cover_the_cases_the_fallback_gets_wrong() -> None:
    """The stem fallback is right often and wrong in named places.

    `google_workspace` → `google-workspace` and `onepassword` → `1password`
    are the two the vocabulary genuinely disagrees on; if either regressed,
    those tenants would read as having no telemetry for anything.
    """
    assert products_for("google_workspace") == ("google-workspace",)
    assert products_for("onepassword") == ("1password",)
    assert products_for("azure_entra") == ("azure", "identity")
    # The fallback, for connectors with no entry.
    assert products_for("salesforce") == ("salesforce",)
    assert products_for("snowflake") == ("snowflake",)


def test_the_connector_map_names_real_connectors() -> None:
    """A map entry for a connector that does not exist is dead configuration."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    pkg = root / "services" / "connectors" / "app" / "connectors"
    if not pkg.is_dir():  # pragma: no cover - the connectors service is always present in CI
        pytest.skip("connectors package not present")
    slugs = {p.stem for p in pkg.glob("*.py")}
    unknown = sorted(k for k in CONNECTOR_PRODUCTS if k not in slugs)
    assert not unknown, f"CONNECTOR_PRODUCTS names connectors that do not exist: {unknown}"
