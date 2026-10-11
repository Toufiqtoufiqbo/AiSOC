"""The content-depth gate, and the two claims it makes about the tree.

Depth plan 3.6. `scripts/check_content_depth.py` owns the grouping for the
cloud/identity/SaaS/code figure, which exists because the figure was
re-derivable two ways and the two disagreed. A gate that owns a definition
needs its definition held against reality, or it becomes a second opinion
rather than the single one.

Two claims are checked here because both can rot silently:

* **Zoom is excluded because no Zoom connector exists.** The plan says
  "every SaaS source *with a connector*", and a rule for a source nothing
  emits is worse than no rule. The moment someone writes a Zoom connector
  that reason stops being true, and a comment would not notice.
* **Every source the gate requires a minimum of must have a connector**,
  for the same reason in the other direction — a minimum nobody can meet
  honestly invites meeting it dishonestly.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_CONNECTORS = _REPO / "services" / "connectors" / "app" / "connectors"


def _gate():
    path = _REPO / "scripts" / "check_content_depth.py"
    spec = importlib.util.spec_from_file_location("aisoc_content_depth", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _connector_slugs() -> set[str]:
    """Connector module names, re-derived from the tree on every run."""
    assert _CONNECTORS.is_dir(), "connector package is missing — refusing a vacuous pass"
    slugs = {p.stem for p in _CONNECTORS.glob("*.py") if not p.stem.startswith("_") and p.stem != "base"}
    assert len(slugs) > 50, f"only {len(slugs)} connectors found — the glob is probably wrong"
    return slugs


def _has_connector(source: str, slugs: set[str]) -> bool:
    """Whether some connector covers this `log_source`.

    Matched on a normalised stem rather than equality: the corpus says
    `google-workspace` and `1password` where the modules are
    `google_workspace` and `onepassword`, and `atlassian` is covered by
    `jira_connector` and `confluence_audit`.
    """
    aliases = {
        "google-workspace": {"google_workspace"},
        "1password": {"onepassword"},
        "m365": {"m365_audit"},
        "slack": {"slack_audit"},
        "atlassian": {"jira_connector", "confluence_audit"},
        "azure": {"azure_entra", "azure_activity", "azure_defender", "azure_event_hubs"},
        "gcp": {"gcp_cloud_audit", "gcp_pubsub", "gcp_scc", "gcp_service_account"},
        "aws": {"aws_cloudtrail", "aws_guardduty", "aws_security_hub", "aws_vpc_flow"},
        "kubernetes": {"kubernetes_audit"},
    }
    if source in aliases:
        return bool(aliases[source] & slugs)
    return source.replace("-", "_") in slugs


def test_zoom_is_excluded_because_no_zoom_connector_exists() -> None:
    """The reason, not just the exclusion.

    If a Zoom connector lands, this fails and whoever added it is told to
    put Zoom back under the minimum — which is the correct outcome and the
    one a comment in the gate would never produce.
    """
    gate = _gate()
    slugs = _connector_slugs()
    assert not _has_connector("zoom", slugs), (
        "a Zoom connector now exists, so the plan's 'every SaaS source with a connector' "
        "minimum applies to it — add 'zoom' to SAAS_SOURCES in scripts/check_content_depth.py"
    )
    assert "zoom" not in gate.SAAS_SOURCES


@pytest.mark.parametrize("source", sorted({*_gate().SAAS_SOURCES, *_gate().MINIMUMS, *_gate().CODE_SOURCES}))
def test_every_source_with_a_minimum_has_a_connector(source: str) -> None:
    """A minimum nobody can meet honestly invites meeting it dishonestly."""
    if source == "ci":
        pytest.skip("`ci` is a generic build-system source, not one vendor's connector")
    assert _has_connector(source, _connector_slugs()), f"{source} carries a minimum in check_content_depth.py but no connector emits it"


def test_every_grouped_source_is_in_exactly_one_group() -> None:
    """Two groups claiming one source would double-count the headline."""
    gate = _gate()
    seen: dict[str, str] = {}
    for group, members in gate.GROUPS.items():
        for member in members:
            assert member not in seen, f"{member} is in both {seen[member]} and {group}"
            seen[member] = group


def test_in_scope_and_out_of_scope_do_not_overlap() -> None:
    gate = _gate()
    in_scope = set().union(*gate.GROUPS.values())
    assert not (in_scope & gate.OUT_OF_SCOPE), sorted(in_scope & gate.OUT_OF_SCOPE)


def test_the_gate_passes_on_this_tree() -> None:
    """The ratchet matches what the tree measures, so CI is not pre-broken."""
    result = subprocess.run(  # noqa: S603
        ["python3", str(_REPO / "scripts" / "check_content_depth.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=_REPO,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_gate_refuses_an_empty_tree() -> None:
    """ "Found nothing" and "scanned nothing" must not print the same word."""
    result = subprocess.run(  # noqa: S603
        ["python3", str(_REPO / "scripts" / "check_content_depth.py"), "--self-test"],
        capture_output=True,
        text=True,
        cwd=_REPO,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "self-test OK" in result.stdout
