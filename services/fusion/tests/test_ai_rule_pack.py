"""The AI rule pack, replayed through the real engines.

Depth plan 6.5. Seven detections: four stateless, three windowed.

Why this file exists when `validate_detections.py` already replays fixtures
---------------------------------------------------------------------------
Fixture replay in this repository is **tautological for most of the corpus**:
`build_positive` and `build_negative` synthesize the fixtures *from the rule
they test*, so replaying them proves the matcher agrees with itself. Roughly
600 of the corpus's fixtures are that shape, and 423 of its 878 negatives
invert a clause by prefixing the literal `not-` to the expected value — a rule
passes its negative by failing to match a value no log source would ever emit.

Every fixture in this pack is hand-authored instead, and the negatives are
events a real AI estate produces every day:

* the same key action from an address the tenant uses constantly;
* the same agent calling the same state-changing tool it calls every hour;
* the approved MCP server, not a renamed one;
* the same coding agent started without the flag.

Each negative inverts **the clause the rule is about** — novelty, approval,
the flag — rather than some unrelated field, because a negative that flips the
tool name would prove the opposite of what the rule claims.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from app.services.detection_engine import DetectionEngine
from app.services.windowed_detection import WindowedDetectionEngine

TENANT = "11111111-1111-1111-1111-111111111111"

#: Every rule depth 6.5 names, with the half of the pack it belongs to.
STATELESS_RULES = (
    "ai-provider-key-from-new-source",
    "ai-agent-new-high-risk-tool",
    "ai-mcp-server-unvetted",
    "ai-coding-agent-prompts-disabled",
)
WINDOWED_RULES = (
    "wd-ai-guardrail-violation-rise",
    "wd-ai-token-spend-burst",
    "wd-ai-oauth-app-bulk-access",
)


def event(fields: dict[str, Any]) -> dict[str, Any]:
    """Wrap connector fields the way `services/ingest` publishes them.

    `raw_data` is a JSON **string**: `normalizer.go` runs `json.Marshal` on the
    connector payload. Building the event any other way would test a pipeline
    this product does not have.
    """
    return {
        "tenant_id": TENANT,
        "ocsf_event": {"tenant_uid": TENANT, "class_uid": 6003, "raw_data": json.dumps(fields)},
    }


FIXTURES = Path(__file__).resolve().parents[3] / "detections" / "fixtures"


def _spec(slug: str) -> dict[str, Any]:
    """The rule as the engine loaded it.

    Resolved by `slug`, not by id. A rule's `id` is positional
    (`det-application-090`) and is pinned in `detections/rule-ids.lock.json`,
    so a test naming one would break the moment a sibling rule is inserted —
    which is the exact instability that lock file exists to contain.
    """
    for rule in DetectionEngine()._rules:  # noqa: SLF001 — the loaded corpus is what is under test
        if rule.get("slug") == slug:
            return rule
    raise AssertionError(f"{slug} is not in the engine's loaded ruleset")


def _fixture(which: str, slug: str) -> dict[str, Any]:
    path = FIXTURES / which / f"{slug}.json"
    assert path.is_file(), f"{slug} ships no {which} fixture at {path}"
    return json.loads(path.read_text())


def _fired(engine: DetectionEngine, fields: dict[str, Any]) -> set[str]:
    """Rule *slugs* that fired, resolved from the positional ids the engine returns."""
    by_id = {rule["id"]: rule.get("slug", rule["id"]) for rule in engine._rules}  # noqa: SLF001
    return {by_id.get(hit.rule_id, hit.rule_id) for hit in engine.evaluate(event(fields))}


# ---------------------------------------------------------------------------
# All seven are loaded
# ---------------------------------------------------------------------------


def test_every_stateless_rule_in_the_pack_is_loaded_by_the_engine():
    """Loaded, not merely written.

    1,724 rules in this corpus sit in `_quarantine/` and a rule on disk that
    the engine never loads fires on nothing, so "we shipped it" and "it can
    run" are separate claims.
    """
    loaded = {rule.get("slug") for rule in DetectionEngine()._rules}  # noqa: SLF001
    missing = [slug for slug in STATELESS_RULES if slug not in loaded]
    assert not missing, f"{missing} are not loaded by the engine"


def test_every_windowed_rule_in_the_pack_is_in_the_shipped_ruleset():
    data = json.loads((Path(__file__).resolve().parents[1] / "app/data/windowed_ruleset.json").read_text())
    rules = data["rules"] if isinstance(data, dict) else data
    ids = {rule["id"] for rule in rules}
    missing = [slug for slug in WINDOWED_RULES if slug not in ids]
    assert not missing, f"{missing} are not in windowed_ruleset.json — re-run scripts/export_windowed_ruleset.py"


# ---------------------------------------------------------------------------
# Stateless: positives fire, negatives stay silent
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("slug", STATELESS_RULES)
def test_the_committed_positive_fires_and_the_negative_does_not(slug: str):
    """Both directions, through the real engine, on the committed fixtures."""
    _spec(slug)  # refuses if the engine never loaded it
    engine = DetectionEngine()

    positive = _fixture("positive", slug)
    negative = _fixture("negative", slug)

    assert slug in _fired(engine, positive), f"{slug} did not fire on its own positive fixture"
    assert slug not in _fired(engine, negative), f"{slug} fired on its negative fixture"


@pytest.mark.parametrize("slug", STATELESS_RULES)
def test_the_negative_differs_from_the_positive_only_in_the_clause_the_rule_is_about(slug: str):
    """A negative that flips an unrelated field measures nothing.

    The generator's default inverts by prefixing `not-` to a value, so a rule
    passes by failing to match a string no source emits. These pairs must
    differ in exactly the field the rule's own claim rests on.
    """
    rule = _spec(slug)
    positive = _fixture("positive", slug)
    negative = _fixture("negative", slug)

    differing = {k for k in set(positive) | set(negative) if positive.get(k) != negative.get(k)}
    assert differing, f"{slug}: its positive and negative are identical"
    # One field, or at most the handful a single real-world difference moves
    # (the command line and nothing else; the novelty boolean and nothing
    # else). More than two means the pair differs in ways the rule does not
    # claim, and a pass could come from any of them.
    assert len(differing) <= 2, f"{slug}: positive and negative differ in {sorted(differing)}, so a pass is not attributable"

    matched_fields = set()
    for key in rule.get("match_when", {}):
        for suffix in ("_contains_any", "_contains", "_in", "_gte", "_lte", "_has_any", "_not_in"):
            if key.endswith(suffix):
                matched_fields.add(key[: -len(suffix)])
                break
        else:
            matched_fields.add(key)
    assert differing & matched_fields, (
        f"{slug}: the pair differs in {sorted(differing)}, none of which the rule matches on "
        f"({sorted(matched_fields)}) — so the negative proves nothing about this rule"
    )


# ---------------------------------------------------------------------------
# Stateless: the specific claims, on events a real estate produces
# ---------------------------------------------------------------------------


def test_a_familiar_address_does_not_raise_the_provider_key_rule():
    """The novelty is the signal, not the key action.

    Every administrator mints keys. Firing on the action would make this rule
    the noisiest thing in the deployment inside a week.
    """
    engine = DetectionEngine()
    familiar = {
        "source": "llm_usage",
        "event_type": "openai.api_key.created",
        "actor": "ada@example.com",
        "src_ip": "198.51.100.4",
        "source_ip_seen_before": True,
    }
    assert "ai-provider-key-from-new-source" not in _fired(engine, familiar)


def test_an_unconfigured_allowlist_leaves_the_mcp_rule_silent():
    """No key at all, not `False`.

    `allowlist_fields` contributes nothing when a tenant has configured no
    allowlist, which is what stops `not_in_allowlist` being true for every
    event on every deployment — the negation-flips-on-absence failure the
    Sigma import already recorded once.
    """
    engine = DetectionEngine()
    no_allowlist = {"source": "ai_gateway", "agent_id": "agent-7f2", "server_name": "community-scraper-mcp", "outcome": "success"}
    assert "ai-mcp-server-unvetted" not in _fired(engine, no_allowlist)


@pytest.mark.parametrize(
    "cmdline",
    [
        "claude --dangerously-skip-permissions -p 'refactor'",
        "codex --full-auto",
        "aider --yes-always main.py",
        "goose --no-confirm",
    ],
)
def test_each_no_prompt_flag_raises_the_coding_agent_rule(cmdline: str):
    engine = DetectionEngine()
    name = cmdline.split()[0]
    fields = {"source": "fleetdm", "event_type": "osquery_query_row", "hostname": "h", "name": name, "cmdline": cmdline}
    assert "ai-coding-agent-prompts-disabled" in _fired(engine, fields), cmdline


def test_an_ordinary_binary_with_a_scary_flag_is_not_a_coding_agent():
    """Both clauses, not either.

    A deployment script invoked with `--auto-approve` is Terraform, not an
    unattended agent, and a rule matching on the flag alone would call it one.
    """
    engine = DetectionEngine()
    fields = {
        "source": "fleetdm",
        "event_type": "osquery_query_row",
        "hostname": "h",
        "name": "terraform",
        "cmdline": "terraform apply --auto-approve",
    }
    assert "ai-coding-agent-prompts-disabled" not in _fired(engine, fields)


# ---------------------------------------------------------------------------
# Windowed: fires at the threshold, not before
# ---------------------------------------------------------------------------


class _FakeRedis:
    """In-memory stand-in for the sorted-set window and the fired marker.

    Storage, not logic: the windowed engine owns the counting, so driving it
    against this exercises the real thresholds.
    """

    def __init__(self) -> None:
        self.zsets: dict[str, dict[str, float]] = {}
        self.strings: dict[str, str] = {}

    async def zadd(self, key: str, mapping: dict[str, float]) -> None:
        self.zsets.setdefault(key, {}).update(mapping)

    async def zremrangebyscore(self, key: str, min_s: float, max_s: float) -> None:
        z = self.zsets.get(key, {})
        for member in [m for m, score in list(z.items()) if min_s <= score <= max_s]:
            del z[member]

    async def expire(self, key: str, ttl: int) -> None:
        return None

    async def zcard(self, key: str) -> int:
        return len(self.zsets.get(key, {}))

    async def set(self, key: str, value: str, nx: bool = False, ex: int | None = None):
        if nx and key in self.strings:
            return None
        self.strings[key] = value
        return True


async def _drive(fields_factory, count: int) -> set[str]:
    engine = WindowedDetectionEngine(_FakeRedis())
    fired: set[str] = set()
    for i in range(count):
        for hit in await engine.evaluate(event(fields_factory(i))):
            fired.add(hit.rule_id)
    return fired


def _guardrail(i: int) -> dict[str, Any]:
    return {
        "source": "ai_gateway",
        "agent_id": "agent-7f2",
        "finding_type": ("prompt_injection", "sensitive_data_egress", "tool_escalation")[i % 3],
        "tool_name": "search",
        "outcome": "blocked",
    }


def _spend(i: int) -> dict[str, Any]:
    return {"source": "ai_gateway", "agent_id": "agent-7f2", "tool_name": "model:gpt-4o", "prompt_tokens": 60000, "outcome": "success"}


def _oauth(i: int) -> dict[str, Any]:
    return {
        "source": "llm_usage",
        "event_type": "google_workspace_oauth.activity",
        "application": "Meeting Notetaker AI",
        "actor": "ada@example.com",
        "oauth_app_not_in_allowlist": True,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("slug", "factory", "threshold"),
    [
        ("wd-ai-guardrail-violation-rise", _guardrail, 5),
        ("wd-ai-token-spend-burst", _spend, 20),
        ("wd-ai-oauth-app-bulk-access", _oauth, 500),
    ],
)
async def test_a_windowed_rule_fires_at_its_threshold_and_not_below(slug: str, factory, threshold: int):
    """Both sides of the threshold.

    A floor-only assertion passes against a rule that fires on the first
    event, which is the noisy failure a threshold exists to prevent.
    """
    assert slug not in await _drive(factory, threshold - 1), f"{slug} fired below its threshold"
    assert slug in await _drive(factory, threshold), f"{slug} did not fire at its threshold"


@pytest.mark.asyncio
async def test_token_spend_counts_large_calls_rather_than_every_call():
    """Twenty small calls are a chatty agent, not an expensive one.

    The windowed engine counts events and does not sum a field, so the rule
    counts calls *above* a size. Without the floor a busy agent making
    thousands of tiny calls would page somebody about cost.
    """

    def small(_i: int) -> dict[str, Any]:
        return {"source": "ai_gateway", "agent_id": "agent-7f2", "tool_name": "model:gpt-4o-mini", "prompt_tokens": 400}

    assert "wd-ai-token-spend-burst" not in await _drive(small, 40)


@pytest.mark.asyncio
async def test_an_approved_oauth_application_reading_at_volume_is_silent():
    """The allowlist is the whole control.

    An approved note-taker reading a calendar continuously is its job. Without
    the clause this rule would page on the most-used integration in the
    tenant.
    """

    def approved(_i: int) -> dict[str, Any]:
        return {
            "source": "llm_usage",
            "event_type": "google_workspace_oauth.activity",
            "application": "Approved Notetaker",
            "oauth_app_not_in_allowlist": False,
        }

    assert "wd-ai-oauth-app-bulk-access" not in await _drive(approved, 600)
