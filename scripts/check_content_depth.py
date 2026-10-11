#!/usr/bin/env python3
"""Executable cloud, identity, SaaS and code conditions, counted one way.

Depth plan 3.6 asks to raise this figure *"counted by a new `make stats`
line held by a `--check` gate"*. The gate exists because the figure was
re-derivable two ways and the two disagreed: the plan captured **461** and
the Phase 0 re-derivation measured **395**, from the same tree on the same
day, because nothing pinned which `log_source` values belong to which
group. A number two honest people compute differently is not a measurement.

So the grouping lives here, in code, and every surface that states the
figure reads it from this one place.

What "in scope" means
---------------------
An entry counts when it is:

* a **detection** in `marketplace/index.json` — the index is the one
  artefact that knows about native specs, Sigma imports and windowed rules
  at once;
* **executable** — replayed and observed to fire on a well-formed event of
  its log source. Not a claim the rule detects an attack, and the
  distinction is kept legible everywhere this number is printed;
* carrying a `log_source` in one of the four groups below.

The recovery that moved this number, and why it is not inflation
-----------------------------------------------------------------
1,770 of 2,535 executable rules indexed with **no log source at all**,
because imported Sigma rules spell it `logsource:` and the indexer read
only AiSOC's `log_source:`. 1,687 of those are Windows rules that no
cloud/identity figure wants — but 83 were in scope (39 AWS, 28 Azure, 16
Okta). The indexer now reads both spellings, which raised this count
without a single new rule being written.

That direction is worth naming. The undercount's real cost was not a small
headline: it invited authoring 83 rules the repository already had.

Why a ratchet and a target are different numbers
------------------------------------------------
`FLOOR` is what the tree measures today and may only rise. `TARGET` is the
plan's 800. The gate fails when the figure drops below `FLOOR`, and reports
the distance to `TARGET` as an open gap rather than pretending the target is
met. Raising `FLOOR` to match a number nobody has reached would be the
weaken-the-gate move this directory exists to refuse; lowering it to make a
scan pass would be the other one.

Usage:
    python3 scripts/check_content_depth.py            # report
    python3 scripts/check_content_depth.py --check    # fail on regression
    python3 scripts/check_content_depth.py --json     # machine-readable
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

ROOT = repo_root()
INDEX = ROOT / "marketplace" / "index.json"

#: The grouping, fixed in code. Depth plan 3.6's scope is "cloud, identity,
#: SaaS and code"; these are the `log_source` values that are each of those.
#:
#: Endpoint sources (`windows`, `linux`, `macos`, `edr`, `osquery`, `mdm`,
#: `mobile`, `android`) and network sources (`proxy`, `waf`, `ndr`,
#: `firewall`, `dns`, `vpn`) are deliberately absent: they are real
#: coverage and they are not what this item measures. A value that is in
#: neither this table nor `OUT_OF_SCOPE` fails the gate, so a new source
#: cannot silently land outside the count.
GROUPS: dict[str, frozenset[str]] = {
    "cloud": frozenset(
        {
            "aws",
            "azure",
            "gcp",
            "kubernetes",
            "docker",
            "cloud",
            "multi-cloud",
            "cloudflare",
            "api-gateway",
            "digitalocean",
            "oci",
            "terraform",
            "container-registry",
        }
    ),
    "identity": frozenset({"identity", "okta", "active-directory", "auth0", "duo", "ping", "keycloak", "vault"}),
    "saas": frozenset(
        {
            "google-workspace",
            "m365",
            "slack",
            "email",
            "salesforce",
            "snowflake",
            "box",
            "dropbox",
            "1password",
            "atlassian",
            "confluence",
            "jira",
            "servicenow",
            "notion",
            "workday",
            "zoom",
        }
    ),
    "code": frozenset({"github", "gitlab", "ci", "build", "pypi"}),
}

#: Minimums are stated per *vendor*, and a vendor can appear in the corpus
#: under more than one product name. Atlassian is the case that matters:
#: `confluence` and `jira` are Atlassian products and were being counted
#: against neither the Atlassian minimum nor anything else, which is the
#: shape the gate's unclassified check exists to surface.
SOURCE_ALIASES: dict[str, tuple[str, ...]] = {
    "atlassian": ("atlassian", "confluence", "jira"),
}


def _count_for(by_source: dict[str, int], source: str) -> int:
    """Rules for a vendor, across every product name it ships under."""
    return sum(by_source.get(name, 0) for name in SOURCE_ALIASES.get(source, (source,)))


#: Sources that exist in the corpus and are deliberately not counted here.
#: Listed rather than ignored, so "not in scope" is a decision with a name
#: on it rather than a value that fell through a gap.
OUT_OF_SCOPE: frozenset[str] = frozenset(
    {
        # endpoint
        "windows",
        "linux",
        "macos",
        "edr",
        "osquery",
        "mdm",
        "mobile",
        "android",
        "endpoint",
        "process_creation",
        "ios",
        # network
        "proxy",
        "waf",
        "ndr",
        "firewall",
        "dns",
        "vpn",
        "network",
        "radius",
        "switch",
        # application and AI estate — their own items (depth plan 6.x)
        "application",
        "openai",
        "ai_guardrail",
        "ai_runtime",
        "ai_gateway",
        "anthropic",
        "llm",
        "database",
        "webserver",
    }
)

#: Per-`log_source` minimums the plan states. The gate reports every one of
#: these and refuses a regression against `MEASURED` below.
MINIMUMS: dict[str, int] = {
    "aws": 120,
    "gcp": 120,
    "azure": 150,
    "kubernetes": 60,
    "okta": 60,
}

#: GitHub and GitLab are given a joint minimum by the plan rather than one
#: each, because the coverage it asks for — token abuse, workflow tampering,
#: secret exposure, session hijack — is the same on both.
CODE_SOURCES: tuple[str, ...] = ("github", "gitlab")
CODE_MINIMUM = 40

#: *"every SaaS source with a connector … has at least 20"*. The qualifier
#: is load-bearing and is enforced rather than assumed: `zoom` is named by
#: the plan and **no Zoom connector exists** in
#: `services/connectors/app/connectors/`, so rules for it would match on
#: fields nothing emits. It is excluded here with that reason, and
#: `test_content_depth.py` re-derives the connector list from the tree so
#: this cannot silently become wrong when a Zoom connector lands.
SAAS_SOURCES: tuple[str, ...] = (
    "google-workspace",
    "m365",
    "slack",
    "salesforce",
    "snowflake",
    "box",
    "dropbox",
    "1password",
    "atlassian",
    "servicenow",
)
SAAS_MINIMUM = 20

#: The plan's goal for the total.
TARGET = 800

#: What the tree measures today. A ratchet: it may rise, never fall. See the
#: module docstring for why this is not `TARGET`.
FLOOR = 521


def _executable_detections() -> list[dict]:
    if not INDEX.is_file():
        raise SystemExit(f"content-depth: {INDEX} is missing — run scripts/build_marketplace.py")
    data = json.loads(INDEX.read_text(encoding="utf-8"))
    items = data.get("items") if isinstance(data, dict) else data
    if not isinstance(items, list) or not items:
        raise SystemExit("content-depth: the marketplace index holds no items — refusing a vacuous pass")
    return [i for i in items if isinstance(i, dict) and i.get("type") == "detection" and i.get("executable")]


def measure() -> dict:
    """Group and count, and name any source that belongs to neither table."""
    rules = _executable_detections()
    if not rules:
        raise SystemExit("content-depth: no executable detections in the index — refusing a vacuous pass")

    by_source: dict[str, int] = {}
    for rule in rules:
        source = rule.get("log_source") or "(none)"
        by_source[str(source)] = by_source.get(str(source), 0) + 1

    known = set().union(*GROUPS.values()) | OUT_OF_SCOPE
    unclassified = sorted(s for s in by_source if s not in known)

    by_group = {g: sum(by_source.get(s, 0) for s in members) for g, members in GROUPS.items()}
    return {
        "total_executable": len(rules),
        "in_scope": sum(by_group.values()),
        "by_group": by_group,
        "by_source": by_source,
        "unclassified": unclassified,
        "target": TARGET,
        "floor": FLOOR,
    }


def _shortfalls(by_source: dict[str, int]) -> list[tuple[str, int, int]]:
    """(source, have, need) for every minimum not yet met."""
    out: list[tuple[str, int, int]] = []
    for source, need in sorted(MINIMUMS.items()):
        have = _count_for(by_source, source)
        if have < need:
            out.append((source, have, need))
    code = sum(_count_for(by_source, s) for s in CODE_SOURCES)
    if code < CODE_MINIMUM:
        out.append(("github+gitlab", code, CODE_MINIMUM))
    for source in SAAS_SOURCES:
        have = _count_for(by_source, source)
        if have < SAAS_MINIMUM:
            out.append((f"saas:{source}", have, SAAS_MINIMUM))
    return out


def _render(stats: dict) -> str:
    lines = [
        f"content depth: {stats['in_scope']} executable cloud, identity, SaaS and code conditions "
        f"(of {stats['total_executable']} executable overall)",
    ]
    for group, count in sorted(stats["by_group"].items()):
        lines.append(f"  {group:10} {count}")
    gap = stats["target"] - stats["in_scope"]
    if gap > 0:
        lines.append(f"  gap to the depth plan 3.6 target of {stats['target']}: {gap}")
    else:
        lines.append(f"  target of {stats['target']} met")
    short = _shortfalls(stats["by_source"])
    if short:
        lines.append(f"  per-source minimums not yet met ({len(short)}):")
        for source, have, need in short:
            lines.append(f"    {source:24} {have:4} / {need}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="fail if the count regressed below the ratchet")
    parser.add_argument("--json", action="store_true", help="emit the measurement as JSON")
    args = parser.parse_args()

    stats = measure()
    if args.json:
        print(json.dumps(stats, indent=2, sort_keys=True))
        return 0

    print(_render(stats))

    if stats["unclassified"]:
        print(
            "\nFAIL: these log_source values are in neither GROUPS nor OUT_OF_SCOPE, "
            "so they are silently uncounted: " + ", ".join(stats["unclassified"])
        )
        return 1

    if args.check:
        if stats["in_scope"] < FLOOR:
            print(
                f"\nFAIL: in-scope conditions fell to {stats['in_scope']}, below the ratchet of {FLOOR}. "
                "Content was removed or a log_source stopped resolving."
            )
            return 1
        if stats["in_scope"] > FLOOR:
            # Advisory, not a failure — the house convention that
            # `check_detection_fields.py` already follows. Failing here
            # would force every content PR to edit this file, which trains
            # people to treat the number as paperwork rather than a gate.
            print(
                f"\nOK — {stats['in_scope']} in scope. The ratchet can be tightened: "
                f"raise FLOOR to {stats['in_scope']} in scripts/check_content_depth.py."
            )
            return 0
        print(f"\nOK — {stats['in_scope']} in scope, at the ratchet of {FLOOR}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
