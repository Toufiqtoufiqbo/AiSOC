#!/usr/bin/env python3
"""AI provider coverage, and the claim it must not accidentally make.

Depth plan 6.3.

The claim this gate protects
----------------------------
**No hosted provider has ever been exercised from this repository.** Every
endpoint in `llm_usage` is verified against the vendor's published reference
and every fixture is built from the documented response shape; none is a
recording from a live tenant. That is a real limit and it has to stay stated,
per provider, in the words "not measured" — because a reader who sees `0.000`
concludes the provider was graded and failed, and a reader who sees nothing
concludes it was verified.

So the `HONESTY` rule below is not documentation hygiene. It is the one rule
here that keeps a true statement from quietly becoming a false one.

The other rules
---------------
`PROVIDERS` requires each provider depth 6.3 names to exist and to be reachable
from the schema the console renders, because a provider in the enum and absent
from the select is one no operator can choose.

`ENDPOINTS` pins each provider to the host its vendor publishes. A typo in a
hostname is a connector that silently returns nothing — the failure shape this
repository has shipped more than once — and the only cheap defence is that the
host a reviewer reads in the docs is the host the code dials.

`FILTERS` requires the three streams that carry far more than AI to filter
before emitting. The Microsoft activity feed is every `Audit.General` record
in the tenant and the Entra audit is every directory change; a connector
without a filter pulls an entire tenant's audit trail into the lake under an
AI connector's name.

`STREAMS` requires every provider to declare whether it is control plane,
usage or an OAuth grant, in both directions. The three mean different things
to a detection and a provider with no stream is one the rule pack cannot
reason about.

Usage:
    python3 scripts/check_ai_provider_coverage.py
    python3 scripts/check_ai_provider_coverage.py --self-test
"""

from __future__ import annotations

import argparse
import ast
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CONNECTOR_PATH = Path("services/connectors/app/connectors/llm_usage.py")
DOC_PATH = Path("apps/docs/docs/connectors/llm_usage.md")
TEST_PATH = Path("services/connectors/tests/connectors/test_llm_usage_providers.py")

READ_PATHS = (CONNECTOR_PATH, DOC_PATH, TEST_PATH)

#: Every provider depth 6.3 names, with the host its vendor publishes. The
#: host is pinned rather than the full path: paths move between API versions,
#: hosts do not, and a wrong host is the failure that returns nothing.
REQUIRED_PROVIDERS: dict[str, str] = {
    "openai": "api.openai.com",
    "anthropic": "api.anthropic.com",
    "google_workspace_gemini": "admin.googleapis.com",
    "google_workspace_oauth": "admin.googleapis.com",
    "m365_copilot": "manage.office.com",
    "entra_consent": "graph.microsoft.com",
    "github_copilot": "api.github.com",
}

#: Streams that carry far more than AI and must be filtered before emitting.
MUST_FILTER = ("m365_copilot", "entra_consent")

#: The exact phrase. Not "unknown", not "n/a", not a dash: a reader has to be
#: told that nobody ran it, which is different from "it was run and failed".
NOT_MEASURED = "not measured"


def _read(root: Path, rel: Path) -> str:
    path = root / rel
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _module(source: str) -> ast.Module | None:
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


def _collection(tree: ast.Module, name: str) -> list[str]:
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else ([node.target] if isinstance(node, ast.AnnAssign) else [])
        if not any(isinstance(t, ast.Name) and t.id == name for t in targets):
            continue
        if node.value is None:
            return []
        return [n.value for n in ast.walk(node.value) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    return []


def _function_source(tree: ast.Module, name: str) -> str:
    """A function's code without its docstring.

    The docstring is dropped because a rule that matches a function's own
    prose passes on a body that stopped doing what the prose describes.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef) and node.name == name:
            body = list(node.body)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                body = body[1:]
            return "\n".join(ast.unparse(stmt) for stmt in body)
    return ""


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def _check_providers(root: Path) -> list[str]:
    source = _read(root, CONNECTOR_PATH)
    tree = _module(source) if source else None
    if tree is None:
        return [f"PROVIDERS: {CONNECTOR_PATH} is absent or does not parse."]
    declared = set(_collection(tree, "PROVIDERS"))
    failures = [
        f"PROVIDERS: {provider!r} is named by depth 6.3 and is not in PROVIDERS, so no instance can pull it."
        for provider in REQUIRED_PROVIDERS
        if provider not in declared
    ]
    # And the direction nobody checks: a provider in the vocabulary that the
    # console's select never offers is one no operator can choose.
    schema = _function_source(tree, "schema")
    for provider in sorted(declared):
        # Both quote styles: `ast.unparse` renders string literals with single
        # quotes whatever the source used, so a double-quoted-only check finds
        # nothing and reports every provider missing — which is how this rule
        # first failed against a tree that was correct.
        if f'"{provider}"' not in schema and f"'{provider}'" not in schema:
            failures.append(f"PROVIDERS: {provider!r} is in PROVIDERS and is not an option in the schema's select, so nobody can pick it.")
    return failures


def _check_endpoints(root: Path) -> list[str]:
    source = _read(root, CONNECTOR_PATH)
    if not source:
        return []
    failures: list[str] = []
    for provider, host in REQUIRED_PROVIDERS.items():
        if host not in source:
            failures.append(
                f"ENDPOINTS: {provider!r} should dial {host} and that host appears nowhere in the connector. "
                f"A wrong host returns nothing and reads as a quiet estate."
            )
    doc = _read(root, DOC_PATH)
    for provider, host in REQUIRED_PROVIDERS.items():
        if host not in doc:
            failures.append(f"ENDPOINTS: {DOC_PATH} does not publish {host} for {provider!r}; a reviewer cannot check what the code dials.")
    return failures


def _check_filters(root: Path) -> list[str]:
    source = _read(root, CONNECTOR_PATH)
    tree = _module(source) if source else None
    if tree is None:
        return []
    include = _function_source(tree, "_include")
    if not include:
        return [
            "FILTERS: the connector has no _include. The Microsoft activity feed is every Audit.General record "
            "in the tenant and the Entra audit is every directory change; without a filter this pulls an entire "
            "tenant's audit trail into the lake under an AI connector's name."
        ]
    return [
        f"FILTERS: _include does not discriminate for {provider!r}, so every record on that stream is ingested as AI activity."
        for provider in MUST_FILTER
        if provider not in include
    ]


def _check_streams(root: Path) -> list[str]:
    source = _read(root, CONNECTOR_PATH)
    tree = _module(source) if source else None
    if tree is None:
        return []
    declared = set(_collection(tree, "PROVIDERS"))
    streams: set[str] = set()
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else ([node.target] if isinstance(node, ast.AnnAssign) else [])
        if not any(isinstance(t, ast.Name) and t.id == "PROVIDER_STREAM" for t in targets):
            continue
        if isinstance(node.value, ast.Dict):
            streams = {k.value for k in node.value.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    if not streams:
        return ["STREAMS: PROVIDER_STREAM is absent. A usage record and a control-plane record mean different things to a detection."]
    failures = [f"STREAMS: {p!r} declares no stream." for p in sorted(declared - streams)]
    failures += [f"STREAMS: PROVIDER_STREAM names {p!r}, which is not a provider." for p in sorted(streams - declared)]
    return failures


def _check_honesty(root: Path) -> list[str]:
    """Per provider, in words, that nobody has run it against a live tenant."""
    doc = _read(root, DOC_PATH)
    if not doc:
        return [f"HONESTY: {DOC_PATH} is absent, so the limit is stated nowhere a reader will see it."]
    failures: list[str] = []
    lowered = doc.lower()
    if NOT_MEASURED not in lowered:
        failures.append(
            f"HONESTY: {DOC_PATH} never says {NOT_MEASURED!r}. No provider here has been exercised against a "
            f"funded account, and a page that omits that reads as verification."
        )
    # Per provider **on its own row**, not once in a footnote. A single
    # caveat covering seven providers lets one of them quietly become
    # "verified" later, and the prose around the table would still carry the
    # phrase — which is exactly what the first cut of this rule accepted.
    for provider in REQUIRED_PROVIDERS:
        if provider not in doc:
            failures.append(f"HONESTY: {DOC_PATH} does not name {provider!r}, so its verification state is unstated.")
            continue
        rows = [line for line in doc.splitlines() if line.lstrip().startswith("|") and provider in line]
        if not any(NOT_MEASURED in row.lower() for row in rows):
            failures.append(
                f"HONESTY: no table row for {provider!r} says {NOT_MEASURED!r}. Nobody has run it against a "
                f"live tenant, and a row that stops saying so reads as verification."
            )
    for forbidden in ("0.000", "0.0%"):
        if forbidden in doc:
            failures.append(
                f"HONESTY: {DOC_PATH} publishes {forbidden!r}. A zero reads as graded-and-failed; the honest "
                f"value for something nobody ran is {NOT_MEASURED!r}."
            )
    # The claim must not be contradicted either — but a *denial* is not a
    # claim, and the first cut of this rule flagged the page's own caution
    # title ("No provider here has been exercised against a funded account")
    # as an overclaim. Checked per line, with any negation exempting the line.
    negations = (" no ", "no ", " not ", "not ", "never", "none ")
    for line in doc.splitlines():
        low = line.lower()
        if any(negation in low for negation in negations):
            continue
        for overclaim in ("verified against a live tenant", "tested against a live account", "exercised against a funded"):
            if overclaim in low:
                failures.append(f"HONESTY: {DOC_PATH} claims {overclaim!r}, which is not true of any provider here.")
    return failures


def _check_tests(root: Path) -> list[str]:
    """A suite that asserts the request, not only the parsed result."""
    source = _read(root, TEST_PATH)
    if not source:
        return [f"TESTS: {TEST_PATH} is absent; no provider is driven through its real HTTP path."]
    failures: list[str] = []
    if "calls.last.request" not in source:
        failures.append(
            f"TESTS: {TEST_PATH} never reads a recorded request back. Across the five closed-finding readers, "
            f"three had fields null because the *query* projected them away, and a mock that answers whatever "
            f"it is asked hides that forever."
        )
    for provider in REQUIRED_PROVIDERS:
        if provider not in source:
            failures.append(f"TESTS: {TEST_PATH} does not exercise {provider!r}.")
    return failures


RULES = (
    ("PROVIDERS", _check_providers),
    ("ENDPOINTS", _check_endpoints),
    ("FILTERS", _check_filters),
    ("STREAMS", _check_streams),
    ("HONESTY", _check_honesty),
    ("TESTS", _check_tests),
)


def evaluate(root: Path) -> list[str]:
    failures: list[str] = []
    for _, rule in RULES:
        failures.extend(rule(root))
    return failures


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

INJECTIONS: tuple[tuple[str, Path, str, str], ...] = (
    ("PROVIDERS", CONNECTOR_PATH, '    "entra_consent",\n    "github_copilot",', '    "github_copilot",'),
    ("ENDPOINTS", CONNECTOR_PATH, "manage.office.com", "manage.offce.com"),
    (
        "FILTERS",
        CONNECTOR_PATH,
        'if self._provider == "m365_copilot":\n            return str(raw.get',
        "if False:\n            return str(raw.get",
    ),
    ("STREAMS", CONNECTOR_PATH, '    "github_copilot": "control_plane",\n}', "}"),
    # The one that matters: the limit quietly stops being stated.
    ("HONESTY", DOC_PATH, "**not measured**", "verified"),
    ("TESTS", TEST_PATH, "calls.last.request", "calls_last_request_removed"),
)


def _materialise(dest: Path) -> None:
    for rel in READ_PATHS:
        src = REPO_ROOT / rel
        if not src.is_file():
            continue
        (dest / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest / rel)


def _apply(root: Path, target: Path, old: str, new: str) -> bool:
    path = root / target
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    if old not in text:
        return False
    path.write_text(text.replace(old, new), encoding="utf-8")
    return True


def _self_test() -> int:
    print(f"{Path(__file__).name} --self-test\n")
    results: list[tuple[str, bool]] = []

    clean = Path(tempfile.mkdtemp(prefix="ai-provider-clean-"))
    try:
        _materialise(clean)
        baseline = evaluate(clean)
        results.append(("the unmodified tree passes", not baseline))
        for line in baseline:
            print(f"        baseline: {line}")
    finally:
        shutil.rmtree(clean, ignore_errors=True)

    for rule_name, target, old, new in INJECTIONS:
        tmp = Path(tempfile.mkdtemp(prefix="ai-provider-"))
        try:
            _materialise(tmp)
            if not _apply(tmp, target, old, new):
                results.append((f"{rule_name}: injection applies", False))
                continue
            caught = any(line.startswith(f"{rule_name}:") for line in evaluate(tmp))
            results.append((f"{rule_name}: catches {old[:48]!r} -> {new[:32]!r}", caught))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    empty = Path(tempfile.mkdtemp(prefix="ai-provider-empty-"))
    try:
        results.append(("refuses an empty tree rather than reporting it clean", bool(evaluate(empty))))
    finally:
        shutil.rmtree(empty, ignore_errors=True)

    ok = True
    for description, passed in results:
        ok &= passed
        print(f"  {'PASS' if passed else 'FAIL'}  {description}")
    print()
    if not ok:
        print(f"{Path(__file__).name}: self-test FAILED")
        return 1
    print(f"{Path(__file__).name}: self-test OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true", help="inject one violation per rule and require each to be caught")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()

    if not (REPO_ROOT / "services" / "connectors").is_dir():
        print("check_ai_provider_coverage: no connectors service — nothing to render a verdict about.", file=sys.stderr)
        return 2

    failures = evaluate(REPO_ROOT)
    if failures:
        print("AI provider coverage (depth plan 6.3) is incomplete:\n", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        print(f"\n{len(failures)} problem(s) across {len(RULES)} rule(s).", file=sys.stderr)
        return 1

    print(
        f"OK — {len(REQUIRED_PROVIDERS)} AI providers, each dialling its published host, each declaring its "
        f"stream, the two firehose streams filtered, and every one recorded as '{NOT_MEASURED}' against a live tenant."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
