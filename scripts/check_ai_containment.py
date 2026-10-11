#!/usr/bin/env python3
"""AI-estate containment: four verbs, every registry, off by default.

Depth plan 6.6.

Why a separate gate when `check_action_contract.py` already exists
------------------------------------------------------------------
That gate walks every direction between an executor and the registries that
make it reachable, and it covers these four as it covers the other eighty-six.
This one asserts the three properties that are specific to *reaching a
customer's model provider*, none of which a generic contract check can see:

**OFF** — all four refuse unless ``AISOC_AI_CONTAINMENT_ENABLED`` is set, and
the refusal is a ``FAILED`` result naming the variable rather than a simulated
success. The direction matters more than the flag: ``NotifySlackExecutor``
reported ``message_sent: true`` on a send that never happened, and the same
shape behind an irreversible verb is an operator who reads "contained" and
stops looking.

**REVERSE** — the one reversible verb names a reverse that is a first-class
verb with its own executor, contract and ``ActionType``. ``unisolate_host``,
the rollback for the most disruptive action in the product, once declared a
platform reverse and resolved to nothing.

**IRREVERSIBLE** — the two verbs the vendor itself cannot undo are declared
``IRREVERSIBLE`` and ``MANDATORY_HUMAN``, and must declare no reverse. A
contract that softened either would let an autonomy tier delete a customer's
production key on a confidence score.

Plus **PLAYBOOK**: the kill-switch exists, requires approval *before* anything
irreversible, and ships disabled — arming a maximally-disruptive playbook on
upgrade is the same mistake as shipping the verbs live, one level up.

Parsed with ``ast`` and JSON rather than imported, so it runs on a bare
interpreter in CI before any service venv exists.

Usage:
    python3 scripts/check_ai_containment.py
    python3 scripts/check_ai_containment.py --self-test
"""

from __future__ import annotations

import argparse
import ast
import json
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

EXECUTORS_PATH = Path("services/actions/app/executors/ai_estate.py")
CONTRACTS_PATH = Path("services/actions/app/live_actions/capability_contracts.py")
CAPABILITIES_PATH = Path("services/actions/app/live_actions/capabilities.py")
ACTION_MODEL_PATH = Path("services/actions/app/models/action.py")
CONNECTOR_BASE_PATH = Path("services/connectors/app/connectors/base.py")
BUILTINS_PATH = Path("services/actions/app/live_actions/builtins.py")
VERIFICATION_PATH = Path("services/actions/app/services/verification.py")
PLAYBOOK_PATH = Path("playbooks/packs/v1/ai-estate/ai-agent-kill-switch.playbook.json")
ADR_PATH = Path("docs/decisions/0011-ai-containment-off-by-default.md")

READ_PATHS = (
    EXECUTORS_PATH,
    CONTRACTS_PATH,
    CAPABILITIES_PATH,
    ACTION_MODEL_PATH,
    CONNECTOR_BASE_PATH,
    BUILTINS_PATH,
    VERIFICATION_PATH,
    PLAYBOOK_PATH,
    ADR_PATH,
)

#: The four verbs. Four rather than three because the gateway block declares a
#: platform reverse, and a reverse that is not a dispatchable verb is a
#: rollback path that resolves to nothing.
AI_VERBS = (
    "revoke_provider_key",
    "revoke_oauth_grant",
    "block_ai_key_at_gateway",
    "unblock_ai_key_at_gateway",
)

#: The two the vendor itself cannot undo.
IRREVERSIBLE_VERBS = ("revoke_provider_key", "revoke_oauth_grant")

ENABLE_FLAG = "AISOC_AI_CONTAINMENT_ENABLED"

#: Every registry a verb has to appear in before governed dispatch can reach
#: it. A verb complete in four of five answers `executor_not_found`, which
#: reads as a missing integration rather than a missing enum member.
REGISTRIES: tuple[tuple[Path, str], ...] = (
    (CONNECTOR_BASE_PATH, "the connectors Capability enum"),
    (CAPABILITIES_PATH, "KNOWN_CAPABILITIES"),
    (CONTRACTS_PATH, "CAPABILITY_CONTRACTS"),
    (ACTION_MODEL_PATH, "the ActionType enum"),
    (BUILTINS_PATH, "the live-action adapters"),
    (VERIFICATION_PATH, "the verification probe table"),
)


def _read(root: Path, rel: Path) -> str:
    path = root / rel
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _module(source: str) -> ast.Module | None:
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


def _function_source(tree: ast.Module, name: str) -> str:
    """A function's body without its docstring.

    The docstring is dropped because a rule matching a function's own prose
    passes on a body that stopped doing what the prose describes.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef) and node.name == name:
            body = list(node.body)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                body = body[1:]
            return "\n".join(ast.unparse(stmt) for stmt in body)
    return ""


def _contract_entries(source: str) -> dict[str, str]:
    """``{verb: unparsed CapabilityContract(...) call}`` for the AI verbs."""
    tree = _module(source)
    if tree is None:
        return {}
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values, strict=False):
            if isinstance(key, ast.Constant) and key.value in AI_VERBS:
                out[str(key.value)] = ast.unparse(value)
    return out


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def _check_registries(root: Path) -> list[str]:
    failures: list[str] = []
    for path, label in REGISTRIES:
        source = _read(root, path)
        if not source:
            failures.append(f"REGISTRIES: {path} is absent, so {label} cannot be checked.")
            continue
        for verb in AI_VERBS:
            if verb not in source:
                failures.append(
                    f"REGISTRIES: {verb!r} is absent from {label} ({path}). A verb complete in every "
                    f"registry but one answers executor_not_found at dispatch, which reads as a missing "
                    f"integration rather than a missing enum member."
                )
    return failures


def _check_off(root: Path) -> list[str]:
    """Off by default, and the refusal is a failure rather than a success."""
    source = _read(root, EXECUTORS_PATH)
    if not source:
        return [f"OFF: {EXECUTORS_PATH} is absent; nothing implements these verbs."]
    tree = _module(source)
    if tree is None:
        return [f"OFF: {EXECUTORS_PATH} does not parse."]

    failures: list[str] = []

    # The module must *define* the flag, and the gate and the refusal must
    # both reference it. Checking for the literal string inside each function
    # would fail on the correct code, which names a module constant — the
    # first cut of this rule did exactly that.
    if f'ENABLE_FLAG = "{ENABLE_FLAG}"' not in source:
        failures.append(f"OFF: {EXECUTORS_PATH} does not define ENABLE_FLAG = {ENABLE_FLAG!r}.")

    gate = _function_source(tree, "containment_enabled")
    if not gate:
        return [
            f"OFF: {EXECUTORS_PATH} has no containment_enabled. These are the first verbs that reach a "
            f"customer's model-provider account rather than a security product they connected for the "
            f"purpose, and a deployment that upgrades would get them live without deciding to."
        ]
    if "ENABLE_FLAG" not in gate and ENABLE_FLAG not in gate:
        failures.append(f"OFF: containment_enabled does not read {ENABLE_FLAG}.")

    refusal = _function_source(tree, "_disabled")
    if not refusal:
        failures.append("OFF: there is no _disabled refusal, so a disabled arm has no honest result to return.")
    else:
        if "FAILED" not in refusal:
            failures.append(
                "OFF: the disabled result is not FAILED. A containment that reports success while touching "
                "nothing is worse than one that refuses — NotifySlackExecutor reported message_sent: true "
                "on a send that never happened."
            )
        if "ENABLE_FLAG" not in refusal and ENABLE_FLAG not in refusal:
            failures.append(f"OFF: the refusal does not name {ENABLE_FLAG}, so an operator cannot act on it.")

    # Every executor must consult the gate. One that does not is live.
    for name in (
        "RevokeProviderKeyExecutor",
        "RevokeOAuthGrantExecutor",
        "BlockAIKeyAtGatewayExecutor",
        "UnblockAIKeyAtGatewayExecutor",
    ):
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == name:
                body = ast.unparse(node)
                if "containment_enabled" not in body:
                    failures.append(f"OFF: {name} never calls containment_enabled, so it reaches a vendor whatever the flag says.")
                break
        else:
            failures.append(f"OFF: {name} is absent from {EXECUTORS_PATH}.")
    return failures


def _check_reverse(root: Path) -> list[str]:
    """The reversible verb names a reverse that is a real, dispatchable verb."""
    entries = _contract_entries(_read(root, CONTRACTS_PATH))
    if not entries:
        return ["REVERSE: no capability contract declares any of the AI verbs."]
    failures: list[str] = []
    block = entries.get("block_ai_key_at_gateway", "")
    if "Reversal.PLATFORM" not in block:
        failures.append(
            "REVERSE: block_ai_key_at_gateway does not declare a platform reverse. It is the one "
            "containment here an approver can be told is undoable, which is what makes it the right "
            "first move when the verdict is not yet certain."
        )
    if "unblock_ai_key_at_gateway" not in block:
        failures.append("REVERSE: block_ai_key_at_gateway names no reverse capability.")
    if "unblock_ai_key_at_gateway" not in entries:
        failures.append(
            "REVERSE: the reverse has no contract of its own. A declared reverse that cannot be "
            "dispatched under governance is worse than none — the rollback path believes it has a route, "
            "which is what unisolate_host was for a release."
        )
    return failures


def _check_irreversible(root: Path) -> list[str]:
    """The two the vendor cannot undo are declared that way, and gated."""
    entries = _contract_entries(_read(root, CONTRACTS_PATH))
    if not entries:
        return []
    failures: list[str] = []
    for verb in IRREVERSIBLE_VERBS:
        entry = entries.get(verb, "")
        if not entry:
            failures.append(f"IRREVERSIBLE: {verb!r} has no contract.")
            continue
        if "ActionImpact.IRREVERSIBLE" not in entry:
            failures.append(
                f"IRREVERSIBLE: {verb!r} is not declared IRREVERSIBLE. Neither vendor returns the secret "
                f"and a re-granted OAuth consent is the user acting in their own browser; softening this "
                f"lets an autonomy tier take it on a confidence score."
            )
        if "ApprovalRequirement.MANDATORY_HUMAN" not in entry:
            failures.append(f"IRREVERSIBLE: {verb!r} is not MANDATORY_HUMAN, so a tier could lift the floor.")
        if "reverse_capability" in entry:
            failures.append(f"IRREVERSIBLE: {verb!r} names a reverse capability it does not have.")
    return failures


def _check_probes(root: Path) -> list[str]:
    """Every verb declares a probe and the probe table registers one."""
    entries = _contract_entries(_read(root, CONTRACTS_PATH))
    verification = _read(root, VERIFICATION_PATH)
    failures: list[str] = []
    for verb in AI_VERBS:
        entry = entries.get(verb, "")
        if entry and "has_verification_probe=True" not in entry:
            failures.append(
                f"PROBES: {verb!r} declares no verification probe. At these impact tiers the alternative "
                f"is inferring the effect from a 200, and for a key revocation that is the whole action — "
                f"the vendor accepting an instruction is not the key having stopped working."
            )
        if f"_probe_{verb}" not in verification:
            failures.append(f"PROBES: no probe named _probe_{verb} exists in {VERIFICATION_PATH}.")
    return failures


def _check_playbook(root: Path) -> list[str]:
    """The kill-switch: approval before the irreversible half, and disabled."""
    raw = _read(root, PLAYBOOK_PATH)
    if not raw:
        return [f"PLAYBOOK: {PLAYBOOK_PATH} is absent. Depth 6.6 asks for one kill-switch composing these arms."]
    try:
        playbook = json.loads(raw)
    except ValueError as exc:
        return [f"PLAYBOOK: {PLAYBOOK_PATH} is not valid JSON ({exc})."]

    failures: list[str] = []
    steps = playbook.get("steps") or []
    types = [str(step.get("type")) for step in steps if isinstance(step, dict)]

    if playbook.get("enabled") is not False:
        failures.append(
            "PLAYBOOK: the kill switch ships enabled. Arming a maximally-disruptive playbook on upgrade "
            "is the same mistake as shipping the verbs live, one level up."
        )
    if "approval" not in types:
        failures.append("PLAYBOOK: there is no approval step, so the irreversible half could run unattended.")
    else:
        approval_at = types.index("approval")
        for verb in IRREVERSIBLE_VERBS:
            if verb in types and types.index(verb) < approval_at:
                failures.append(
                    f"PLAYBOOK: {verb!r} runs before the approval step. Everything reversible has to happen "
                    f"first, so the human is asked only about what cannot be taken back."
                )
    for verb in ("block_ai_key_at_gateway", "kill_process"):
        if verb not in types:
            failures.append(f"PLAYBOOK: the kill switch does not use {verb!r}, which is one of the arms depth 6.6 names.")
    return failures


def _check_adr(root: Path) -> list[str]:
    adr = _read(root, ADR_PATH)
    if not adr:
        return [f"ADR: {ADR_PATH} is absent; the off-by-default decision and the irreversibility are recorded nowhere."]
    failures: list[str] = []
    lowered = adr.lower()
    for needle, why in (
        (ENABLE_FLAG.lower(), "the flag that gates every arm"),
        ("irreversible", "the two verbs no API of ours can undo"),
        ("unisolate_host", "the precedent for a reverse that resolved to nothing"),
    ):
        if needle not in lowered:
            failures.append(f"ADR: {ADR_PATH} does not mention {needle} — {why}.")
    return failures


RULES = (
    ("REGISTRIES", _check_registries),
    ("OFF", _check_off),
    ("REVERSE", _check_reverse),
    ("IRREVERSIBLE", _check_irreversible),
    ("PROBES", _check_probes),
    ("PLAYBOOK", _check_playbook),
    ("ADR", _check_adr),
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
    ("REGISTRIES", CAPABILITIES_PATH, '"revoke_oauth_grant",', ""),
    # The defect this gate exists for: a disabled containment that reports
    # success instead of refusing.
    (
        "OFF",
        EXECUTORS_PATH,
        "status=ActionStatus.FAILED,\n        blast_radius=blast,\n        error=(",
        "status=ActionStatus.COMPLETED,\n        blast_radius=blast,\n        error=(",
    ),
    ("REVERSE", CONTRACTS_PATH, 'reverse_capability="unblock_ai_key_at_gateway",', ""),
    (
        "IRREVERSIBLE",
        CONTRACTS_PATH,
        "impact=ActionImpact.IRREVERSIBLE,\n        approval=ApprovalRequirement.MANDATORY_HUMAN,",
        "impact=ActionImpact.HIGH,\n        approval=ApprovalRequirement.ANALYST,",
    ),
    # Renamed, not suffixed: a suffix leaves the substring in place and the
    # rule would pass on a probe that no longer exists under its own name.
    ("PROBES", VERIFICATION_PATH, "_probe_revoke_provider_key", "_probe_revoked_key_unused"),
    ("PLAYBOOK", PLAYBOOK_PATH, '"enabled": false,', '"enabled": true,'),
    ("ADR", ADR_PATH, "unisolate_host", "un-isolate-host"),
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

    clean = Path(tempfile.mkdtemp(prefix="ai-contain-clean-"))
    try:
        _materialise(clean)
        baseline = evaluate(clean)
        results.append(("the unmodified tree passes", not baseline))
        for line in baseline:
            print(f"        baseline: {line}")
    finally:
        shutil.rmtree(clean, ignore_errors=True)

    for rule_name, target, old, new in INJECTIONS:
        tmp = Path(tempfile.mkdtemp(prefix="ai-contain-"))
        try:
            _materialise(tmp)
            if not _apply(tmp, target, old, new):
                results.append((f"{rule_name}: injection applies", False))
                continue
            caught = any(line.startswith(f"{rule_name}:") for line in evaluate(tmp))
            results.append((f"{rule_name}: catches {old[:44]!r} -> {new[:28]!r}", caught))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    empty = Path(tempfile.mkdtemp(prefix="ai-contain-empty-"))
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

    if not (REPO_ROOT / "services" / "actions").is_dir():
        print("check_ai_containment: no actions service — nothing to render a verdict about.", file=sys.stderr)
        return 2

    failures = evaluate(REPO_ROOT)
    if failures:
        print("AI-estate containment (depth plan 6.6) is incomplete:\n", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        print(f"\n{len(failures)} problem(s) across {len(RULES)} rule(s).", file=sys.stderr)
        return 1

    print(
        f"OK — {len(AI_VERBS)} AI containment verbs in all {len(REGISTRIES)} registries, every one off by "
        f"default and probed, {len(IRREVERSIBLE_VERBS)} declared irreversible and mandatory-human, and a "
        f"kill-switch playbook that ships disabled and approves before the irreversible half."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
