"""Per-agent behavioural baselines, built from the stream that already flows.

Depth plan 6.4 / parity 6.7: *"use the AI-agent runtime telemetry that
``packages/aisoc-ai-sdk`` already emits to build a per-agent behavioural
baseline, with anomaly alerts for customers' own AI agents."*

Where it runs, and why here
---------------------------
Beside the AI-asset recorder, on the fusion consumer's raw-events branch,
because that is the one path every normalized event already travels on the
default profile. The alternative — a worker reading the lake — is a service
CORE does not start, and a baseline nothing writes is the second half of this
repository's most expensive defect: the code runs, the page renders, and the
table it reads is one nothing fills.

What it records, and what it refuses to record
----------------------------------------------
Five dimensions, which is what parity 6.7 asks for: tools, resources, call
volume, token spend and hours. All as **distributions**, so a reader can see
*what* changed rather than being handed a number.

There is deliberately no anomaly score and no ``is_anomalous`` flag. Whether
a departure from baseline matters depends on the alert it happened during,
which this module cannot see; the detections in 6.5 and the windowed engine
are where that judgement belongs. What this exposes instead is
:func:`deviation`, which answers "how far from its own baseline is this call"
and returns ``None`` when the baseline is too thin to say — a standard
deviation over four observations is a number, not a measurement.

Fail-soft, in the same direction as the inventory
--------------------------------------------------
A Postgres outage drops the buffered observations and logs it. A baseline is
a governance surface, and losing an hour of it is survivable in a way that
stalling alert promotion is not.
"""

from __future__ import annotations

import json
import math
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger()

_MAX_PENDING = 200
_MAX_AGE_SECONDS = 30.0

#: Below this many calls a standard deviation is arithmetic rather than
#: evidence. `deviation` returns None until a baseline clears it, which is the
#: difference between "this agent is behaving oddly" and "we have barely seen
#: this agent".
MIN_OBSERVATIONS_FOR_DEVIATION = 30

#: How many distinct values each distribution keeps. A cap, because an agent
#: that touches ten thousand distinct resources would otherwise grow one row
#: without bound — and the hundredth most common tool tells a reader nothing
#: the first ten did not.
MAX_DISTRIBUTION_KEYS = 50

_UPSERT_SQL = """
INSERT INTO aisoc_ai_agent_baselines (
    tenant_id, agent, tools, resources, hours,
    call_count, token_total, token_mean, token_m2,
    first_seen_at, last_seen_at
)
VALUES ($1, $2, $3::jsonb, $4::jsonb, $5::jsonb, $6, $7, $8, $9, $10, $11)
ON CONFLICT (tenant_id, agent) DO UPDATE SET
    -- Counts merge rather than replace: this batch is an increment on what
    -- is already there, and `||` on two JSONB objects would take the new
    -- value for a shared key and silently discard the accumulated one.
    tools       = aisoc_ai_agent_baselines.tools       || EXCLUDED.tools,
    resources   = aisoc_ai_agent_baselines.resources   || EXCLUDED.resources,
    hours       = aisoc_ai_agent_baselines.hours       || EXCLUDED.hours,
    call_count  = aisoc_ai_agent_baselines.call_count  + EXCLUDED.call_count,
    token_total = aisoc_ai_agent_baselines.token_total + EXCLUDED.token_total,
    token_mean  = EXCLUDED.token_mean,
    token_m2    = EXCLUDED.token_m2,
    first_seen_at = LEAST(aisoc_ai_agent_baselines.first_seen_at, EXCLUDED.first_seen_at),
    last_seen_at  = GREATEST(aisoc_ai_agent_baselines.last_seen_at, EXCLUDED.last_seen_at),
    updated_at  = NOW()
"""

_SELECT_SQL = """
SELECT tools, resources, hours, call_count, token_total, token_mean, token_m2
FROM aisoc_ai_agent_baselines
WHERE tenant_id = $1 AND agent = $2
"""


@dataclass
class _Observation:
    """One agent's activity in this flush window."""

    tenant_id: str
    agent: str
    tools: dict[str, int] = field(default_factory=dict)
    resources: dict[str, int] = field(default_factory=dict)
    hours: dict[str, int] = field(default_factory=dict)
    calls: int = 0
    tokens: int = 0
    #: Welford state for tokens-per-call within this window. Merged with the
    #: stored state at write time.
    mean: float = 0.0
    m2: float = 0.0
    first_seen: float = 0.0
    last_seen: float = 0.0

    def observe(self, *, tool: str | None, resource: str | None, hour: int, tokens: int, when: float) -> None:
        self.calls += 1
        self.tokens += tokens
        if tool:
            self.tools[tool] = self.tools.get(tool, 0) + 1
        if resource:
            self.resources[resource] = self.resources.get(resource, 0) + 1
        self.hours[str(hour)] = self.hours.get(str(hour), 0) + 1
        # Welford, so one pass over a stream gives a variance without keeping
        # the stream.
        delta = tokens - self.mean
        self.mean += delta / self.calls
        self.m2 += delta * (tokens - self.mean)
        self.first_seen = min(self.first_seen, when) if self.first_seen else when
        self.last_seen = max(self.last_seen, when)


def _nested(obj: Any, *path: str) -> Any:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()[:120]
    return None


def _int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def observation_from(message: dict[str, Any]) -> tuple[str, str, dict[str, Any]] | None:
    """``(tenant, agent, fields)`` for an AI runtime event, or ``None``.

    Only `ai-runtime` and `ai-finding` events. A provider audit record names
    no agent, and an endpoint process row carries no tool or token count, so
    folding either in would populate a baseline with blanks and make the
    distributions describe the absence of data rather than the agent.
    """
    ocsf = message.get("ocsf_event")
    if not isinstance(ocsf, dict):
        return None
    source_type = _text(ocsf.get("source_type")) or _text(_nested(ocsf, "metadata", "product", "name")) or ""
    if source_type not in ("ai-runtime", "ai-finding", "AI Runtime", "AI Guardrail"):
        return None
    tenant_id = _text(message.get("tenant_id") or ocsf.get("tenant_uid"))
    agent = _text(_nested(ocsf, "actor", "process", "name"))
    if not (tenant_id and agent):
        return None
    evidence = _nested(ocsf, "finding", "evidence") or {}
    return (
        tenant_id,
        agent,
        {
            "tool": _text(ocsf.get("activity_name")),
            "resource": _text(_nested(ocsf, "resource", "name")) or _text(_nested(ocsf, "finding", "title")),
            "tokens": _int(evidence.get("prompt_tokens")) + _int(evidence.get("completion_tokens")),
        },
    )


def deviation(baseline: dict[str, Any], *, tokens: int, tool: str | None, hour: int) -> dict[str, Any] | None:
    """How far this call sits from the agent's own baseline, or ``None``.

    ``None`` when the baseline has seen fewer than
    :data:`MIN_OBSERVATIONS_FOR_DEVIATION` calls. A standard deviation over
    four observations is arithmetic, not a measurement, and publishing one
    would make every newly-seen agent look anomalous on its fifth call —
    the failure mode that gets a detection turned off in a week.
    """
    calls = _int(baseline.get("call_count"))
    if calls < MIN_OBSERVATIONS_FOR_DEVIATION:
        return None

    mean = float(baseline.get("token_mean") or 0.0)
    m2 = float(baseline.get("token_m2") or 0.0)
    variance = m2 / calls if calls else 0.0
    stdev = math.sqrt(variance)

    tools = baseline.get("tools") or {}
    hours = baseline.get("hours") or {}
    return {
        "observations": calls,
        # Zero standard deviation is a real answer for an agent whose calls
        # are identical in size, and dividing by it is not. Reported as None
        # rather than infinity, because an infinite z-score renders as a
        # confident extreme and means "we cannot say".
        "token_z": None if stdev == 0 else round((tokens - mean) / stdev, 2),
        "token_mean": round(mean, 1),
        "new_tool": bool(tool) and tool not in tools,
        "new_hour": str(hour) not in hours,
    }


class AgentBaselineRecorder:
    """Accumulate per-agent observations and merge them into Postgres."""

    def __init__(
        self,
        pool_provider: Callable[[], Any],
        *,
        max_pending: int = _MAX_PENDING,
        max_age_seconds: float = _MAX_AGE_SECONDS,
    ) -> None:
        self._pool_provider = pool_provider
        self._max_pending = max_pending
        self._max_age = max_age_seconds
        self._pending: dict[tuple[str, str], _Observation] = {}
        self._last_flush = time.monotonic()
        self._metrics = {"observed": 0, "written": 0, "dropped": 0}

    @property
    def metrics(self) -> dict[str, int]:
        return dict(self._metrics)

    async def observe(self, message: dict[str, Any]) -> bool:
        parsed = observation_from(message)
        if parsed is None:
            return False
        tenant_id, agent, fields = parsed
        now = time.time()
        key = (tenant_id, agent)
        entry = self._pending.get(key)
        if entry is None:
            entry = _Observation(tenant_id=tenant_id, agent=agent)
            self._pending[key] = entry
        entry.observe(
            tool=fields["tool"],
            resource=fields["resource"],
            hour=datetime.fromtimestamp(now, tz=UTC).hour,
            tokens=fields["tokens"],
            when=now,
        )
        self._metrics["observed"] += 1
        if len(self._pending) >= self._max_pending:
            await self.flush()
        return True

    async def flush_if_stale(self) -> None:
        if self._pending and (time.monotonic() - self._last_flush) >= self._max_age:
            await self.flush()

    async def flush(self) -> int:
        if not self._pending:
            self._last_flush = time.monotonic()
            return 0
        batch = list(self._pending.values())
        self._pending.clear()
        self._last_flush = time.monotonic()

        pool = self._pool_provider() if callable(self._pool_provider) else self._pool_provider
        if pool is None:
            self._metrics["dropped"] += len(batch)
            logger.warning("agent_baseline.no_pool", dropped=len(batch), detail="no database pool; agent baselines were discarded")
            return 0

        written = 0
        try:
            async with pool.acquire() as conn:
                for entry in batch:
                    merged_mean, merged_m2 = await self._merge_welford(conn, entry)
                    await conn.execute(
                        _UPSERT_SQL,
                        entry.tenant_id,
                        entry.agent,
                        json.dumps(_merge_counts(await self._stored(conn, entry, "tools"), entry.tools)),
                        json.dumps(_merge_counts(await self._stored(conn, entry, "resources"), entry.resources)),
                        json.dumps(_merge_counts(await self._stored(conn, entry, "hours"), entry.hours, cap=24)),
                        entry.calls,
                        entry.tokens,
                        merged_mean,
                        merged_m2,
                        datetime.fromtimestamp(entry.first_seen or time.time(), tz=UTC),
                        datetime.fromtimestamp(entry.last_seen or time.time(), tz=UTC),
                    )
                    written += 1
        except Exception as exc:  # noqa: BLE001 — a baseline must never wedge promotion
            self._metrics["dropped"] += len(batch) - written
            logger.warning("agent_baseline.flush_failed", error=str(exc)[:300], dropped=len(batch) - written)
        self._metrics["written"] += written
        return written

    async def _row(self, conn: Any, entry: _Observation) -> dict[str, Any]:
        record = await conn.fetchrow(_SELECT_SQL, entry.tenant_id, entry.agent)
        return dict(record) if record else {}

    async def _stored(self, conn: Any, entry: _Observation, column: str) -> dict[str, int]:
        row = await self._row(conn, entry)
        raw = row.get(column)
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except ValueError:
                return {}
        return {str(k): _int(v) for k, v in (raw or {}).items()} if isinstance(raw, dict) else {}

    async def _merge_welford(self, conn: Any, entry: _Observation) -> tuple[float, float]:
        """Combine this window's Welford state with what is stored.

        Chan's parallel formula, so a baseline accumulated in batches equals
        the one a single pass would have produced. Summing means weighted by
        count would be close and wrong, and the error compounds over every
        flush for the life of the deployment.
        """
        row = await self._row(conn, entry)
        n_a = _int(row.get("call_count"))
        if n_a == 0:
            return entry.mean, entry.m2
        mean_a = float(row.get("token_mean") or 0.0)
        m2_a = float(row.get("token_m2") or 0.0)
        n_b, mean_b, m2_b = entry.calls, entry.mean, entry.m2
        n = n_a + n_b
        delta = mean_b - mean_a
        return mean_a + delta * n_b / n, m2_a + m2_b + delta * delta * n_a * n_b / n


def _merge_counts(stored: dict[str, int], window: dict[str, int], *, cap: int = MAX_DISTRIBUTION_KEYS) -> dict[str, int]:
    """Sum two count maps, keeping the ``cap`` most frequent keys.

    Bounded because an agent touching ten thousand distinct resources would
    otherwise grow one row without limit, and the hundredth most common tool
    tells a reader nothing the first ten did not.
    """
    merged = dict(stored)
    for key, count in window.items():
        merged[key] = merged.get(key, 0) + count
    if len(merged) <= cap:
        return merged
    return dict(sorted(merged.items(), key=lambda kv: (-kv[1], kv[0]))[:cap])
