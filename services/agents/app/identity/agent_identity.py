"""Each of AiSOC's own agents gets an identity, a short credential and a tool scope.

Depth plan 6.4 / parity 6.7.

What this replaces
------------------
One string. Every internal caller presented ``AISOC_AGENTS_SERVICE_TOKEN``, so
the audit trail could say "the agents service" and nothing finer, and every
agent in that service could call every tool the registry held. A triage agent
and a response agent had exactly the same reach.

Three things change, and the third is the one that matters:

**Identity.** Each agent is named in :data:`AGENT_IDENTITIES`, with the tools
it may call. The name travels on the credential, so a ledger row and an audit
row can attribute an action to ``triage`` rather than to a container.

**A short credential.** :func:`mint` derives a time-bounded token from the
service secret by HMAC. It is derived rather than stored because the
alternative is a second secret store for credentials that live ten minutes,
and because a derived token needs no round trip to verify — the API checks it
with the same secret it already holds.

**Least privilege, enforced where the call happens.** :func:`tool_scope`
returns the tool names an agent may use, and the registry refuses anything
outside it at execute time. Filtering the *offered* schema list is necessary
and not sufficient: a model can emit a call for a tool it was never offered,
and a registry that only filtered the advertisement would run it.

What an identity is not
-----------------------
It is not a tenant boundary. The agents container triages alerts for every
tenant on the deployment and names the one it is acting for per request; the
tenant comes from that header and never from this credential. Conflating the
two would make an agent identity a cross-tenant credential, which is the
authority `workload_identities` exists to remove.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from dataclasses import dataclass

import structlog

logger = structlog.get_logger()

#: Where the shared secret lives. The same one the API verifies against, so a
#: derived credential needs no second store and no round trip.
SECRET_ENV = "AISOC_AGENTS_SERVICE_TOKEN"

#: How long a minted credential is good for. Ten minutes: long enough for the
#: longest investigation this product runs (the deep-investigation budget is
#: well under it), short enough that a leaked one is worthless by the time it
#: reaches anybody. Overridable, floored and capped, because "short-lived"
#: with an unbounded setting is a claim rather than a property.
DEFAULT_TTL_SECONDS = 600
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 3600


@dataclass(frozen=True)
class AgentIdentity:
    """One named agent, and the tools it may call."""

    agent: str
    description: str
    #: Tool names from `app.tools.registry`. Empty means **no tools**, which
    #: is the honest default for an agent that reasons over what it is given
    #: rather than one that goes and looks.
    tools: frozenset[str]
    #: What this agent is for, in the audit trail's words.
    purpose: str


#: Every agent that may hold an identity, with its tool scope.
#:
#: Scopes are narrow by construction and differ because the agents genuinely
#: differ. The triage agent decides a verdict from an alert it was handed: it
#: needs to recognise indicators and techniques, and it has no business
#: reaching a sandbox or a customer's EDR. The investigation agent is the one
#: that goes and looks, so it holds the enrichment and lookup tools. The hunt
#: agent composes queries and reads results.
#:
#: A tool added to the registry is **not** automatically added to any scope.
#: That is the point, and `scripts/check_agent_identity.py` fails when a
#: registry tool belongs to no scope, so a new tool is a decision somebody
#: makes rather than a reach every agent silently gains.
AGENT_IDENTITIES: dict[str, AgentIdentity] = {
    "triage": AgentIdentity(
        agent="triage",
        description="Disposition an alert from the evidence it was handed.",
        tools=frozenset({"extract_iocs", "map_to_mitre", "lookup_technique"}),
        purpose="verdict",
    ),
    "investigation": AgentIdentity(
        agent="investigation",
        description="Go and look: pivot through the lake, enrich, and reach connected vendors.",
        tools=frozenset({"extract_iocs", "map_to_mitre", "lookup_technique", "enrich_ioc", "sandbox_lookup_file_hash"}),
        purpose="investigation",
    ),
    "hunt": AgentIdentity(
        agent="hunt",
        description="Turn a hypothesis into a query and read what comes back.",
        tools=frozenset({"extract_iocs", "map_to_mitre", "lookup_technique"}),
        purpose="hunt",
    ),
    "respond": AgentIdentity(
        agent="respond",
        description="Propose and dispatch response steps, each graded on its own contract.",
        # Deliberately empty. Every verb this agent can reach goes through the
        # action contract and the approval matrix, which is a stronger control
        # than a tool allowlist and would be weakened by duplicating it here.
        tools=frozenset(),
        purpose="response",
    ),
    "recon": AgentIdentity(
        agent="recon",
        description="Assemble context for an investigation before it starts.",
        tools=frozenset({"extract_iocs", "map_to_mitre", "lookup_technique", "enrich_ioc"}),
        purpose="context",
    ),
    "report": AgentIdentity(
        agent="report",
        description="Write up what the other agents concluded.",
        tools=frozenset(),
        purpose="reporting",
    ),
}


class AgentIdentityError(RuntimeError):
    """An agent asked for something its identity does not cover."""


def known_agents() -> tuple[str, ...]:
    return tuple(sorted(AGENT_IDENTITIES))


def tool_scope(agent: str) -> frozenset[str]:
    """The tools this agent may call.

    An unknown agent gets **nothing**, not everything. The default direction
    matters: a typo in an agent name that opened the whole registry would be
    indistinguishable from a correct call until somebody read a ledger.
    """
    identity = AGENT_IDENTITIES.get(agent)
    if identity is None:
        logger.warning("agent_identity.unknown", agent=agent, detail="no tools granted")
        return frozenset()
    return identity.tools


def _secret() -> str:
    return os.getenv(SECRET_ENV, "").strip()


def _ttl(requested: int | None) -> int:
    if requested is None:
        return DEFAULT_TTL_SECONDS
    return max(MIN_TTL_SECONDS, min(MAX_TTL_SECONDS, int(requested)))


def mint(agent: str, *, ttl_seconds: int | None = None, now: float | None = None) -> str:
    """A short-lived credential naming this agent.

    Shape: ``aisoc-agent.<agent>.<expires_at>.<mac>``. The agent name and the
    expiry are in the clear because they are not secrets — the MAC is what
    makes them unforgeable, and a verifier that had to decrypt before it could
    tell which agent was calling could not log the attribution of a credential
    it then rejected.
    """
    if agent not in AGENT_IDENTITIES:
        raise AgentIdentityError(f"{agent!r} is not a known agent; known: {', '.join(known_agents())}")
    secret = _secret()
    if not secret:
        raise AgentIdentityError(f"{SECRET_ENV} is unset, so no agent credential can be minted")
    expires_at = int((now if now is not None else time.time()) + _ttl(ttl_seconds))
    return f"aisoc-agent.{agent}.{expires_at}.{_mac(secret, agent, expires_at)}"


def _mac(secret: str, agent: str, expires_at: int) -> str:
    payload = f"{agent}.{expires_at}".encode()
    digest = hmac.new(secret.encode(), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def verify(credential: str, *, now: float | None = None) -> str | None:
    """The agent this credential names, or ``None``.

    ``None`` for every failure — malformed, expired, wrong MAC, no secret
    configured — because a caller that could tell *which* of those happened
    would be an oracle for the first three.
    """
    secret = _secret()
    if not secret or not credential:
        return None
    parts = credential.strip().split(".")
    if len(parts) != 4 or parts[0] != "aisoc-agent":
        return None
    _, agent, raw_expiry, mac = parts
    try:
        expires_at = int(raw_expiry)
    except ValueError:
        return None
    # Compared before the MAC so an expired credential costs nothing, and
    # after the parse so a malformed one cannot reach the comparison.
    if (now if now is not None else time.time()) >= expires_at:
        return None
    if not hmac.compare_digest(mac, _mac(secret, agent, expires_at)):
        return None
    return agent if agent in AGENT_IDENTITIES else None


def audit_subject(agent: str) -> dict[str, str]:
    """What an audit or ledger row records about the acting agent.

    The name and the purpose, never the credential. A trail that carried the
    credential would be a trail that leaks one.
    """
    identity = AGENT_IDENTITIES.get(agent)
    return {
        "actor_type": "ai_agent",
        "agent": agent,
        "purpose": identity.purpose if identity else "unknown",
    }
