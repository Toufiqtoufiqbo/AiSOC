"""Tool registry for LLM tool-calling (Wave 4a).

Until now no agent used LLM tool-calling: tools were hardcoded Python calls the
code decided to make, and the model only returned a JSON verdict. This registry
exposes AiSOC's real tools (IOC enrichment, MITRE lookup, IOC/technique
extraction, graph blast-radius) as OpenAI-style function schemas so an LLM can
*choose* which to call, and executes the model's selected calls safely.

Design:
* Each ``Tool`` carries a JSON-schema ``parameters`` block (what ``bind_tools``
  ships to the provider) and a callable (sync or async).
* ``execute`` is fail-soft: an unknown tool or a raising tool returns a
  structured ``{"error": ...}`` the model can react to, never an exception that
  aborts the loop.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from app.identity.agent_identity import tool_scope


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON schema for the arguments
    fn: Callable[..., Any] | Callable[..., Awaitable[Any]]

    def openai_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {"name": self.name, "description": self.description, "parameters": self.parameters},
        }


class ToolRegistry:
    """The tools one agent may call, and the scope that bounds them.

    ``allowed`` is depth 6.4's least-privilege half. ``None`` means
    unbounded, which is what every caller got before agent identities
    existed and is still right for a registry assembled for a specific
    purpose. A set means *only these*, and it is enforced in
    :meth:`execute` rather than only by filtering :meth:`openai_schemas`.

    Both halves are needed and neither is sufficient. Filtering the offered
    schemas is what stops the model choosing a tool it should not have;
    refusing at execute is what stops a model that emits a call for a tool
    it was never offered — which models do, and which a
    filter-the-advertisement-only registry would run.
    """

    def __init__(self, tools: list[Tool] | None = None, *, allowed: frozenset[str] | None = None) -> None:
        self._tools: dict[str, Tool] = {}
        self._allowed = allowed
        for tool in tools or []:
            self.register(tool)

    @property
    def allowed(self) -> frozenset[str] | None:
        return self._allowed

    def permits(self, name: str) -> bool:
        return self._allowed is None or name in self._allowed

    def register(self, tool: Tool, *, grant: bool = True) -> None:
        """Add a tool, and by default let this registry call it.

        The static scope bounds the **shared built-in** tools: an agent's
        declared reach over things every run has. A tool registered after the
        fact is resolved for this run specifically — a vendor tool for a
        connector this tenant actually connected, an MCP tool from this
        tenant's own allowlist — and is already governed where it is
        resolved, so registering it grants it.

        ``grant=False`` is for a caller that wants a tool present and not
        callable, which is how a test proves the refusal fires.
        """
        self._tools[tool.name] = tool
        if grant and self._allowed is not None:
            self._allowed = self._allowed | {tool.name}

    def names(self) -> list[str]:
        return sorted(name for name in self._tools if self.permits(name))

    def all_names(self) -> list[str]:
        """Every registered tool, scope ignored. For gates and diagnostics."""
        return sorted(self._tools)

    def openai_schemas(self) -> list[dict[str, Any]]:
        return [t.openai_schema() for t in self._tools.values() if self.permits(t.name)]

    async def execute(self, name: str, args: dict[str, Any]) -> Any:
        if not self.permits(name):
            # Structured like every other failure here so the model can react
            # rather than the loop aborting, and worded so a ledger reader can
            # tell a refusal from a tool that does not exist.
            return {"error": f"tool not permitted for this agent: {name}"}
        tool = self._tools.get(name)
        if tool is None:
            return {"error": f"unknown tool: {name}"}
        try:
            result = tool.fn(**(args or {}))
            if inspect.isawaitable(result):
                result = await result
            return result
        except Exception as exc:  # noqa: BLE001 — surface tool failure to the model, don't abort
            return {"error": f"{type(exc).__name__}: {exc}"}


def _str_param(name: str, desc: str) -> dict[str, Any]:
    return {"type": "object", "properties": {name: {"type": "string", "description": desc}}, "required": [name]}


def scoped_registry(agent: str, tenant_id: str = "") -> ToolRegistry:
    """The default registry, bounded to one agent's declared tool scope.

    Depth 6.4. An agent with an empty scope gets a registry that advertises
    nothing and refuses everything, which is the honest shape for an agent
    that reasons over what it is handed — and for an unknown agent name,
    where granting everything on a typo would be indistinguishable from a
    correct call until somebody read a ledger.
    """
    registry = default_registry(tenant_id)
    registry._allowed = tool_scope(agent)  # noqa: SLF001 — the scope is the registry's own invariant
    return registry


def default_registry(tenant_id: str = "") -> ToolRegistry:
    """Registry of AiSOC's real analyst tools, wrapped for LLM tool-calling.

    ``tenant_id`` is the run's own. The sandbox lookup reaches the API, which
    refuses a service credential that does not name the tenant it acts for.
    """
    from app.investigator.tools import enrich_ioc, extract_iocs, map_to_mitre
    from app.tools.mitre import lookup_technique
    from app.tools.sandbox import TOOL_DESCRIPTION, TOOL_NAME, TOOL_PARAMETERS, lookup_file_hash

    return ToolRegistry(
        [
            Tool(
                name=TOOL_NAME,
                description=TOOL_DESCRIPTION,
                parameters=TOOL_PARAMETERS,
                fn=lambda sha256: lookup_file_hash(sha256, tenant_id=tenant_id),
            ),
            Tool(
                name="extract_iocs",
                description="Extract IOCs (IPs, domains, hashes, URLs) from free text.",
                parameters=_str_param("text", "The text to scan for indicators of compromise."),
                fn=lambda text: extract_iocs(text),
            ),
            Tool(
                name="map_to_mitre",
                description="Map free text describing behaviour to MITRE ATT&CK technique IDs.",
                parameters=_str_param("text", "The behaviour description to map to ATT&CK techniques."),
                fn=lambda text: map_to_mitre(text),
            ),
            Tool(
                name="lookup_technique",
                description="Look up a MITRE ATT&CK technique by ID (e.g. T1110).",
                parameters=_str_param("technique_id", "The ATT&CK technique ID, e.g. T1059.001."),
                fn=lambda technique_id: lookup_technique(technique_id),
            ),
            Tool(
                name="enrich_ioc",
                description="Enrich a single IOC (ip|domain|hash|url) with threat intelligence.",
                parameters={
                    "type": "object",
                    "properties": {
                        "ioc_value": {"type": "string", "description": "The IOC value."},
                        "ioc_type": {"type": "string", "enum": ["ip", "domain", "hash", "url"]},
                    },
                    "required": ["ioc_value", "ioc_type"],
                },
                fn=lambda ioc_value, ioc_type: enrich_ioc(ioc_value, ioc_type),
            ),
        ]
    )
