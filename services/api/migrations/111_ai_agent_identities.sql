-- 111: identities for AiSOC's own agents, and a behavioural baseline per agent.
--
-- Depth plan 6.4 / parity 6.7.
--
-- Two tables, and they answer different questions on purpose.
--
-- `aisoc_ai_agent_identities` is the **declaration**: which agents this
-- deployment runs, what each may call, and how long a credential it is issued
-- lives. It is deployment-wide and carries no tenant, for the same reason
-- `workload_identities` (087) does not: the agents container triages alerts
-- for every tenant and names the one it is acting for per request. An agent
-- identity that carried a tenant would be a cross-tenant credential, which is
-- the authority that table exists to remove.
--
-- `aisoc_ai_agent_baselines` is the **observation**, and it is tenant-scoped,
-- because an agent behaves differently for different customers: an estate
-- with one connector gives its triage agent a narrower tool mix than one with
-- twelve, and a baseline that averaged across tenants would describe neither.
--
-- Why the baseline stores distributions rather than a score
-- --------------------------------------------------------
-- A single "normality" number cannot be argued with, and an analyst asked to
-- action an agent anomaly needs to see what changed: a tool the agent has
-- never called, a token spend four times its usual, activity at 03:00 from an
-- agent that has only ever run in business hours. So the row holds the
-- observed distributions and the reader forms the judgement — which is the
-- same reason the AI-asset inventory stores risk *reasons* beside its score.
--
-- Why there is no `is_anomalous` column
-- -------------------------------------
-- Because it would be read as a verdict and it is not one. Whether a
-- departure from baseline matters depends on the alert it happened during,
-- which this table cannot see. The detections in 6.5 and the windowed engine
-- are where that judgement is made.

CREATE TABLE IF NOT EXISTS aisoc_ai_agent_identities (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- The canonical agent name, matching `AGENT_IDENTITIES` in
    -- `services/agents/app/identity/agent_identity.py`. Constrained to one
    -- row per agent so two deployments of the same service cannot disagree
    -- about what `triage` may do.
    agent               TEXT        NOT NULL UNIQUE,
    description         TEXT        NOT NULL DEFAULT '',

    -- Tool names this agent may call. Empty is meaningful and is the honest
    -- default for an agent that reasons over what it is handed rather than
    -- one that goes and looks.
    tool_scopes         JSONB       NOT NULL DEFAULT '[]'::jsonb,

    -- How long a minted credential lives. Bounded in the database as well as
    -- in code: "short-lived" with an unbounded setting is a claim rather than
    -- a property, and the one place both halves of this product can agree on
    -- a bound is here.
    credential_ttl_seconds INTEGER  NOT NULL DEFAULT 600
                                    CHECK (credential_ttl_seconds BETWEEN 60 AND 3600),

    -- Observation, not configuration: when a credential was last minted for
    -- this agent. An agent that has never been issued one is either not
    -- running or not using its identity, and those are different problems.
    last_issued_at      TIMESTAMPTZ,

    enabled             BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE aisoc_ai_agent_identities IS
    'Which agents this deployment runs, what each may call, and how long its '
    'credentials live. Deployment-wide and deliberately not tenant-scoped: an '
    'agent identity that carried a tenant would be a cross-tenant credential.';
COMMENT ON COLUMN aisoc_ai_agent_identities.tool_scopes IS
    'Tool names from the agents tool registry. Empty means no tools, which is '
    'correct for an agent that reasons over what it is handed.';


CREATE TABLE IF NOT EXISTS aisoc_ai_agent_baselines (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The agent as its telemetry names it. Not constrained to the identities
    -- table: a customer's own agent reporting through `aisoc-ai-sdk` gets a
    -- baseline too, and refusing one because AiSOC does not run it would make
    -- this table describe only ourselves.
    agent               TEXT        NOT NULL,

    -- The five dimensions parity 6.7 names. Distributions rather than scores,
    -- so the reader can see what changed.
    tools               JSONB       NOT NULL DEFAULT '{}'::jsonb,
    resources           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    hours               JSONB       NOT NULL DEFAULT '{}'::jsonb,

    call_count          BIGINT      NOT NULL DEFAULT 0,
    token_total         BIGINT      NOT NULL DEFAULT 0,

    -- Welford running mean and sum-of-squares for tokens per call, so a
    -- deviation can be expressed in standard deviations without keeping every
    -- observation. Stored rather than recomputed because recomputing means
    -- scanning the lake per read, per agent, per page load.
    token_mean          DOUBLE PRECISION NOT NULL DEFAULT 0,
    token_m2            DOUBLE PRECISION NOT NULL DEFAULT 0,

    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, agent)
);

COMMENT ON TABLE aisoc_ai_agent_baselines IS
    'Per-agent behavioural baseline: which tools it calls, which resources it '
    'reaches, when it runs, how much it costs. Distributions rather than a '
    'score, because an analyst actioning an agent anomaly needs to see what '
    'changed. Deliberately carries no is_anomalous column: whether a '
    'departure matters depends on the alert it happened during, which this '
    'table cannot see.';
COMMENT ON COLUMN aisoc_ai_agent_baselines.token_m2 IS
    'Welford sum of squared deviations. With token_mean and call_count this '
    'gives a standard deviation without retaining every observation.';

CREATE INDEX IF NOT EXISTS idx_ai_agent_baselines_tenant
    ON aisoc_ai_agent_baselines (tenant_id, last_seen_at DESC);

-- Row-level security on the tenant-scoped table only. The identities table is
-- deployment-wide and has no tenant column to compare, which 087 says in the
-- same words for the same reason.
ALTER TABLE aisoc_ai_agent_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_ai_agent_baselines FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_ai_agent_baselines_tenant ON aisoc_ai_agent_baselines;
CREATE POLICY aisoc_ai_agent_baselines_tenant ON aisoc_ai_agent_baselines
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_ai_agent_baselines TO aisoc_app;
        GRANT SELECT, INSERT, UPDATE ON aisoc_ai_agent_identities TO aisoc_app;
    END IF;
END
$$;
