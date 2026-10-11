# AiSOC depth plan: progress

Mirrors `plans/aisoc_depth_plan.plan.md`, which is locked and is the source of
truth. This file is the mutable half.

Legend: `[ ]` not started, `[~]` in progress, `[x]` done, `[!]` blocked (with
exactly what is needed).

An item is `[x]` only when all three of these are recorded against it: the test
or gate that failed on the pre-fix tree for the stated reason, the change, and
the negative control showing that reverting it fails again.

- **Base commit:** `1b8bc2d4` (`origin/main`, v17.1.0).
- **Plan captured at:** `90ea2fd`. Figures in the plan body are hints at that
  commit; Phase 0.2 below re-derives each one and the tree wins.

## Reconciliation, 2026-10-09

Eleven items had merged to `main` and every one still read `[ ]` here. The
tracker is the mutable half of a locked plan, so a tick that lags the tree
makes it describe a repository that no longer exists -- the same failure the
plan exists to catch, one level up.

Reconciled against the tree rather than against the pull requests: each item
below was confirmed by the artefact it was supposed to produce being present
on `main` (the corpus file, the OCSF decision table, the event catalogue
directory, the scorecard fields, the notify arms, the report scheduler, the
step bounds, the access-conditions routes, the security pack), not by a merged
title. Each carries the reproduce, change and negative control the legend
requires in its own pull request body.

| Item | Landed in | Confirmed by |
| --- | --- | --- |
| 1.1 | #1205 | `services/agents/tests/eval_data/verdict/verdict_corpus_v1.json` |
| 1.2 | #1191 | nine scorecard fields in `aisoc_benchmark/replay.py` |
| 1.3 | #1197 | `scripts/check_verdict_corpus.py`, `prompting/tool_results.py` |
| 2.1 | #1195 | `internal/normalizer/ocsf_classes.go` |
| 2.2 | #1204 | `scripts/check_activity_projection.py` |
| 2.3 | #1209 | `schemas/event_catalog/` |
| 5.1 | #1203 | `live_actions/notify_arms.py` |
| 5.2 | #1211 | `app/workers/report_scheduler.py` |
| 5.3 | #1207 | `app/playbook/bounds.py` |
| 8.2 | #1206 | `endpoints/access_conditions.py` |
| 8.3 | #1210 | `docs/security/` |

Not started: phases 3, 4, 6, 7, 9 and the whole of 10, plus 1.4--1.6 and
2.4--2.7. Those remain `[ ]` and are not claimed here.

## Migration and ADR numbers claimed

Phases run in parallel lanes, so a number is claimed here **before** the file
is written. Next free at capture: migration `095`, ADR `0010`
(`docs/decisions/`, not `docs/adr/` -- the plan's wording; the directory is
`decisions/` and the highest is `0009-auto-close-without-an-earned-grant.md`).

| Number | Claimed by | Status |
|---|---|---|
| ADR `0010` | 2.7 — entity and session context in CORE | **landed**, `docs/decisions/0010-entity-and-session-context-in-core.md`, accepted |
| migration `102` | 2.4 — `102_sessions.sql` | claimed |
| migration `103` | 2.5 — `103_posture_snapshots.sql` | claimed |
| migration `104` | 9.1 — `104_mcp_access.sql` | claimed |
| migration `105` | 9.2 — `105_semantic_memory.sql` | claimed |
| migration `106` | 9.3 — `106_case_depth.sql` | claimed |
| migration `107` | 9.4 — `107_case_war_rooms.sql` | claimed |
| migration `108` | 9.5 — `108_hunt_reports.sql` | claimed |
| migration `109` | 9.6 — `109_push_devices.sql` | claimed |
| migration `110` | 6.1 — `110_ai_assets.sql` | claimed |
| migration `111` | 6.4 — `111_ai_agent_identities.sql` | claimed |
| ADR `0011` | 6.6 — AI containment arms off by default, and the rollback a kill-switch needs | claimed |
| — | 5.4 — `104_playbook_verification.sql` on `depth/5.4-5.6-lane-c`, and 7.1 — `104_phishing_campaigns.sql` on `depth/7.1-7.3-phishing` | **collision, unresolved here.** Both lanes wrote a `104` on a branch without a row in this table. Phase 9's `104` is the one with a claim, so these two need renumbering by their own lanes; recorded rather than renamed from outside, because renaming another lane's migration from here is how a branch comes back to a file that no longer exists |

Highest migration on `main` at claim time was `101_audit_immutable_nullify.sql`,
so `095`--`101` were taken by sibling lanes between the capture above and this
claim; re-read `services/api/migrations/` rather than trusting the capture row.

The same is true of this table: `104` was already written on two sibling
lanes' branches with no row here, which is how lanes collide. Phase 6's
numbers were picked after reading `services/api/migrations/` on `main` **and**
`git ls-tree` over every `origin/*` branch, not from the row above.

Phase 9 re-read `services/api/migrations/` on 2026-10-11 before claiming:
`101_audit_immutable_nullify.sql` was still the highest on `main`, and `102`
and `103` were already spoken for in the table above, so Phase 9 takes `104`
through `109`, one per item. A number left unused at the end of the phase is
released by striking its row rather than by silently leaving a gap.

**Phase 6 moved `105`/`106` to `110`/`111` on 2026-10-11**, because Phase 9's
claim for `104`--`109` reached this table on `main` first and a claim table
nobody defers to is not a coordination mechanism. The lesson is the one this
section already states and that three lanes still fell to: the table is
authoritative only for lanes that write to it **before** the file, and four
branches now carry a `104` or a `105` that was never claimed here. Reading
`main` is not enough; read `git ls-tree` over every `origin/*` branch as
well, which is what found this.

## Phase 0: Kickoff

- [x] **0.1** `DEPTH_PROGRESS.md` exists (this file), modelled on
  `PARITY_PROGRESS.md`.
- [x] **0.2** Every figure re-derived against the base commit. See below.
- [~] **0.3** Baselines captured. Four of five recorded; `make up-full` and the
  hosted-model matrix are noted under Deviations.

### 0.2 Re-derived figures

Measured on `1b8bc2d4`, 2026-10-07, each by the generator or gate the plan
names. Where the captured and measured values differ, **the measured value is
the one later phases are graded against**.

| Figure | Captured in plan | Measured | Note |
|---|---|---|---|
| Executable detections | 2,603 | **2,603** | `generate_corpus_stats.py --check` |
| On disk | 6,991 | **6,991** | same |
| Quarantined | — | **4,388** | same |
| Unreachable native rules | 119 | **119** | `check_detection_fields.py`; `MAX_UNREACHABLE = 119` |
| … needing a windowed evaluator | 74 | **74** | the family Phase 3.1 translates |
| … identity enrichment | 24 | **24** | Phase 3.3 |
| … fields nothing emits | 8 | **8** | Phase 3.3 |
| … first-seen / age | 8 | **8** | Phase 3.3 |
| … other | 6 | **6** | |
| … behavioural baseline | 2 | **2** | Phase 3.4 |
| Windowed rules | 18 | **18** | `services/fusion/app/data/windowed_ruleset.json` |
| Executor arms | 73 | **74** | classes declaring `capability = "…"` under `services/actions/app/live_actions/`. **33 distinct capability verbs.** Phase 5.5 counts arms, so its target is measured from 74 |
| Claim-to-gate matrix | 290 rows, all GATED | **290 rows, 290 GATED, 0 PARTIAL, 0 NO GATE** | `check_claim_gate_matrix.py` |
| CORE / full services | 16 / 22 | **16 / 22** | `check_profile_service_counts.py` (production stack: 16 / 21) |
| Next migration | 095 | **095** | highest is `094_user_delete_fk.sql` |
| Next ADR | 0010 | **0010** | in `docs/decisions/`, highest `0009` |

**Cloud, identity, SaaS and code executable rules: captured 461, measured
395.** The gap is a definition the plan does not pin, not a change in the
tree, so it is recorded here rather than reconciled silently. Measured by
`log_source` on executable entries in `marketplace/index.json`, grouping:

| Group | Count | `log_source` values counted |
|---|---|---|
| cloud | 225 | aws 76, azure 50, gcp 40, kubernetes 36, docker 10, cloud 8, multi-cloud 5 |
| identity | 123 | identity 47, okta 35, active-directory 22, auth0 5, duo 5, ping 5, keycloak 4 |
| saas | 34 | google-workspace 8, m365 7, slack 6, email 3, salesforce 3, + 7 others |
| code | 13 | github 12, gitlab 1 |
| **total** | **395** | |

Phase 3.6 must therefore raise **395 → 800** and ship the `make stats` line
with a `--check` gate that fixes this grouping in code, so the figure stops
being re-derivable two ways.

**Two measurement caveats found while re-deriving, both worth carrying:**

1. **1,724 of the 2,603 executable rules live under
   `detections/sigma-imports/_quarantine/`.** "Executable" and "quarantined"
   overlap, because the Sigma compiler began translating rules in place
   without moving them. Any later statement of the form "N executable rules"
   must not be read as "N rules outside quarantine".
2. **The plan's "1,798 of 2,603 are Windows (69%)" does not reproduce from
   the index.** Only 111 executable entries carry `log_source: windows`, and
   218 are Windows by path or log source (8%). The 1,770 Sigma imports carry
   **no `log_source` at all**, which is where the difference lives: the
   captured figure counted the Sigma corpus as Windows, which is
   approximately but not exactly true. Phase 3.6's gate should classify by a
   field that exists rather than by corpus membership.

### 0.3 Baseline artefacts

Hardware: Apple M5 Max, 18 cores, 128 GiB host; Docker 29.5.2 in a 6-CPU /
15.6 GiB Linux VM. Date 2026-10-07. Commit `1b8bc2d4`.

| Baseline | Result | Artefact |
|---|---|---|
| `make up` (CORE) | **PASS** -- 16 services healthy, administrator created | — |
| `make smoke` | **PASS 10/10 stages** -- event traversed ingest → Kafka → fusion → alert, severity and source attribution survived | — |
| Behavioural injection suite | **19 passed.** Overall flip rate **0.2593**, unsafe-action rate **0.037** over 27 cases | `services/agents/tests/eval_data/behavioural_injection.json` |
| Live-agent model matrix | **0 of 2 models measured** -- "no live LLM key configured", reported as *not measured* rather than zeros | — |
| Load harness, 20,000 events | **pipeline 130.3 alerts/s**, ingest accepted 397.6 events/s, p50 **54.9 s**, p95 **100.2 s**, p99 103.9 s, delivery ratio **1.0**, duplicates **0**, dead letters **0** | `docs/perf/results/2026-10-07-compose-depth-baseline.json` |

Per-family injection flip rates at baseline, from the artefact above:

| Family | Cases | Flip rate | Guard catch rate |
|---|---|---|---|
| command_line | 4 | 0.25 | 0.75 |
| email_subject | 3 | 0.3333 | 0.6667 |
| fake_analyst_note | 2 | 0.0 | 1.0 |
| **fake_tool_output** | — | **1.0** | **0.0** |
| file_path, process_name, url, username | — | 0.0 | — |
| persona | — | 0.67 | — |

`fake_tool_output` at 1.0 flip / 0.0 catch is the figure Phase 1.3 must bring
to **at or below 0.10 on tuned *and* held-out payloads**.

The load-harness row is the "before" for Phase 4.4, whose target is a
sustained 5,000 events/s at p95 under 2 s on documented cloud hardware. The
measured p95 of 100 s is a *drain* latency under a 20,000-event burst on a
6-CPU laptop VM, not a steady-state figure, and must be labelled that way
wherever it is quoted.

## Deviations

Recorded as they happen. A deviation is not a failure; an unrecorded one is.

### D1 -- The load harness could not run from a clean checkout (fixed here)

`scripts/perf/load_harness.py` invoked `go run ./services/demo-producer` with
`cwd=` the repository root. There is no `go.mod` at the root -- the producer
is its own module at `services/demo-producer/go.mod` -- so the subprocess
failed before starting:

```
producer failed (1): go: go.mod file not found in current directory or any
parent directory; see 'go help modules'
```

The harness has therefore never produced a run on the path it documents; the
published laptop figures must have come from a prebuilt `--producer-bin`,
which needs no module context. Fixed in the Phase 0 commit by running `go run
.` from the producer's own directory, which is what produced the baseline
above. Phase 4.4 extends this harness and inherits the fix.

### D2 -- `make up-full` not captured on this host

Deferred rather than claimed. The `full` profile is 22 services at ~12 GiB
against a 15.6 GiB VM that is already running the 16 CORE services, and a
baseline taken under memory pressure would describe the host rather than the
stack. Recorded as unmeasured; Phase 4.5 (`helm install` brings up all of
CORE) and Phase 3.4 (baselines in CORE) are the items that need it, and both
will re-take it on a sized host.

### D3 -- Hosted model rows are maintainer-blocked (M2)

`scripts/run_model_matrix.py` reports **0 of 2 models measured** with "no live
LLM key configured". This is the gate behaving correctly: it refuses to
publish `0.000` where it means "not measured". Phase 1.4 adds local 7--8B
candidates, which need no key and *can* be measured here; the hosted rows stay
`[!]` until the maintainer funds a key.

### D4 -- Not all 74 "windowed" rules need a window

The reachability gate attributes a rule to the windowed family by matching
its field names against `_count$|^count_|_per_|time_window|_window_|_5min|_ratio$`.
Eight of the 74 are per-event properties the pattern misreads: `row_count` is
the size of one export record, `answer_count` the number of records in one DNS
response, `insecure_registries_count` the length of a list in one daemon
config event, `subdomain_hex_ratio` a property of one query name, and
`active_keys_per_account` the state of an account at one moment. They are
refused under the `not-windowed` kind rather than translated, and the family
label in `check_detection_fields.py` is left as it is: changing the classifier
would move the published family counts that Phase 0.2 recorded, for no gain
now that each rule carries an individual reason.

### D5 -- Five windowed rules that predate this work group by a field nothing emits

`wd-secret-enumeration` (`distinct_by=secret_name`), `wd-windows-password-spray`,
`wd-sysmon-remote-thread-fanout`, `wd-sysmon-dns-query-fanout` and
`wd-sysmon-process-spawn-burst` name entity fields outside the statically
recovered namespace. Four of the five are Windows `EventData` keys the
`windows_event` connector lifts wholesale, so the namespace under-approximates
and the rules are probably fine; `secret_name` has no such explanation. The
new gate **reports** these rather than failing on them, because failing would
be a false alarm about working rules, and the entity question is answered by
replay rather than by a name lookup. Not fixed here: changing a shipped
rule's `group_by` is a content decision with its own blast radius.

### D6 -- The windowed engine ran a narrower field namespace than the stateless one

`WindowedDetectionEngine._fields` carried a docstring saying it matched the
stateless engine's namespace "exactly". It did not: the stateless engine then
applies `derived_fields.enrich()` and the per-tenant allowlist overlay, and
the windowed engine applied neither. Two of the rules translated here carry an
`<x>_in_allowlist` clause, so without fixing this they would have moved from
one engine that could not fire them to another. Both passes are now applied in
`evaluate()`, which takes the overlay the consumer had already resolved for
the stateless engine.

### D7 -- There is no "existing watermark" in fusion to order sequences by

Item 3.2 says to order sequences "by event time with the existing
watermark". No watermark exists anywhere in the detection path: the only two
in the tree belong to `services/actions`' shadow-reconcile router and the
dead-letter replay, which are unrelated subsystems. Rather than invent one or
quietly order by arrival, the engine orders strictly by event time and
declares its own bound,
`SEQUENCE_REORDER_TOLERANCE_SECONDS = 300`, for how late an event may arrive
and still be stitched into a sequence. The bound is stated in the module
rather than inherited from something that does not exist.

Ordering by arrival would have been the easy implementation and is wrong
here: almost every connector in this tree **polls**, so a batch arrives in
the vendor's order and the event that starts a sequence routinely lands after
the one that finishes it. `test_a_batch_delivered_out_of_arrival_order_still_fires`
is the regression test for that, and reverting the event-time read makes it
and two others fail.

### D8 -- No upstream Sigma correlation rule exists in this tree to import

`detections/sigma-imports/` holds 3,132 rule documents and **not one carries
a `correlation:` block**, so the missing importer and the missing corpus hid
each other: there was nothing for an importer to have failed on. There is
also no fetcher for the upstream corpus (`scripts/` has `compile_sigma_ruleset.py`,
`sigma_compiler.py` and `sigma_proof_event.py`, none of which downloads
anything).

So the importer is built and exercised against **first-party** correlation
documents hand-authored in the upstream format under
`detections/sigma-correlations/`, four accepted and two refused. The figure
they contribute is first-party content and is labelled that way in the truth
table and in the corpus README; it is not imported coverage. Vendoring the
upstream correlation corpus needs a fetcher and a licence review, and is not
attempted here.

One standard is weaker here than for the stateless Sigma imports, and stays
weaker: those are replayed through the real connector `normalize()` by an
out-of-process worker, and these are replayed through the real **windowed
engine** only. The connector step is not applied, because importing
`services/connectors` into a fusion test process shadows fusion's own `app`
package — the documented reason `compile_sigma_ruleset.py` uses a subprocess.
Instead, every selector field, `group-by` and `distinct_by` is checked
against the emitted-field namespace with **no ceiling**, which caught three
invented fields on the first run of the gate.

### D11 -- ASN novelty is not reachable from the detection match namespace

Depth 6.5's first rule is *"a provider key created or used from a new ASN"*.
The ASN exists: `activity.Project` computes `location.asn` and `location.as_org`
onto the **OCSF event**. The detection matcher reads a different namespace —
`DetectionEngine._raw_fields`, which is the connector's own payload merged with
`raw_event` — and nothing copies the projection into it.

Three options, and why the third was taken. Copying the projection into the
match namespace is a change to what every one of the 2,515 loaded rules sees,
for one rule. Adding ASN lookup to the connector means shipping a geo database
into `services/connectors`. So the rule keys on a new source **address**
instead, and says so in its name (`ai-provider-key-from-new-source`) and in its
description.

That is weaker than the plan asks for: an attacker on the same ASN as the
tenant's own egress raises nothing. It is recorded here rather than closed with
an ASN-shaped field that would actually hold an address, which is the
substitution `first_seen.py`'s own docstring refuses for `domain_age_days`.

## Phase 1: Verdict quality you can publish

- [x] **1.1** Balanced, labelled verdict corpus
- [x] **1.2** Scorecard: balanced accuracy, MCC, per-class precision/recall,
  Wilson interval, false negatives, auto-close precision, escalation rate,
  time to verdict
- [x] **1.3** Close `fake_tool_output` structurally (≤ 0.10 tuned and held-out)
- [ ] **1.4** A 7--8B local model in the matrix, chosen by score
- [ ] **1.5** `make replay-eval` design-partner kit
- [ ] **1.6** Published "Verdict quality" table with a `--check` drift gate

## Phase 2: A semantic layer and live posture

- [x] **2.1** OCSF classes beyond five
- [x] **2.2** Activity projection on every event
- [x] **2.3** Event classification catalogue
- [ ] **2.4** Sessions per principal
- [ ] **2.5** `__posture_snapshot__` collectors (AWS, Azure, GCP, Workspace, GitHub)
- [ ] **2.6** Use the posture everywhere
- [ ] **2.7** Entity context in CORE (ADR first)

## Phase 3: Detection depth for cloud, identity and SaaS

- [x] **3.1** Translate the 74 windowed `det-*` rules — 50 translated, 24
  refused with a reason. `MAX_UNREACHABLE` 119 → 45.
- [x] **3.2** Ordered sequences and Sigma correlations — the windowed engine
  stages ordered and unordered sequences; all four translatable Sigma
- [ ] **3.2** Ordered sequences and Sigma correlations
- [ ] **3.3** Enrichment inputs (parity 5.5)
- [ ] **3.4** Behavioural baselines in CORE
- [ ] **3.5** Threat-and-anomaly condition rules
- [ ] **3.6** 395 → at least 800 cloud, identity, SaaS and code conditions
- [ ] **3.7** Detection engineering agent (gap-closure Phase 9 / parity 6.2)

## Phase 4: Collection and scale

- [ ] **4.1** Cloud-native collection (S3+SQS org trail, Pub/Sub, Event Hubs)
- [~] **4.2** Standard inputs (syslog, OTLP, Kafka, TAXII 2.1). **One of
  four bullets closed.** The syslog listener is done: `services/ingest`
  accepts UDP and TCP and reads RFC 5424, RFC 3164, CEF and LEEF, with the
  tenant taken from a minted token because syslog carries nothing a sender
  does not control. Gated by `scripts/check_syslog_listener.py` (self-test:
  one injected violation per rule, including each of the three Go syntaxes
  a tenant could leak through) wired into `ci.yml :: python-lint`. 33 new
  Go tests. **Three bullets are open and were not attempted**, named here
  rather than left to be inferred: an OTLP logs receiver, a Kafka input for
  customer topics, and a TAXII 2.1 server over the tenant IOC store. Each
  reproduces trivially — nothing in the tree implements any of them.
- [x] **4.1** Cloud-native collection (S3+SQS org trail, Pub/Sub, Event Hubs).
  Three connectors (`aws_cloudtrail_s3`, `gcp_pubsub`, `azure_event_hubs`),
  each resumable and each declaring a bounded `collection_budget` that says
  where the overflow goes. Gated by
  `scripts/check_cloud_native_collection.py` (self-test: one injected
  violation per rule, plus a refusal on both an absent and an empty tree),
  wired into `ci.yml :: python-lint`. 83 new tests, connectors suite 1014 ->
  1098. **One verification gap, stated rather than buried:** no Azure
  subscription is reachable from here, so the Event Hubs capture fixture was
  synthesised from the Avro specification rather than recorded from a live
  hub, and the Data Lake Gen2 listing path has never run against a real
  storage account. The claim row is `PARTIAL` for exactly that reason.
- [ ] **4.2** Standard inputs (syslog, OTLP, Kafka, TAXII 2.1)
- [~] **4.3** Retention the tenant chooses. **Two of three bullets
  closed.** The lake TTL is now a 400-day ceiling rather than a fixed 90
  days, in `001_init.sql`, in the tiering DELETE and in a `MODIFY TTL`
  migration so an existing volume converges; `MAX_LAKE_DAYS` bounds what a
  tenant may choose and the three numbers are held equal. Legal hold now
  blocks the purge, through `may_purge` so the decision has one home, with
  unreadable hold evidence withholding rather than proceeding, and the run
  reporting what it withheld. Gated by
  `scripts/check_retention_window.py` (self-test: eight injected
  violations, one per rule) wired into `ci.yml :: python-lint`. 13 new
  tests, api suite 4,569 -> 4,582.

  **Open, and not attempted:** the third bullet — a cold-data query through
  `/lake/sql` or a hunt reporting an estimated cost and a progress state
  instead of timing out silently. `/lake/sql`'s `cost` today is a
  rate-limit token price, not a scan estimate, and there is no progress
  state at all.

  **Two limits on what is closed**, recorded rather than left to be found:
  the lake half is gated statically — no test in CI watches a row survive
  past day 90 on a real ClickHouse, so what is proven is that the numbers
  agree and the migration exists; and a hold stops the whole tenant's sweep
  rather than only its own subjects, because both purges are bulk
  statements. Narrowing that needs a per-subject predicate on each store
  and is follow-up.
- [ ] **4.4** Throughput (parity 6.9) and a cloud-hardware run
- [ ] **4.5** Deployment completeness (parity 6.8)

## Phase 5: Response that finishes

- [x] **5.1** Steps that act (parity 5.3)
- [x] **5.2** Delivery (parity 5.7)
- [x] **5.3** `wait`, `parallel`, `loop` with idempotency keys
- [ ] **5.4** Stateful user and manager verification
- [ ] **5.5** Executor arms 74 → at least 150
- [ ] **5.6** Plain-language playbooks

## Phase 6: AI agent security

- [x] **6.1** AI asset inventory. Reproduced:
  `scripts/check_ai_asset_inventory.py` on the unmodified tree reported nine
  problems across five of its eight rules — no migration creates the table,
  no model maps it, no route reads it, no writer exists, and the graph
  vocabulary has no label for an AI asset. Implemented `aisoc_ai_assets`
  (migration `110`, tenant-scoped, `FORCE ROW LEVEL SECURITY`, granted to
  `aisoc_app`), the ORM model, `GET /ai-assets`, `GET /ai-assets/{id}` and
  `POST /ai-assets/{id}/sanction` behind a new `ai_estate:read` /
  `ai_estate:write` pair held by five roles and mintable into an API key,
  `AiAssetRecorder` in the fusion consumer's raw-events branch, the `AIAsset`
  graph label with `OPERATES` and `HOSTS` edges emitted at ingest (schema
  `v1.2 -> v1.3`), and the `/ai-estate` console page. 21 new fusion tests
  (suite 662 -> 683), 8 new Go tests in `internal/graph`, 5 live-Postgres
  cases in `tests/isolation/test_ai_estate_live.py`.

  **The writer is the whole item**, and the gate says so rather than the
  prose: the `WRITER` rule requires the consumer to call the recorder *and*
  `main.py` to construct it, because an unconstructed recorder is a `None`
  every call site skips in silence and the page would render "no AI estate"
  to a tenant that has one — the second half of this repository's recurring
  defect, the half module reachability cannot see.

  Two negative controls, both re-injecting a real defect rather than an
  invented one, both run against a real PostgreSQL 16 with every migration
  applied and the suite connected as the DML-only `aisoc_app` role: reverting
  the identity constraint from `UNIQUE NULLS NOT DISTINCT` to plain `UNIQUE`
  turns one provider-key row into **three**, each claiming to be first seen
  now (measured, not predicted — a provider key has no device, so under the
  default NULL semantics every sighting inserts); and a tenant policy of
  `USING (true)` lets tenant A read tenant B's estate. Each fails the suite
  and each is a step in `ai-estate-live.yml`. The gate's own self-test
  injects one violation per rule and found two blind spots in the gate while
  being written — it read its own component's docstring as a fabrication, and
  a `NodeAIAsset,` substring match would have passed on a commented-out
  `// NodeAIAsset,`.

  **Two limits, stated rather than left to be found.** Phase 2.5 is open, so
  `effective_permissions` is a column with a resolver behind it and nothing
  writing it yet; the risk scorer returns `False` for an absent snapshot
  rather than treating unknown as privileged, and the console says in words
  that permissions did not contribute. And the three discovery sources see
  genuinely different things — runtime telemetry never carries a device, a
  provider audit log never carries either — so `discovery_source` is stored
  per row and the page prints what each source can and cannot see, because
  an unlinked device and an unlinkable one are different facts.
- [x] **6.2** Endpoint discovery with no new agent. Reproduced:
  `services/fusion/tests/test_ai_endpoint_discovery.py` was written first and
  **13 of its 16 cases failed** on the tree as 6.1 left it, driving payloads
  in the shapes `windows_event`, `auditd`, `fleetdm` and `osctrl` actually
  emit — read out of each connector's own `normalize()` rather than invented.

  **The root cause is the one this repository keeps paying for, in its second
  form.** 6.1's endpoint branch read `process.name` off the OCSF event. The
  canonical OCSF profile maps `title`, `external_id` and the identity aliases
  and *nothing else*; all four endpoint connectors put their process fields in
  the connector payload, which `services/ingest` stores as a JSON string under
  `raw_data`. So the branch resolved `None` on every real source and could
  never have produced one row — and its own unit tests passed throughout,
  because they built events in the shape the module expected. The recorder now
  reconstructs the same flat namespace `DetectionEngine._raw_fields` does, and
  `PROCESS_FIELDS` / `COMMAND_LINE_FIELDS` name each connector's own spelling.

  Built: `packs/aisoc-ai-estate.yaml` (5 queries — coding-agent processes, MCP
  server processes, MCP client configuration files, AI IDE extensions,
  provider key files; loaded through the real `pack_loader`, 5 packs -> 6),
  `SOURCE_CAPABILITIES` declaring what each of the five discovery sources sees
  *and* cannot see, `apps/docs/docs/concepts/ai-estate-discovery.md`, and
  `scripts/check_ai_endpoint_discovery.py` (6 rules, self-test injects one
  violation each). Fusion suite 683 -> 700.

  Negative controls: an ordinary process (`falcon-sensor`, `osqueryd`,
  `nginx`, `chrome`, `MsMpEng.exe`, `node`), an unrelated IDE extension
  (`esbenp.prettier-vscode`) and an unrelated `package.json` each produce no
  asset, and an endpoint sighting is asserted to carry no model or provider —
  because filling those from a default would make the inventory assert
  something no source observed. The gate's own self-test re-injects the
  original defect (`fields = _connector_fields(ocsf)` -> `fields = dict(ocsf)`)
  and requires NAMESPACE to catch it; writing it found the same
  read-your-own-docstring blind spot a second time, now fixed by stripping the
  docstring before matching.

  **Honest limit, and the reason the claim row is PARTIAL:** `crowdstrike`,
  `sentinelone` and `azure_defender` poll the vendor's own **detections**, not
  process telemetry — `crowdstrike.py` reads `/detects/queries/detects/v1` —
  so they cannot supply a process start, and the plan's wording that endpoint
  discovery comes from them is not satisfiable with the connectors this tree
  has. The documentation says so in a callout rather than leaving a reader to
  assume their EDR covers it. Separately, no osquery agent runs in CI: the
  pack is asserted to load and to select the columns the recorder reads, but
  no test has watched a real `osqueryd` execute one of its queries.
- [x] **6.3** Provider coverage beyond OpenAI and Anthropic. Reproduced:
  `check_ai_provider_coverage.py` on the pre-change tree reported five of the
  seven providers absent from `PROVIDERS`, from the console's select and from
  the documentation. `llm_usage` accepted exactly two values and raised
  `ValueError` on anything else.

  Built: `google_workspace_gemini`, `google_workspace_oauth`, `m365_copilot`,
  `entra_consent` and `github_copilot`, each with its own credential shape,
  its own request parameters and its own normalisation. **Every endpoint was
  fetched from the vendor's current published reference before it was used**
  — the Workspace Gemini and token appendices, the Purview Copilot audit
  record reference, the Office 365 Management Activity API reference, the
  Graph `directoryAudits` reference and the GitHub Copilot user-management
  reference. 15 new tests (connectors suite 1,126 -> 1,141), each driving the
  real HTTP path and asserting the **recorded request** as well as the parsed
  result.

  Three findings that only came from reading the references: the Microsoft
  content endpoint returns blob references rather than records, so a reader
  that normalised the reference list would report "no Copilot activity" on a
  busy tenant; `AIAppInteraction` is Microsoft's own term for a third-party AI
  app the organisation has *not* deployed, which is the most interesting row
  in the stream and the one a `RecordType == "CopilotInteraction"` filter
  would drop; and `app_name` means the third-party application on the
  Workspace token stream but the Workspace *surface* (gmail, docs) on the
  Gemini stream, so folding them loses one.

  **The claim this item must not make, and the gate that stops it.** No hosted
  provider has ever been exercised from this repository and that is still
  true. `check_ai_provider_coverage.py`'s HONESTY rule requires every provider
  to carry `not measured` **on its own documentation table row** — a single
  footnote covering seven lets one quietly become "verified" — and fails on a
  `0.000` anywhere in that table, because a zero reads as graded-and-failed
  where nobody ran it at all. The claim row is PARTIAL for exactly that
  reason and returns to GATED one provider at a time.

  Writing the gate found two defects in the gate itself, both the same class:
  `ast.unparse` renders string literals with single quotes whatever the source
  used, so a double-quoted-only check reported all seven providers missing from
  a schema that listed them; and a denial is not a claim, so the overclaim
  check flagged the page's own caution title. Both are covered by injections.- [ ] **6.3** Provider coverage beyond OpenAI and Anthropic
- [ ] **6.4** Agent identity and baselines (parity 6.7)
- [x] **6.5** AI rule pack. Reproduced: of the seven abuses the plan names,
  the corpus detected **none**. The eight existing `ai-*` rules all fire on a
  `finding_type` a guardrail already decided; nothing matched on novelty, on
  approval, on a command-line flag, or on a rate.

  Built four stateless rules (`ai-provider-key-from-new-source`,
  `ai-agent-new-high-risk-tool`, `ai-mcp-server-unvetted`,
  `ai-coding-agent-prompts-disabled`) and three windowed
  (`wd-ai-guardrail-violation-rise`, `wd-ai-token-spend-burst`,
  `wd-ai-oauth-app-bulk-access`). **Executable 2,511 → 2,515; windowed 72 →
  75; on disk 6,991 → 6,995.** 22 new fusion tests (suite 700 → 722). Strict
  fixture replay: 6,995 validated, 0 failed.

  **Every fixture is hand-authored, which is the point of the item.** The
  generator's `build_negative` inverts a clause by prefixing `not-` to the
  expected value, and 423 of the corpus's 878 negatives are that shape: a
  rule passes by failing to match a string no source emits. These negatives
  are events a real AI estate produces every day — the same key action from a
  familiar address, the same agent calling the tool it calls hourly, the
  approved MCP server, the same agent started without the flag — and each
  inverts **the clause the rule is about**. A test refuses a pair differing in
  more than that, and it fired during authoring: the MCP negative also changed
  the tool name, which would have made a pass unattributable.

  Three new reachable fields rather than rules that cannot fire, all gated by
  `check_detection_fields.py`: `source_ip_seen_before`, a **composite**
  `agent_tool_seen_before` (the pair is the subject; either half alone answers
  a weaker question), and two per-tenant allowlists. Each contributes no key
  when unconfigured, so a `not_in_allowlist` clause cannot flip true on
  absence — the Sigma-import failure this corpus already recorded once.

  **One deviation, recorded rather than closed with a substitute.** The plan
  asks for a provider key used from a new **ASN**. The activity projection
  computes `location.asn` onto the OCSF event, and the detection match
  namespace is the *connector payload*, so ASN is not reachable there. The
  rule keys on a new source **address** instead and says so in its name and
  description; closing it with a plausible-looking ASN substitute would be the
  dishonesty the corpus's own first-seen module docstring warns about. See
  D11.
- [ ] **6.6** AI containment and kill-switch

## Phase 7: Phishing operations

- [ ] **7.1** Intake to purge (gap-closure Phase 10 / parity 6.4)
- [ ] **7.2** Header, URL and attachment analysis
- [ ] **7.3** Adversary-in-the-middle session reuse

## Phase 8: Enterprise gates

- [ ] **8.1** Identity and administration
- [x] **8.2** ABAC, elevation and workload identities
- [x] **8.3** Buyer security pack

## Phase 9: Analyst surfaces

- [ ] **9.1** MCP over streamable HTTP (parity 6.6)
- [ ] **9.2** Semantic memory (parity 6.5)
- [ ] **9.3** Case depth (parity 5.6 remainder)
- [ ] **9.4** War rooms
- [ ] **9.5** Hunt to report
- [ ] **9.6** Native responder

## Phase 10: Close the books

- [ ] **10** Re-run touched claim rows, update sibling progress files, one
  `[Unreleased]` entry per phase, final report here

## Item log

| Date | Item | What happened |
|---|---|---|
| 2026-10-07 | 0.1 | This file created at base commit `1b8bc2d4`. |
| 2026-10-07 | 0.2 | Every figure re-derived. Two matched exactly (detections, unreachable families); executor arms measured 74 against a captured 73; the cloud/identity/SaaS/code figure measured 395 against a captured 461 on a grouping the plan does not pin, recorded above. Two measurement caveats found: executable and quarantined overlap by 1,724 rules, and the "69% Windows" figure does not reproduce from the index. |
| 2026-10-09 | 4.3 | Reproduced: `check_retention_window.py` on the unmodified tree reported six problems — the lake deleting at 90 days against a 3,650-day cap, no `MODIFY TTL` migration, tiering deleting at 90, and the purge worker calling neither `alerts_under_legal_hold` nor `may_purge` and reporting nothing withheld. Fixed all but the cold-query bullet. Four negative controls recorded in the PR, including the positive control: a purge stuck closed withholds every tenant and fails four of the eight hold tests, which is the only thing that separates a working control from commendable caution. One pre-existing test (`test_storage_tiering.py`) pinned the 90-day tiering DELETE and now reads the shared constant; `test_retention_worker.py`'s session double could not answer the new holds query, so the worker failed closed and five of its cases failed — the double was taught the query rather than the fail-closed behaviour relaxed. |
| 2026-10-09 | 4.2 | Reproduced: `check_syslog_listener.py` against `origin/main` reported "no Go sources under services/ingest/internal/syslog", and the only syslog path was `POST /v1/inbox/cef`, which needs a forwarder that already speaks HTTP. Implemented `services/ingest/internal/syslog` (UDP + TCP, both RFC 6587 framings, four wire formats, token-derived tenant, batched publish, `/readyz` subscription). Five negative controls recorded in the PR; one of them found a hole in the new gate itself, which reported OK while the tenant came from `msg.Hostname` through a struct field — the detector now knows all three Go syntaxes and the self-test exercises each. Writing the tests also found a shutdown deadlock: `Stop` waited on goroutines watching a context the caller had not cancelled yet. Ingest suite green, `internal/syslog` 33 cases. |
| 2026-10-07 | 0.3 | `make up` and `make smoke` (10/10) pass. Injection suite and load-harness baselines committed. `make up-full` deferred (D2) and hosted model rows blocked (D3). Fixing D1 was a precondition for the load-harness baseline. |
| 2026-10-09 | 3.3 | Identity privilege (18 rules) and a per-tenant first-seen store (2) built; 5 rules were never unreachable (gate operator drift, D9); 18 retired with a reason (D10). `MAX_UNREACHABLE` 45 → 2, the two remaining both needing the 3.4 baseline. Two matcher operators three shipped rules already used were implemented. |
| 2026-10-09 | 3.2 | Ordered and unordered sequences in the windowed engine; all four translatable Sigma correlation types compile, seven refusal reasons recorded. No upstream correlation rule exists in this tree to import (D8), so the corpus is first-party and labelled as such. |
| 2026-10-09 | 4.1 | Reproduced: `check_cloud_native_collection.py` on the unmodified tree reported all three collection paths absent. Implemented `aws_cloudtrail_s3` (SQS-notified S3 objects; management events, data events and VPC flow logs; delete-after-emit), `gcp_pubsub` (REST pull on a log-sink subscription; ack-after-read) and `azure_event_hubs` (Capture blobs over the Data Lake Gen2 JSON API, with a focused Avro OCF reader). Negative controls recorded in the PR: deleting the SQS message before the object is read, acknowledging the Pub/Sub batch before it is built, ignoring the Avro union branch index, and ignoring the flow-log header line each fail a named test, and all were restored. Connectors suite 1014 -> 1098 passed. |
| 2026-10-11 | 6.5 | Reproduced: none of the seven abuses the plan names was detectable — the eight existing `ai-*` rules all fire on a `finding_type` a guardrail already decided. Added four stateless and three windowed rules with hand-authored fixtures on both sides. Executable 2,511 → 2,515, windowed 72 → 75, fusion suite 700 → 722, strict replay 6,995 validated / 0 failed. The attributability test fired during authoring and tightened one negative. One deviation recorded (D11): ASN novelty is not reachable from the match namespace, so the rule keys on a new source address and says so. |
| 2026-10-11 | 6.3 | Reproduced: five of seven providers absent. Added Gemini in Workspace, Workspace OAuth grants, M365 Copilot, Entra consent and GitHub Copilot, every endpoint fetched from the vendor's current reference first. 15 new tests asserting the request shape as well as the result; connectors suite 1,126 -> 1,141. Three findings from reading the references (blob references not records; `AIAppInteraction` is Microsoft's own word for undeployed third-party AI; `app_name` means two things across the two Google streams). PARTIAL: no funded account exists with any of the seven, recorded per provider as `not measured` rather than as a zero. |
| 2026-10-11 | 6.2 | Reproduced: 13 of 16 new cases failed, driving the shapes the four endpoint connectors actually emit. Root cause was 6.1's endpoint branch reading `process.name` off OCSF, which the canonical profile never populates — it found `None` on every real source while its own tests passed. Fixed by reconstructing the connector namespace. Shipped the osquery pack (5 queries, packs 5 -> 6), the source-capability table, the operator doc and a 6-rule gate. Fusion suite 683 -> 700. Claim row is PARTIAL: no osquery agent runs in CI, and the EDR connectors return vendor detections rather than process telemetry, so the plan's "CrowdStrike, Defender, SentinelOne" wording is not satisfiable with these connectors. |
| 2026-10-11 | 6.1 | Reproduced: the new gate reported nine problems across five of eight rules on the unmodified tree. Built `aisoc_ai_assets` (migration 105), its routes behind a new `ai_estate:*` permission pair, the fusion recorder that writes it on the default profile, the `AIAsset` graph label with `OPERATES`/`HOSTS` edges, and the `/ai-estate` page. Two negative controls against a real PostgreSQL: reverting `NULLS NOT DISTINCT` turns one provider-key row into three, and a `USING (true)` policy leaks across tenants. Claim matrix 302 -> 303 rows, 300 GATED. Writing the gate found two blind spots in the gate itself. || 2026-10-11 | 6.1 | Reproduced: the new gate reported nine problems across five of eight rules on the unmodified tree. Built `aisoc_ai_assets` (migration 110), its routes behind a new `ai_estate:*` permission pair, the fusion recorder that writes it on the default profile, the `AIAsset` graph label with `OPERATES`/`HOSTS` edges, and the `/ai-estate` page. Two negative controls against a real PostgreSQL: reverting `NULLS NOT DISTINCT` turns one provider-key row into three, and a `USING (true)` policy leaks across tenants. Claim matrix 302 -> 303 rows, 300 GATED. Writing the gate found two blind spots in the gate itself. |
| 2026-10-09 | 3.1 | All 74 decided. 50 translated into `wd-*` rules derived from each original's own clauses and replayed through the real engine (162 assertions); 24 refused with a reason across five kinds. `MAX_UNREACHABLE` 119 → 45, published executable 2,603 → 2,529, windowed 18 → 68. Three findings recorded as D4–D6 below. |
