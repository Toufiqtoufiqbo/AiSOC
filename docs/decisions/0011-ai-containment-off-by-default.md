# 0011. AI-estate containment ships off by default, and two of its four verbs can never be undone

- **Status:** accepted
- **Date:** 2026-10-11
- **Deciders:** AiSOC maintainers
- **Context:** depth plan 6.6

## Context

Depth 6.6 adds the first response verbs AiSOC has that reach a customer's
**model provider account** and **identity directory's application consents**
rather than their endpoints, firewalls or SIEM. Two questions had to be
answered before any of them could be written, and both have been answered the
wrong way elsewhere in this repository's history.

**The first: can this be undone?** The product's capability contract already
models four answers — platform reverse, self-healing, manual-only, none — and
the gate refuses a MODERATE, HIGH or SEVERE verb that declares `MANUAL_ONLY`,
because an action that disrupts a person and leaves no route back is one
somebody has to fix by hand at 3am from a runbook they have not read. But
`unisolate_host`, the rollback for the most disruptive action in the product,
once resolved to nothing: the contract declared a platform reverse and the
verb it named had no executor. A declared reverse that cannot be dispatched is
worse than an honest "none", because the rollback path believes it has a
route.

**The second: should a new reach-out capability be live the day it ships?**
Every containment verb before this one reaches a security product the customer
deliberately connected to AiSOC for that purpose. These reach a billing
relationship with a model vendor and a directory's consent records. A
deployment that upgrades gets them without having decided to.

## Decision

### Four verbs, not three

`revoke_provider_key`, `revoke_oauth_grant`, `block_ai_key_at_gateway` and
`unblock_ai_key_at_gateway`.

The fourth exists because the third declares `Reversal.PLATFORM`. A reverse
capability is only real when it is a first-class verb with its own executor,
its own contract, its own probe and its own place in the vocabulary — anything
less resolves to `executor_not_found` at the exact moment somebody is trying to
undo a containment.

### Two of them are `IRREVERSIBLE` and `MANDATORY_HUMAN`

Not as caution, as fact. OpenAI deletes a key and Anthropic archives one;
neither hands the secret back, so every workload holding it stops until a
replacement is minted and redistributed. A revoked OAuth grant is re-created by
the **user** consenting again, in their own browser, which no API of ours can
perform on their behalf.

`MANDATORY_HUMAN` is an actual floor rather than a high bar: no confidence
score and no autonomy tier may lift it. `revoke_provider_key` additionally
carries `BlastRadius.CRITICAL` rather than `HIGH`, because its subject is not
one person's access — it is every process using that key, including ones
nobody remembers deploying.

### The reversible one is the first move

`block_ai_key_at_gateway` is `SEVERE` with a platform reverse and an `ANALYST`
approval, deliberately a *lower* bar than the two above. It stops every call a
key can make without destroying it, and one request undoes it. That is the
containment to reach for when the verdict is not yet certain, and the only one
of the three an approver can be told has a route back. The kill-switch playbook
orders the steps accordingly: gateway block and process kill first, human
approval next, and the irreversible pair only after that.

### All four are off by default

`AISOC_AI_CONTAINMENT_ENABLED` gates every arm, read at call time rather than
at import so a deployment can enable it without a restart.

When the flag is unset the executors return **`FAILED`, naming the variable** —
not a simulated success. That direction is deliberate and is the lesson from
`NotifySlackExecutor`, which reported `message_sent: true` on a send that never
happened: a containment that reports success while touching nothing is strictly
worse than one that refuses, because the operator stops looking.

### Every verb has a verification probe

The contract rule is unconditional at these impact tiers, and for a key
revocation the distinction is the whole action: a `200` says the vendor
accepted the instruction, not that the key has stopped working. Each probe
re-reads the vendor — key gone or inactive, grant absent from the list, the
gateway's own `blocked` flag — and returns `None` rather than `False` when it
cannot read, because reporting "still active" when nobody knows sends an
operator to repeat a containment during an incident.

## Consequences

- A tenant that has not set `AISOC_AI_CONTAINMENT_ENABLED` sees these verbs in
  the registry and gets a refusal naming the variable if anything dispatches
  one. That is a visible, diagnosable state rather than a silent no-op.
- `irreversible` enters the approval-matrix sweep for the first time. The
  sweep's own test pins the covered impact tiers as an exact set in both
  directions, so a tier joining it is a decision somebody records rather than
  a side effect.
- Google Workspace revokes OAuth grants **per user**, so containing an
  application across a domain is a loop over its grantees. The result says
  which scope was achieved rather than implying the whole tenant, and the
  playbook's own record step says a step whose condition was false did not run.
- The kill-switch playbook ships with `enabled: false`. Arming a
  maximally-disruptive playbook on upgrade would be the same mistake as
  shipping the verbs live, one level up.
- None of the four has been exercised against a funded account with any
  vendor. Every endpoint was read from the provider's current published
  reference and every test drives the real HTTP path against a mock; that is
  verification of the request, not of the effect, and it is recorded that way.
