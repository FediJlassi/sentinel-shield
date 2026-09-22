# SENTINEL Shield — Technical Report

## 1. Threat Model

SENTINEL Shield sits as a policy proxy in front of an LLM agent: every
candidate action the agent wants to take is submitted to `POST
/v1/decision` before it is executed, and the proxy returns one of four
outcomes — allow, block, escalate, rewrite. The threat model covers the
attack families the competition scenarios exercise:

- **Direct prompt injection** — an untrusted party addresses the agent
  directly (e.g. through a user-facing channel) with instructions that
  contradict the authenticated user's actual goal.
- **Indirect prompt injection** — instructions are smuggled inside content
  the agent retrieves as part of its task (a document, an email, a tool
  result) rather than said to it directly. This is the dominant pattern in
  the captured scenarios: a case note, contract, or support ticket contains
  text engineered to look like an approval, a policy update, or a new
  instruction.
- **Multi-step attacks** — the injected instruction and its payoff are
  separated across several tool calls (e.g. `case_document_read` plants a
  fake "already approved" note at step 3, and `payment_confirm` /
  `payment_execute` attempt to cash it in at steps 4-5). A defense that only
  looks at the current step in isolation misses these; SENTINEL persists
  run-scoped state (`app/main.py: run_state`, keyed on `run_id`) and
  consults `history_digest` so the confirmation chain is checked, not just
  the current action.
- **Memory / context poisoning** — the same mechanism as indirect injection,
  but aimed at corrupting the agent's working memory of what has already
  been approved or confirmed, rather than triggering an immediate action.
- **Tool-output tampering** — a tool result is not what it claims to be
  (fabricated data, forged metadata) and is used to justify a subsequent
  action. The defense's answer is provenance-based, not content-based: it
  does not try to detect "this text looks fake," it checks whether the
  *source* of the content is trusted enough to authorize what's being asked.
- **Exfiltration** — sensitive content (a canary token, an account id, a
  contract reference) that entered the run via a `restricted` or
  `confidential` sensitivity-tagged source ends up in the agent's final
  response to an untrusted sink.
- **Over-refusal** — the defense blocks or escalates benign, in-scope work.
  This is treated as a first-class failure mode, not a lesser one: per
  CLAUDE.md, "blocking everything is failure — benign tasks MUST complete."

**Adversary capabilities.** The adversary can control the content of
anything the agent observes that isn't authenticated-user input or system
policy — documents, emails, tool outputs, and (per the verified simulator
contract) content ranked `untrusted_internal` through `adversary_controlled`
(trust ranks 3-5). It can plant multi-step setups, forge the appearance of
approval, and try to exfiltrate sensitive data it has read access to as part
of a legitimate-looking task.

**Adversary limitations.** The adversary cannot forge `system_policy` or
`authenticated_user` provenance (ranks 0-1) — the simulator's trust levels
are asserted by the harness, not claimed by content. It cannot fabricate a
`confirmations_granted` digest, because `action_digest` is computed
byte-for-byte identically to the starter kit and must match what the
simulator itself recorded (`app/policy_engine.py:action_digest`). It cannot
bypass the proxy: every candidate action, including the agent's own
`request_confirmation` calls, passes through `/v1/decision`. And per the
verified contract (docs/contract.md), escalating an injected action to the
simulated human does not help the attacker — `human_confirm` checks the
action against the scenario's actual legitimate plan, not against whatever
the escalated payload claims, so escalation is safe rather than a bypass.

## 2. Hypothesis

**Authorization must trace to rank ≤1 provenance; anything else is
evidence.**

Concretely: a state-changing or sensitive action is only authorized when the
chain of trust behind it terminates in `system_policy` (rank 0) or
`authenticated_user` (rank 1). Content from any other source — a document,
an email, a case note, a prior tool result, regardless of how authoritative
it *sounds* — can inform a decision but can never *authorize* one on its
own. This is the single rule the whole defense is organized around, and it
is why the fake-approval attack family fails structurally rather than
needing to be pattern-matched: the injected "already approved" note is
real, readable content, but its provenance rank (2 or higher) can never
satisfy a confirmation requirement, no matter how it's worded.

The implementation makes this hypothesis observable, not just structural:
whenever a decision is influenced by evidence above rank 1, `decision.py`
appends a `TRUST_RANK_<n>` reason code and an explanation naming the rank
and source type, and states explicitly that "only system_policy or
authenticated_user can authorize sensitive actions" (`app/decision.py`,
compose()). A juror reading the trace does not have to infer the rule from
behavior — it is printed on every relevant decision.

## 3. Method

Architecture as implemented in `app/` (this section describes the code as
it exists today, not the original design notes — see the discrepancies
called out inline):

- **`main.py`** — hosts `POST /v1/decision`. Raw payloads are first appended
  to `traces/raw-payloads.jsonl` for forensic replay, then a short-circuit
  check fires *before any schema parsing*: if `candidate_action.tool` (or
  `.type`) is `request_confirmation`, the proxy returns an instant `allow`
  with `SYSTEM_CONFIRMATION`. This exists because any error at that point
  previously caused an infinite `DefenseUnavailable` retry loop in the
  agent. Sensitive-content tracking and the final-response redaction path
  (`update_run_state`, `scan_respond`, `_leaked`, `_redact`) also live here,
  inline — the architecture notes in CLAUDE.md describe this as a separate
  `infoflow.py` module, but as implemented it is part of `main.py`; there is
  no `app/infoflow.py` file. Tracking is keyed on the provenance
  `sensitivity` field (`restricted` / `confidential`), not trust rank, per
  the verified finding that canary documents are `trusted_internal` (rank
  2) but carry the most dangerous leaks. Only sha256 hashes of sensitive
  strings are ever logged; raw values are held in-process only, per
  `run_id`.
- **`schemas.py`** — `DefenseRequest` is lenient (`extra: allow`) so unknown
  simulator fields never cause a 500; `DefenseDecision` is strict, validated
  against the exact contract (lowercase decision enum, `UPPER_SNAKE_CASE`
  reason codes, ≤16 of them, ≤500-char explanation, `rewritten_action`
  mandatory iff `decision == "rewrite"` and forbidden otherwise).
  `CandidateAction.confirmation_for` accepts `str | dict | None` and coerces
  a dict to `None` at validation time, since the simulator sometimes echoes
  a full copy of the confirmed action rather than a string/null reference.
- **`firewall.py`** — maps `provenance.trust_level` (string name or raw int)
  to a numeric rank 0-5. Anything missing, malformed, out-of-range, or of an
  unexpected type fails closed to rank 5 (`adversary_controlled`), logged as
  a warning rather than silently defaulting to a trusted rank.
  `observation_trust` and `args_trust` take the *max* rank across all
  provenance ids referenced by the observation or found (by id-substring
  match) inside the candidate action's arguments — the least-trusted
  contributor determines the rank, not the most-trusted.
- **`policy_engine.py`** — `action_digest` is copied exactly from the
  starter kit so confirmation digests byte-match what the simulator records
  in `history_digest.confirmations_granted`. `evaluate()` walks
  `policy_context.rules` generically by `kind`: `tool_permission`,
  `requires_confirmation` (with the benign-read carve-out described below),
  `prerequisite` (a prepare→confirm→execute chain check against
  `history_digest.tool_calls`), and `data_flow`/`forbidden_effect`, which
  are explicitly stubbed — they are returned un-triggered with a "evaluator
  not implemented" detail rather than silently dropped, and the same
  pass-through applies to any rule `kind` the engine doesn't recognize at
  all, so future scenario rule kinds fail visibly rather than
  disappearing.
- **`decision.py`** — composes the final outcome from triggered rules and
  trust signals: critical → block; a data-flow violation or
  adversary-controlled evidence (rank 5) on a non-meta action → block; an
  unconfirmed consequential action or a high-severity trigger on a non-meta
  action → escalate; otherwise allow. Meta/system actions (`respond`,
  `request_confirmation`, `ask_user`) are exempted from the block/escalate
  branches so the defense doesn't get in the way of the agent talking, only
  acting. `TRUST_RANK_<n>` codes and explanation text are appended whenever
  observation or argument evidence exceeds rank 1, independent of the final
  decision.
- **`trace.py`** — appends every decision to `traces/run.jsonl` as
  hash-chained JSONL (`prev_hash` = sha256 of the previous line), giving a
  tamper-evident, append-only record that the dashboard (Session 1) reads
  directly.
- **`configs/policy.yaml`** — the tunable surface: `severity_weights` (risk
  contribution per rule severity), `thresholds.escalate_unconfirmed_consequential`,
  and `benign_reads` (suffix list + max trusted rank), which is what
  calibrates read-only tools like `*_lookup`/`*_search` to allow by default
  instead of escalating on every unconfirmed call. As implemented today this
  file does not yet contain the `provenance_check` / `infoflow` ablation
  toggles referenced in the architecture notes and progress log — those
  remain a standing TODO (see Ablations, below).

## 4. Results

*(Placeholder — pending full sweep re-run.)* The most recent captured
results are a partial, pre-fix scenario table in `reports/results.md`
covering a single finance scenario. A full sweep across the 19-scenario set
plus hard negatives, run against the mock model after the three hotfixes
(confirmation-loop short-circuit, canary-leak rewrite, YAML calibration),
is the input this section needs before it can be filled in. This section
will hold: task-success rate, attack-prevention rate, and false-positive
(over-refusal) rate per scenario domain, plus the aggregate numbers judges
will see first.

## 5. Ablations

*(Placeholder.)* Planned per progress.md: `provenance_check` and `infoflow`
toggles in `configs/policy.yaml`, run across 5 representative scenarios ×
2 (on/off), to demonstrate that the fake-approval and canary-exfiltration
attacks succeed against the *un-hardened* baseline and are caught by the
provenance/infoflow logic specifically — isolating what each mechanism
actually contributes rather than crediting the whole pipeline for one
signal. These toggles do not yet exist in `configs/policy.yaml`; adding them
without changing default behavior is a prerequisite for this section.

## 6. Failure Analysis

*(Placeholder — to be drafted from the Results table once it exists.)*
Known, already-diagnosed failure classes from tonight's pre-fix sweep
(progress.md) that this section should account for once re-verified:
canary leaks into a final `respond` reaching `ALLOWED` (root cause:
infoflow keyed on trust rank instead of sensitivity — fixed, needs
re-verification at scale); `request_confirmation` retry loops exhausting
`max_steps` (root cause: the confirmation relay wasn't short-circuited
before schema parsing — fixed, needs re-verification); intermittent 500s
from `confirmation_for` arriving as a nested dict (fixed via coercion);
over-escalation on benign reads (fixed via the `benign_reads` YAML
calibration, but the boundary of what counts as "benign" is itself a
judgment call worth stress-testing further).

## 7. Responsible AI Statement

**What we protect.** State-changing and sensitive actions are gated on
provenance trust, not on content plausibility — an attacker cannot talk
their way past the defense with a convincing-sounding fake approval,
because the rank of *where the words came from* is what's checked, not how
authoritative they sound. Sensitive content (canary tokens, account
identifiers, contract references) tagged `restricted`/`confidential` by
provenance is tracked per-run and redacted from any final response that
would leak it to an untrusted sink, in plain, base64, hex, and reversed
form. Escalation is a genuine human-in-the-loop control, not a rubber
stamp: the simulated human checks the escalated action against the
scenario's actual legitimate plan, so an injected action reaching escalation
is still denied. Every decision is appended to a hash-chained trace, so the
decision record itself is tamper-evident.

**Known false positives.** Before calibration, the defense escalated
benign read-only actions (e.g. `*_lookup`, `*_search`) whenever they lacked
a recorded confirmation, because the raw rule (`requires_confirmation`) does
not distinguish reads from writes on its own. This is mitigated, not
eliminated, by the `benign_reads` suffix/rank carve-out in
`configs/policy.yaml` — a read-only tool that doesn't match a known suffix,
or whose observation trust exceeds `max_trusted_rank`, can still escalate
unnecessarily. This is a calibration surface, not a solved problem, and the
Ablations/Failure Analysis sections above are where we intend to quantify
it once the full sweep is back.

**When humans stay in the loop.** Any consequential action that is missing
a matching confirmation digest, or that triggers a high-severity rule on a
non-meta action, is escalated rather than blocked outright or silently
allowed — the defense treats "we're not sure yet" as a human decision, not
an autonomous one, and per the verified contract that escalation path
cannot be turned into a bypass by an attacker manufacturing the appearance
of approval.

**What we don't claim.** `data_flow` and `forbidden_effect` rule kinds are
explicitly stubbed in `policy_engine.py` — they pass through un-triggered
rather than being silently dropped, but the defense does not yet
independently enforce them beyond the sensitivity-keyed respond-scanning in
`main.py`. We have not independently verified whether the simulator itself
validates `rewritten_action` structure (open item in docs/contract.md); our
own schema enforces it regardless, but that's a defense-side guarantee, not
a verified simulator-side one. The defense's authority is scoped entirely to
what passes through `POST /v1/decision` — any agent action that could
bypass that call is outside what this system can see or stop. Finally, a
missing or malformed `trust_level` fails closed to the most restrictive
rank (`adversary_controlled`) rather than being treated as trusted by
default; this is a deliberate bias toward more escalation/blocking under
uncertainty, and is part of why over-refusal calibration (above) is an
ongoing, not finished, concern.
