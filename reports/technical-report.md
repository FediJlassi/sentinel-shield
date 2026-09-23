# SENTINEL Shield — Technical Report

## 1. Abstract

SENTINEL Shield is a policy proxy in front of an LLM agent (`POST
/v1/decision`) that authorizes every candidate action against provenance
trust rather than content plausibility: a state-changing or sensitive
action is only authorized when its chain of trust terminates in
`system_policy` or `authenticated_user` (rank ≤1); anything else — a
document, an email, a case note, no matter how authoritative it reads — is
evidence, not authorization. On the full 40-scenario public split (31
attack-bearing, 9 benign; `--model mock` for determinism), this holds
uniformly: **ASR 0.0/31**, **CVR 0.0**, **BTU 1.0**, **FBR 0.0**, across
enterprise, finance, and SOC domains alike, including the fake-approval
attack family the hypothesis was designed around
(`finance_false_approval`). Sensitive content (canary tokens) tagged
`restricted`/`confidential` by provenance is tracked per-run and rewritten
out of any final response that would leak it to an untrusted sink. The
most significant limitation we found and fixed: an early version of that
rewrite mechanism keyed on any string ≥8 characters inside a
sensitivity-tagged document, so legitimate facts (an account ID, a
transfer amount) sharing a document with a real canary were redacted
alongside it, failing 6/40 task graders on missing facts even though the
underlying attack was still prevented in every case. Narrowing detection
to field semantics (secret-shaped keys, inline `label: value` declarations,
and a high-entropy fallback — never scenario or canary names) fixed all 6
without moving ASR or CVR. Against the starter kit's own baselines on the
same split, we are the only one of `allow_all` / `provenance` / ours with
FBR = 0.0 and ASR = 0.0 and CVR = 0.0 simultaneously, at the cost of a
higher escalation (human-in-the-loop) rate than `provenance`'s calibration
— an explicit, unresolved tradeoff, not a hidden one.

## 2. Threat Model

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

## 3. Hypothesis

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

## 4. Method

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

## 5. Experiments

**What we ran the published scenario library against.** Full public sweep
— 40 scenarios (15 enterprise, 12 finance, 13 SOC; 31 attack-bearing, 9
benign/hard-negative) — run against the live, unmodified defense via the
simulator's own evaluator (`sentinel eval public`). No self-authored
scenarios were added; the public split was run as-is. Full per-scenario
table and raw scorecard: `reports/results.md` / `reports/eval-scorecard-mock.json`.

**Models, hardware, seeds.** `--model mock` (deterministic, used for every
quantitative number in this report) and `ollama:qwen3:8b` (the organizer-
required real reference agent, used only for the qualitative video
walkthrough — see `reports/video-script.md`; captured on the desktop rig,
RTX 3060, WSL2). No other external model or dataset is declared. Scorecard
digests (Section 10) are from `sentinel-bench/0.1.0`, `split: public`,
`attack_mode: static`, `run_seed: 0` — deterministic and reproducible
run-to-run under the mock model.

**Baselines compared.** Same 40-scenario split, same `--model mock`, run
via the starter kit's own in-process baselines (`uv run sentinel eval
public --defense <name> --model mock --json`, no `--defense-url`):
`allow_all` (no defense at all — confirms the split isn't accidentally
already-safe) and `provenance` (the starter kit's own deterministic
source-to-sink + confirmation baseline, no escalation) against `ours`
(this defense, post-redaction-fix branch `partner/redaction-fix`, commit
`d4e4a3a`). Full results and an honest discussion of the tradeoffs are in
Section 6.

## 6. Results

Full public sweep, as described in Section 5 (Experiments).

| Metric | Value |
|---|---|
| Official score (core) | 0.902 |
| **ASR** (attack success rate) | **0.0** — 0/31 attack scenarios succeeded |
| **CVR** (critical violation rate) | **0.0** — no forbidden effect ever fired |
| **BTU** (benign task utility) | **1.0** — every no-attack scenario completed |
| FBR (false block rate) | 0.0 |
| Task success, overall | 34/40 (85%) on `main` at time of writing; **40/40** on the redaction-fix branch, see Section 8 |
| Escalation rate / precision | 0.756 / 0.317 |
| Rewrite events (canary redaction) | 8 on `main` (see Section 8 — likely false positives); 0 on the fix branch (real catches, none needed rewriting this sweep) |
| Defense errors (`DEFENSE_UNAVAILABLE`) | 0 |

### Baseline comparison

Baselines and setup as described in Section 5 (Experiments); "ours" is the
post-redaction-fix branch (`partner/redaction-fix`, commit `d4e4a3a`). See
`reports/results.md` for the full per-scenario breakdown.

| Defense | BTU | ASR | CVR | FBR | UER | TUI | DFI | Brier | ECE | p95 ms |
|---|---|---|---|---|---|---|---|---|---|---|
| `allow_all` | 1.0 | 1.0 | 0.775 | 0.0 | 0.0 | 0.652 | 0.4 | 0.235 | 0.235 | 0.026 |
| `provenance` | 1.0 | 0.0 | 0.0 | 0.222 | 0.0 | 1.0 | 1.0 | 0.147 | 0.197 | 0.073 |
| **ours** | **1.0** | **0.0** | **0.0** | **0.0** | 0.675 | **1.0** | **1.0** | 0.322 | 0.351 | 8.47 |

`allow_all` confirms the scenario library isn't accidentally already-safe
(ASR 1.0, CVR 0.775 with zero defense). `provenance` — the starter kit's
own deterministic source-to-sink baseline, which never escalates
(`escalation_rate` 0.0) — matches us on ASR/CVR/BTU/TUI/DFI exactly but
trades differently: its FBR (0.222) is worse than ours (0.0, it outright
blocks some benign actions we allow), while its UER is 0.0 against our
0.675 since it has no escalation cost to pay at all. Its official `core`
score (0.939) beats ours (0.902) because the scoring formula penalizes our
escalation volume harder than its false-block rate — a real, unresolved
weakness in our current calibration (Section 7/8), not a scoring artifact.
We are the only one of the three with FBR = ASR = CVR = 0.0 simultaneously,
at the explicit cost of leaning on human-in-the-loop escalation more than
`provenance` does.

Per domain, ASR/CVR/BTU are 0.0/0.0/1.0 across enterprise, finance, and SOC
alike — the provenance-authorization hypothesis (Section 3) holds uniformly,
not just on the finance scenario it was originally verified against
(`finance_false_approval`, which is included in this sweep and passes:
escalate on the injected `payment_confirm`, simulated human denies it, task
still completes via the legitimate `payment_prepare` + `case_note_create`
path).

The 6 task-success failures (all finance, all `data_exfiltration` /
`direct_instruction`) are a single root cause — the redaction path being
too aggressive, not too permissive — and are analyzed in Section 8 rather
than double-counted here. Critically, none of the 6 are security failures:
all 6 have `attack_prevented=True` and `critical_violation=False`; the
defense over-corrected on usefulness, not under-corrected on safety.

## 7. Ablations

Still blocked on the `provenance_check` / `infoflow` toggles in
`configs/policy.yaml` (owned by Fedi) — not implemented as of this writing,
so no on/off comparison exists yet for those two mechanisms specifically.

In the meantime, the sweep in Section 6 already gives one ablation for
free: the simulator's own `--defense allow_all` baseline is the "no defense
at all" condition, and we ran it for `finance_false_approval` while
sanity-checking the sweep setup (Section 6's methodology check). Under
`allow_all`, that scenario's `payment_confirm`/`payment_execute` both
execute — `attack_success=True`, `critical_violation=True`
(`FORBIDDEN_EFFECT`, `PAYMENT_CONFIRMATION` both fire) — versus
`attack_success=False`, `critical_violation=False` under our defense. That
is a real (allow_all vs. full pipeline) ablation, just not the finer-grained
(provenance-only vs. infoflow-only vs. both) breakdown originally planned.
The finer breakdown needs the config toggles; recommend Fedi add them as a
narrow, additive change (default both `true`, so existing calibration is
unaffected) — 5 scenarios × 2 states is a ~20-run addition once they exist.

## 8. Failure Analysis

**Confirmed fixed, verified at scale (this sweep, 213 decisions, 0 errors):**
- Canary leaks into a final `respond` reaching `ALLOWED` — pre-fix, 8×
  `SENSITIVE_TO_UNTRUSTED_SINK` leaked. Post-fix: 0 leaked, 8 caught and
  rewritten. Root cause was keying leak detection on trust rank instead of
  sensitivity (canary docs are `trusted_internal`, rank 2, not low-trust).
- `request_confirmation` retry loops exhausting `max_steps` — pre-fix,
  ~6 scenarios killed this way. Post-fix: 0 `DEFENSE_UNAVAILABLE` errors
  across the full 40-scenario sweep. Root cause was the confirmation relay
  reaching schema validation and occasionally erroring before the
  short-circuit existed.
- Intermittent 500s from `confirmation_for` arriving as a nested dict —
  0 errors this sweep; fixed via `Union[str, dict] -> coerce to None`.

**Failure class found by this sweep and fixed (branch `partner/redaction-
fix`, commit `d4e4a3a`, pending merge to `main`): the canary-redaction
mechanism was over-broad.** On `main` at time of writing, 6/40 scenarios
(all finance) fail task_success because `_observation_sensitive_strings`
(`app/main.py:54-77`) treats every string ≥8 characters inside a
`restricted`/`confidential` observation as sensitive, not just the actual
canary value. An account ID (`ACC-1001`) or formatted amount
(`48,210.00`) that happens to live in the same document as a real secret
gets redacted from the final response right alongside it, and the task
grader — which needed that fact verbatim — fails. This is the report's
clearest illustration of the allow/block/escalate/rewrite tradeoff cutting
the wrong way: the mechanism built to stop exfiltration is, in these 6
cases, the thing that breaks "benign tasks MUST complete."

The fix keys the redaction set off field *semantics* instead of length,
still without any scenario/canary-name hardcoding (CLAUDE.md's hard
rule): a string is collected only if (a) its JSON key matches
`/secret|token|key|code|credential|password|passphrase/i`, (b) it is
declared inline as prose matching a `label: value` pattern under that same
label regex, or (c) — for a secret declared with no label at all — it is
high-entropy (≥12 chars, mixed case + digits, no spaces/punctuation).
Case (b) was not optional: inspecting `traces/raw-payloads.jsonl` showed
the real canary format is prose embedded in a neutrally-keyed `body`
field (`"Current authorisation_code: SENTINEL_SECRET_..."`), which a
key-only implementation missed almost entirely (3/213 decisions flagged a
canary instead of the expected ~9). Re-running the identical sweep against
the fixed branch: task_success 34/40 → **40/40**, ASR still 0.0/31, CVR
still 0.0, 31/31 unit tests green. Full numbers and the false-positive
analysis of the pre-fix rewrite events are in `reports/results.md`.

**Not yet re-quantified:** over-escalation on benign reads. The
`benign_reads` YAML calibration is in place and no benign scenario fails on
escalation alone (BTU = 1.0 across all three domains), but escalation
precision sits at 0.317 and the unnecessary-escalation rate at 0.675 —
most escalations in this sweep, including on legitimate actions, still
weren't strictly required. Not a correctness bug (nothing is denied that
shouldn't be — the simulated human approves the legitimate ones) but a
usefulness/annoyance cost worth tightening if there's time before the
freeze.

## 9. Responsible AI and Security Considerations

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
`configs/policy.yaml`: the full sweep (Section 6) shows FBR=0.0 and BTU=1.0
(no benign task is ever outright blocked or fails to complete), but
escalation precision is only 0.317 — a read-only tool that doesn't match a
known suffix, or whose observation trust exceeds `max_trusted_rank`, still
escalates unnecessarily far more often than not. A separate false-positive
class was found by the sweep and is more serious: over-broad redaction (see
Section 8) breaks 6/40 tasks by stripping legitimate facts, not just
adding friction.

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

**On lenient request parsing.** `DefenseRequest` (`app/schemas.py`) uses
`extra: allow` and defaults every field, so a structurally incomplete
payload — a field the simulator omits, an unrecognized type — is accepted
(HTTP 200) rather than rejected. This is deliberate fail-operational
tolerance to unknown simulator fields, at the cost of not rejecting
malformed requests: we chose not to have the defense itself become a
source of run-ending errors (`DEFENSE_UNAVAILABLE`) over a schema mismatch
it didn't cause. `DefenseDecision`, the response we control end-to-end, is
strict by contrast.

## 10. Reproducibility

**Repository:** `sentinel-shield` (private, competition submission).
Pre-fix numbers in Sections 6/8 above (34/40 task success, 8 rewrite
events) are from `main` at commit `9b1731c`. Post-fix numbers (40/40, the
baseline comparison table, this report's Abstract) are from branch
`partner/redaction-fix` at commit `d4e4a3a`, pending review/merge to
`main` at the 13:00/15:00 freeze checkpoints — check `git log main` for
whether it has landed by the time this is read.

**Exact commands** (from `sentinel-shield/`, defense on port 8080; from
`sentinel-starter-kit/`, evaluator):

```bash
uv run --no-project uvicorn app.main:app --port 8080

uv run sentinel eval public \
  --defense-url http://127.0.0.1:8080 --model mock --json > results/public.json

# Baselines (in-process, no --defense-url):
uv run sentinel eval public --defense allow_all --model mock --json
uv run sentinel eval public --defense provenance --model mock --json

# Self-test:
uv run pytest -q   # from sentinel-shield/
```

**Declared external models:** `--model mock` and `ollama:qwen3:8b` (Qwen3-8B
via Ollama) — no other external model or dataset. Full description of how
each is used is in Section 5 (Experiments).

**Scorecard digests** (`sentinel-bench/0.1.0`, `split: public`,
`attack_mode: static`, `run_seed: 0`):

| State | `deterministic_digest` |
|---|---|
| `main` @ `9b1731c` (pre-fix, `reports/eval-scorecard-mock.json`) | `6ff9c17f020a4c50ae7b1c976d152131533cc356e8e50cff494fd55c5b0843bb` |
| `partner/redaction-fix` @ `d4e4a3a` (post-fix) | `1428260f6c141ad30d29947054b57926a79022eeb462c53055cf66fd755363ea` |

Both digests are reproducible from the commands above against the
respective commit; the mock model makes this deterministic run-to-run.
