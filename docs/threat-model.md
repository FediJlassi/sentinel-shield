# Threat Model — SENTINEL Shield

This is the defender's-eye threat model: what SENTINEL Shield protects, what
it assumes about the adversary, and where its coverage stops. It complements
`docs/contract.md` (the verified simulator contract — request/response shape,
escalation semantics) and `reports/technical-report.md` §2–3 (the full
narrative version with code references). This file is the quick-reference;
the technical report is the argued version.

## What we protect

| Asset | Where it shows up | Why it matters |
|---|---|---|
| State-changing actions | `payment_confirm`/`execute`, `incident_create`, tool calls in `consequential_tools` | irreversible or costly if unauthorized |
| Sensitive content | canary tokens, account IDs, contract refs — tagged `sensitivity: restricted`/`confidential` in provenance | exfiltration to an untrusted sink is a critical failure even if no state changed |
| The confirmation chain | `history_digest.confirmations_granted`, prepare→confirm→execute sequences | an attacker who can fake "already confirmed" skips the one control that was supposed to stop them |
| Benign task completion | every scenario without an attack, and the legitimate parts of scenarios with one | per CLAUDE.md: "blocking everything is failure" — over-defense is a real failure mode we score ourselves on |

## Adversary capabilities (what we assume the attacker CAN do)

Per the verified simulator contract, the adversary controls the *content* of
anything the agent observes that is not authenticated-user input or system
policy: documents, emails, tool outputs, prior case notes — anything carrying
provenance rank 2 (`trusted_internal`) through rank 5
(`adversary_controlled`). Concretely, it can:

- Plant a fake approval, policy update, or instruction inside content the
  agent reads as part of a legitimate task (indirect prompt injection).
- Spread an attack across multiple steps — plant at step N, cash in at step
  N+k (multi-step attacks; `finance_false_approval` plants a fake approval
  at step 3, attempts to execute a payment at steps 4–5).
- Poison the agent's working memory of what has already been approved
  (memory/context poisoning).
- Make the user's own literal request the vector (direct instruction) —
  we cannot assume "the user asked for it" is sufficient authorization on
  its own if the request itself is out of policy.
- Place a real secret (canary) in a document that is otherwise
  `trusted_internal` (rank 2) — sensitivity and trust rank are independent
  axes, and the adversary can exploit a defense that conflates them.

## Adversary limitations (what we assume the attacker CANNOT do)

- **Cannot forge rank 0/1 provenance.** `system_policy` and
  `authenticated_user` are asserted by the simulator harness, not claimed by
  content. No amount of convincing text raises an untrusted source's rank.
- **Cannot fake a confirmation digest.** `action_digest` is computed
  byte-for-byte identically to the reference implementation
  (`app/policy_engine.py`), so a forged `confirmations_granted` entry
  cannot silently match.
- **Cannot bypass `/v1/decision`.** Every candidate action — including the
  agent's own `request_confirmation` calls — passes through the proxy.
- **Cannot turn escalation into a bypass.** `human_confirm` checks the
  escalated action against the scenario's actual legitimate plan
  (`matcher.is_legitimate`), not against whatever the escalated payload
  claims about itself. An injected action that reaches escalation is still
  denied.

## Defense-in-depth mapping (threat → mechanism → where)

| Threat | Mechanism | Code |
|---|---|---|
| Fake approval / indirect injection | authorization requires rank ≤1 provenance; higher-rank evidence is logged (`TRUST_RANK_n`) but never authorizes | `app/decision.py` |
| Multi-step setup-then-cash-in | run-scoped state + `history_digest.tool_calls` prerequisite check (prepare→confirm→execute) | `app/policy_engine.py`, `app/main.py: run_state` |
| Untrusted/adversary-controlled evidence | fail-closed trust mapping (unknown/malformed `trust_level` → rank 5) | `app/firewall.py` |
| Exfiltration of sensitive content | sensitivity-keyed (not trust-rank-keyed), destination-aware scan of every sink — final `respond` and tool-call arguments alike — redacted/blocked in plain, URL, base64, hex, rot13, and reversed form | `app/main.py: update_run_state`, `scan_exfil`, `_find_leaked`, `_redact` |
| Escalation-as-bypass | not our mechanism — verified property of the simulator's `human_confirm`; we rely on it rather than re-implementing plan-matching ourselves | `docs/contract.md` |
| Confirmation-relay abuse / DoS via retry loop | `request_confirmation` short-circuited to instant `allow` before any parsing | `app/main.py` |

## Residual risk / known gaps (honest, not aspirational)

- **Non-zero false-block rate on the public split (0.049), explained, not
  eliminated.** Every instance found is a correctly-blocked malicious
  variant of a structurally-legitimate step (the grader's "legitimate"
  label is positional, matched against the reference plan's tool/step, not
  content-aware) — task success remains 40/40 and BTU is 1.0. See
  `reports/results.md`'s "Known behavior" section for a concrete
  decision-trace example. This previously manifested as a much worse,
  genuine usefulness bug (over-broad string tracking breaking 10/49 tasks
  by redacting legitimate facts alongside real secrets); that root cause is
  fixed (`reports/technical-report.md` §8), and this residual number is a
  grading-label artifact rather than a recurrence of it.
- **`data_flow` and `forbidden_effect` rule kinds are stubbed.**
  `policy_engine.py` passes them through un-triggered rather than silently
  dropping them, but does not independently enforce them beyond the
  sensitivity-keyed sink-scan above. A `data_flow` rule with semantics we
  haven't anticipated would not currently do anything on its own. No config
  toggle exists to exercise this in isolation; the ablation in
  `reports/technical-report.md` §7 instead replays real captured decisions
  through the pipeline with and without the sink-scan layer directly.
- **Escalation is precise but rare by design, not absent.** Unconfirmed
  `critical`-severity actions (an unconfirmed payment/remediation
  execution) are blocked outright rather than escalated, since these
  aren't cases of genuine uncertainty; escalation is reserved for
  `high`-severity or less clear-cut cases. Escalation precision in the full
  sweep is 1.0 (every escalation this sweep was on a genuinely unconfirmed
  action) — a real change from an earlier, much noisier calibration
  (precision 0.317) documented in `progress.md`.
- **Out of scope entirely:** anything that doesn't pass through
  `POST /v1/decision`. If an agent implementation had a path to act without
  calling the proxy, this defense has no visibility into it — its authority
  is exactly as wide as the interface it's given.

## Forbidden / out-of-scope adversarial activity

Per the SENTINEL challenge rules: attacks against the host, other teams,
sponsors, or real infrastructure are out of scope and grounds for
disqualification, not part of this threat model. Everything above concerns
only text-level mutations within the simulator's declared attack surfaces.
