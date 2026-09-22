# Threat Model — SENTINEL Shield

This is the defender's-eye threat model: what SENTINEL Shield protects, what
it assumes about the adversary, and where its coverage stops. It complements
`docs/contract.md` (the verified simulator contract — request/response shape,
escalation semantics) and `reports/technical-report.md` §1–2 (the full
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
| Exfiltration of sensitive content | sensitivity-keyed (not trust-rank-keyed) scan of final `respond` actions, redacted in plain/base64/hex/reversed form | `app/main.py: update_run_state`, `scan_respond`, `_redact` |
| Escalation-as-bypass | not our mechanism — verified property of the simulator's `human_confirm`; we rely on it rather than re-implementing plan-matching ourselves | `docs/contract.md` |
| Confirmation-relay abuse / DoS via retry loop | `request_confirmation` short-circuited to instant `allow` before any parsing | `app/main.py` |

## Residual risk / known gaps (honest, not aspirational)

- **Over-broad redaction.** The exfiltration defense currently treats every
  string ≥8 characters in a sensitivity-tagged observation as sensitive, not
  just the actual canary value. This has a measured cost: 6/40 scenarios in
  the full sweep fail their task because a legitimate fact (an account ID,
  a transfer amount) sitting in the same document as a real secret gets
  redacted alongside it. See `reports/results.md` and
  `reports/technical-report.md` §6. This is a usefulness failure, not a
  safety one — nothing sensitive leaked in any of these cases — but it is a
  real instance of the exact failure mode ("blocking/over-correcting breaks
  benign work") this project is scored against.
- **`data_flow` and `forbidden_effect` rule kinds are stubbed.**
  `policy_engine.py` passes them through un-triggered rather than silently
  dropping them, but does not independently enforce them beyond the
  sensitivity-keyed respond-scan above. A `data_flow` rule with semantics
  we haven't anticipated would not currently do anything on its own.
  (`configs/policy.yaml` ablation toggles for exercising this deliberately
  are a standing TODO — see `progress.md`.)
- **Escalation is over-used, not incorrectly used.** Escalation precision
  in the full sweep is 0.317 (most escalations resolve as "was actually
  fine") — a friction/usefulness cost, not a correctness bug, since the
  simulated human still approves the legitimate ones and no benign task
  fails because of it (BTU = 1.0).
- **Out of scope entirely:** anything that doesn't pass through
  `POST /v1/decision`. If an agent implementation had a path to act without
  calling the proxy, this defense has no visibility into it — its authority
  is exactly as wide as the interface it's given.

## Forbidden / out-of-scope adversarial activity

Per the SENTINEL challenge rules: attacks against the host, other teams,
sponsors, or real infrastructure are out of scope and grounds for
disqualification, not part of this threat model. Everything above concerns
only text-level mutations within the simulator's declared attack surfaces.
