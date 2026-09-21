# SENTINEL Simulator Contract

Source: sentinel-starter-kit baseline defense code + scenario YAMLs.
Environment: WSL2 Ubuntu (uv synced, 206/206 baseline tests pass).

## Endpoints
- `POST /v1/decision` — defense decision endpoint
- `GET /healthz` — health check
- Run: `sentinel run --scenario <scenario.yaml> --defense-url http://127.0.0.1:8080/v1/decision`

## Request: DefenseRequest (what the simulator sends us)
| Field | Type | Notes |
|---|---|---|
| run_id | str | execution session ID |
| step_id | int | current step index; key for long-horizon/multi-step |
| user_goal | str | original authenticated user request |
| conversation | list[ConversationItem] | active chat history |
| observation | ObservationView \| None | latest raw context (emails, logs, attachments); primary injection surface |
| candidate_action | CandidateAction | tool call (name + args) to evaluate |
| policy_context | dict | active security policies |
| provenance | list[ProvenanceRecord] | source tracking for observations |
| history_digest | HistoryDigest | summary of prior tool executions |

## Response: DefenseDecision (what we must return)
| Field | Type | Constraint |
|---|---|---|
| decision | str | MUST be lowercase: `allow` / `block` / `escalate` / `rewrite` |
| risk_score | float | 0.0–1.0 |
| confidence | float | 0.0–1.0 |
| reason_codes | list[str] | UPPER_SNAKE_CASE, max 16 codes |
| explanation | str \| None | human-readable, max 500 chars (observability) |
| rewritten_action | CandidateAction \| None | MANDATORY if decision == "rewrite"; FORBIDDEN otherwise |
| metadata | dict | bounded JSON-serializable |

## Trust levels (from ProvenanceRecord), most → least trusted
| Level | Rank | Meaning |
|---|---|---|
| system_policy | 0 | real policy — only source with policy authority |
| authenticated_user | 1 | the user's actual request |
| trusted_internal | 2 | internal systems |
| untrusted_internal | 3 | e.g. employee emails — evidence, not authority |
| untrusted_external | 4 | vendor email, web, attachments |
| adversary_controlled | 5 | known hostile source |

- Kit's built-in `is_trusted` = rank <= 2.
- OUR rule: only rank <= 1 (system_policy + authenticated_user) can authorize
  sensitive/state-changing actions. Ranks 2–5 can only justify reads.
- Memory inherits trust: anything recalled from rank >= 3 content stays evidence.

## Invariants we enforce in code (tested)
1. decision is always lowercase, one of the four values.
2. rewritten_action is set iff decision == "rewrite".
3. reason_codes are UPPER_SNAKE_CASE.
4. No response field exceeds simulator bounds (explanation <= 500 chars).

## [TODO] Open checks
- Escalate behavior in simulator: [auto-approve / auto-deny / simulated human?]
- Does simulator validate rewritten_action against the tool schema? [yes/no]

## Architecture mapping (contract → our components)
- Observation Firewall  <- consumes `observation` + `provenance`
- Provenance Ledger     <- persists run_id/step_id/candidate/decision from each request
- Decision Composer     <- outputs DefenseDecision; enforces invariants 1–4
- InfoFlow check        <- taint `candidate_action.args` using provenance + history_digest
- Memory guard          <- conversation/history_digest entries carry trust ranks
- Trace                 <- every request/response logged to traces/run.jsonl (hash-chained)