# CLAUDE.md — SENTINEL Shield

## What this is
Defense solution for the SENTINEL research challenge (IndabaX Tunisia 2026).
A safety proxy around the official Qwen3-8B tool-using agent, running fully
offline against the SENTINEL simulator and synthetic scenarios. We build ONLY
the defense, never the attacks. Team of 2, ~48h to submission.

## Hard rules (violating these can disqualify us)
- NEVER decide from scenario identifiers, filenames, or expected outcomes.
- Every decision must come from: agent state, candidate action, provenance,
  active policy, observed content.
- The only four interventions: allow / block / escalate / rewrite.
- No chain-of-thought in outputs — short explanation + risk signals only.
- Blocking everything is failure; benign tasks MUST still complete.
- Commit real work frequently; never commit empty files or scenario-specific hacks.

## Simulator contract (already discovered, in docs/contract.md — read it)
- Endpoint: POST /v1/decision (FastAPI), GET /healthz, port 8080.
- Request: run_id, step_id, user_goal, conversation, observation,
  candidate_action, policy_context, provenance, history_digest.
- Response: DefenseDecision {decision (LOWERCASE: allow|block|escalate|rewrite),
  risk_score 0-1, confidence 0-1, reason_codes UPPER_SNAKE_CASE max 16,
  explanation <=500 chars, rewritten_action (mandatory iff decision==rewrite,
  forbidden otherwise), metadata dict}.
- Trust ranks: system_policy=0, authenticated_user=1, trusted_internal=2,
  untrusted_internal=3, untrusted_external=4, adversary_controlled=5.
- CORE RULE: only rank <=1 may authorize sensitive/state-changing actions;
  ranks 2-5 are evidence, never authority. Memory inherits trust.

## Architecture
Observation Firewall (tag trust) -> Provenance Ledger (hash-chained JSONL)
-> proxy guardrail (hard policy rules -> infoflow/exfil check -> risk score
-> decision composer) -> four outcomes -> tool execution -> new observation
re-enters firewall. Every request/response logged to traces/run.jsonl.
Details + mermaid diagram in README.md.

## Repo layout
- app/ — defense service (OWNER: teammate 1, do not restructure without asking)
  main.py, schemas.py, firewall.py, ledger.py, infoflow.py, decision.py, trace.py
- configs/policy.yaml — thresholds + rules, all tunables live here
- dashboard/ — trace viewer (OWNER: teammate 2)
- docs/ — contract.md, trace-schema.md, threat-model.md
- reports/ — technical report, ablations, failure analysis
- traces/ — gitignored, generated at runtime

## Current state
- Project skeleton, GitHub repo, WSL2 Ubuntu env (uv). 206/206 starter tests pass.
- Block 1 Status: Core Policy & Firewall Implementation Complete. `app/policy_engine.py`, `app/firewall.py`, `app/decision.py`, and `app/main.py` are live. `/v1/decision` actively evaluates policy contexts and tags observation trust ranks. 
- 17/17 pytest suites passing locally.
- Next Action: Pull onto desktop, verify live against `finance_false_approval` scenario, then execute Block 2 (scenario mapping across all 19 public scenarios).

## When writing code
- Python + FastAPI + pydantic. Tests with pytest for every module.
- All thresholds/rules in configs/policy.yaml, never hard-coded.
- Keep functions small and typed; this code will be read by jurors.
- Before any non-trivial change: run `uv run pytest`, then commit.
