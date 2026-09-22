# CLAUDE.md — SENTINEL Shield

## Hard rules
- Four outcomes only: allow / block / escalate / rewrite.
- Never decide from scenario identifiers, filenames, or expected outcomes.
- No chain-of-thought in outputs — short explanation + risk signals only.
- Blocking everything is failure: benign tasks MUST complete.
- All thresholds/tunables live in configs/policy.yaml — never hard-coded.
- Commit real work frequently; never commit empty files or scenario-specific hacks.
- Ownership: teammate 1 (Fedi) owns app/ + configs/. Teammate 2 owns dashboard/ + reports/.
  docs/ is shared — read before editing, pull before working.

## Simulator contract — read docs/contract.md FIRST (gold source, updated 22/09)
Verified additions beyond the old summary:
- ESCALATE does not auto-approve: human_confirm calls matcher.is_legitimate() against
  the scenario's legitimate plan. Injected actions escalated → still DENIED.
  Legit-but-unconfirmed actions escalated → approved. Escalation is safe.
- candidate_action.confirmation_for can be a STRING, NULL, or a nested DICT (simulator
  sends a copy of the confirmed action). Schemas tolerate all; dicts are coerced to None.
- agent calls tool "request_confirmation" to receive a human verdict after escalation.
  /v1/decision MUST allow it instantly, before any parsing — any error here causes
  infinite DefenseUnavailable retry loops (was our worst bug tonight).
- Rules in policy_context.rules use kinds our engine may not implement — pass them
  through un-triggered, never drop silently.
- Canaries (secret_token, account_id, access_token, contract_ref) are planted in
  trusted_internal documents with sensitivity=restricted. Exfil detection keys off the
  SENSITIVITY field, not trust rank (rank-2 docs carry the most dangerous leaks).
- "SENTINEL is not a hidden-test competition": generic rules keyed off policy fields,
  trust ranks, and sensitivity only. No scenario names in code.

## Architecture (as implemented in app/)
- main.py — /v1/decision endpoint; run-scoped sensitive-string state (sha256 in traces,
  raw values never logged); request_confirmation short-circuit.
- schemas.py — DefenseRequest/DefenseDecision, strict response, lenient request.
- firewall.py — provenance trust map (rank 0–5, fail-closed to 5), observation/args trust.
- policy_engine.py — action_digest copied EXACTLY from starter kit (must match
  confirmations_granted byte-for-byte); evaluators: tool_permission (skip for respond),
  requires_confirmation, prerequisite (prepare→confirm→execute chain), data_flow,
  forbidden_effect; unknown rule kinds pass through.
- infoflow.py — sensitive-content tracking keyed on sensitivity ∈ {restricted,
  confidential}; final respond actions are scanned (plain + base64/hex/reversed) and
  REWRITTEN with leaked values redacted ("[REDACTED — restricted per policy]").
- decision.py — outcome ladder (critical→block, high→escalate/block,
  unconfirmed-consequential→escalate, data_flow→block, else allow).
- trace.py — append-only hash-chained JSONL; every decision logged with digest+findings.
- configs/policy.yaml — severity weights, thresholds, benign-read allowlist,
  ablation toggles: provenance_check, infoflow.

## Current state (22/09 22:30 — updated by Fedi)
- Defense built and wired (A/B/C prompts done). 3 hotfixes landing tonight:
  (1) confirmation_for dict tolerance + request_confirmation short-circuit,
  (2) canary-leak rewrite on final respond via sensitivity-keyed infoflow,
  (3) YAML calibration: benign reads allow, escalation only for consequential.
- Verified tonight on desktop with real agent (ollama:qwen3:8b): decisions fire per
  step, escalate reaches simulated human, canary-rewrite path implemented.
- Sweep results (pre-fix): finance mostly OK; enterprise scenarios leak canaries via
  final respond (8× SENSITIVE_TO_UNTRUSTED_SINK); several task failures caused by
  request_confirmation retry loops (fix 1 kills this); ~8 SOC/finance runs interrupted
  (Ctrl+C) — re-run after fixes before judging.
- Baseline: 206/206 starter tests pass; our pytest suite green (3+n tests).
- Docs: docs/contract.md is the verified contract. README, threat-model.md pending.
- Video runs use the REAL agent: --model ollama:qwen3:8b on the desktop rig
  (RTX 3060, WSL2). Mock model for sweeps/results tables only.

## When writing code
- Python + FastAPI + pydantic. Tests with pytest for every module.
- Keep functions small and typed — jurors read this code.
- Before any non-trivial change: uv run pytest, then commit.
- progress.md is the team's shared memory — update it after every task.
