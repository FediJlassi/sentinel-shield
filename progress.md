# progress.md — read this first at every session start

## Status: start of Day 1 — CORRECTED 2026-09-21
### ⚠️ Reconciliation note (2026-09-21)
This file and CLAUDE.md previously claimed Task 3 (app/ package, allow-all
`/v1/decision`, hash-chained trace) was done. Verified against the actual
repo on disk and `git log --all -- app/ configs/`: **neither `app/` nor
`configs/` has ever existed, on any branch.** README.md is also empty
(CLAUDE.md says it should hold the architecture + mermaid diagram).
Task 3 is being treated as NOT started until it exists in this repo.
If a teammate has this work locally on another machine, pull/merge it
before rebuilding from scratch.

### Done
- [x] Repo + GitHub + WSL2 env (206/206 starter tests pass)
- [x] Task 2: simulator contract documented (docs/contract.md)
- [x] CLAUDE.md written; trace schema agreed (docs/trace-schema.md)
- [x] dashboard/: read-only trace viewer (FastAPI + inline HTML/JS, no new
      deps). Reads `traces/run.jsonl`, shows a run timeline (time, step_id,
      run_id, candidate action, decision badge, risk_score, reason_codes,
      explanation), click a row to expand the full event JSON. Polls
      `/api/events` every 2s; tolerates missing/empty trace file and
      malformed JSONL lines. Run with:
      `uv sync --no-install-project && uv run --no-project uvicorn dashboard.app:app --reload --port 8501`
      then open http://127.0.0.1:8501 (details in dashboard/README.md).
- [x] Block 1 (Core Policy & Firewall): `app/policy_engine.py` (digest matching, confirmation checks), `app/firewall.py` (fail-closed trust tagging, worst-case args ranking), `app/decision.py` & `configs/policy.yaml` (composition and thresholds), `app/main.py` (`/v1/decision` endpoint active). 17/17 tests passing.

### Not started (previously mismarked as done)
- [ ] app/trace.py: hash-chained JSONL trace writer
- [ ] README.md content (architecture + mermaid diagram)
- [ ] docs/threat-model.md (referenced in CLAUDE.md repo layout, not present)

### In progress
- [ ] NOTHING — Moving to Block 2 (Scenario Failure Mapping)

### Next up (Day 1, in this order)
1. [YOU] Pull code to Desktop, run `uv run python -m app.main` in background.
2. [YOU] Run `finance_false_approval` scenario with Qwen3-8B reference agent to verify Block 1 firewall triggers `ESCALATE` successfully.
3. [YOU] Block 2 — Scenario Failure Mapping: Run all 19 scenarios and log pass/fail status in `reports/results.md`.
4. [PARTNER] dashboard/: trace viewer per kickoff prompt (already done, verify against real traces)

### Known blockers / questions
- [ ] Does simulator auto-approve or auto-deny "escalate"? (check starter kit, add to contract.md)
- [ ] Does simulator validate rewritten_action schema? (check, add to contract.md)

### Rules reminder
- decisions lowercase; rewritten_action ONLY on rewrite; never scenario-specific hacks
- commit after every working state; pull before every session; app/ owned by YOU, dashboard/ by PARTNER
- verify claimed "done" work actually exists in git before building on top of it
