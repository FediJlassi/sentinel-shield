# progress.md — read this first at every session start

## Status: end of Day 0 (night 1)
### Done
- [x] Repo + GitHub + WSL2 env (206/206 starter tests pass)
- [x] Task 2: simulator contract documented (docs/contract.md)
- [x] Task 3: /v1/decision returns allow-all, full DefenseDecision shape,
      hash-chained JSONL trace (traces/run.jsonl), tests pass
- [x] CLAUDE.md written; trace schema agreed (docs/trace-schema.md)
- [x] dashboard/: read-only trace viewer (FastAPI + inline HTML/JS, no new
      deps). Reads `traces/run.jsonl`, shows a run timeline (time, step_id,
      run_id, candidate action, decision badge, risk_score, reason_codes,
      explanation), click a row to expand the full event JSON. Polls
      `/api/events` every 2s; tolerates missing/empty trace file and
      malformed JSONL lines. Run with:
      `uv sync --no-install-project && uv run --no-project uvicorn dashboard.app:app --reload --port 8501`
      then open http://127.0.0.1:8501 (details in dashboard/README.md).

### In progress
- [ ] NOTHING — starting Day 1 fresh

### Next up (Day 1, in this order)
1. [YOU] app/firewall.py: attach trust rank to observation using provenance field
2. [YOU] configs/policy.yaml + app/decision.py: first hard rules + decision composer (4 outcomes)
3. [PARTNER] dashboard/: trace viewer per kickoff prompt
4. Run finance_false_approval + poisoned-invoice scenario, watch decisions in trace
5. First REWRITE working (send -&gt; draft without secret)

### Known blockers / questions
- [ ] Does simulator auto-approve or auto-deny "escalate"? (check starter kit, add to contract.md)
- [ ] Does simulator validate rewritten_action schema? (check, add to contract.md)

### Rules reminder
- decisions lowercase; rewritten_action ONLY on rewrite; never scenario-specific hacks
- commit after every working state; pull before every session; app/ owned by YOU, dashboard/ by PARTNER