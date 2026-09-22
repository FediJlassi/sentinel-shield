# SENTINEL Shield

A defense proxy that sits between an LLM agent and its tools, and decides —
per action, before execution — whether to **allow / block / escalate /
rewrite** it. Built against the SENTINEL simulator contract
(`docs/contract.md`, the verified gold source for request/response shape and
escalation semantics).

## Why

Agents given tools and untrusted context (emails, docs, logs, prior tool
output) can be steered into harmful actions by content injected into that
context — not just by the user. SENTINEL Shield evaluates every candidate
action against policy, provenance/trust, and data-sensitivity signals
without needing to see the agent's reasoning, and without needing a
scenario-specific rule for every attack.

## Architecture

```
Untrusted input (email/docs/logs)
        │
        ▼
Observation Firewall  ── tags trust rank + provenance ─────┐
        │                                                    │
        ▼                                                    │
   Agent (ollama:qwen3:8b, external to this repo)            │
        │ candidate action                                   │
        ▼                                                    │
Proxy Guardrail  ── policy rules + exfil/sensitivity scan     │
   (/v1/decision)     + risk score                            │
        │                                                     │
   ┌────┼────────────┐                                        │
   ▼    ▼            ▼                                        │
 ALLOW BLOCK/     ESCALATE → Human approve/deny                │
       REWRITE         (matcher.is_legitimate — see below)     │
   │    │              │                                       │
   └────┴──────────────┴──► back to agent's tool loop ─────────┘
                              (next observation)
        │
        ▼
  Trace JSONL (hash-chained) ──► Dashboard (read-only viewer)
```

- **Observation Firewall** — `app/firewall.py`: builds a trust map from
  `provenance` (rank 0=`system_policy` … 5=`adversary_controlled`, fail-closed
  to 5 on anything unrecognized) and ranks the observation and candidate-action
  arguments against it.
- **Agent** — not part of this repo. Real runs use `--model ollama:qwen3:8b`;
  mock model is used for scripted sweeps only.
- **Proxy Guardrail** — `app/policy_engine.py` (declarative rule evaluation:
  tool permission, requires-confirmation, prepare→confirm→execute prerequisite
  chains, data-flow, forbidden-effect; unknown rule `kind`s pass through
  un-triggered rather than being silently dropped) + `app/decision.py`
  (severity → outcome ladder, thresholds from `configs/policy.yaml`) +
  sensitivity-scan/redaction logic **inline in `app/main.py`** (scans final
  `respond` actions — plain, base64, hex, reversed — for values sourced from
  `sensitivity ∈ {restricted, confidential}` provenance, and rewrites leaks
  with a redaction token). Note: this scan is not a separate `infoflow.py`
  module despite earlier architecture notes describing one that way.
- **Human approve/deny** — escalation does **not** auto-approve. Per the
  verified simulator contract, `human_confirm` calls `matcher.is_legitimate()`
  against the scenario's real plan: an injected action that reaches escalation
  is still denied; a legitimate action missing only a confirmation is
  approved. This makes escalation safe to use liberally for
  "consequential + unconfirmed or untrusted-evidence-backed" actions instead
  of guessing block vs. allow.
- **Tool Gateway** — the `DefenseDecision` returned by `/v1/decision` (see
  below) is the gate; actual tool dispatch happens in the simulator/agent
  harness, outside this repo.
- **Trace + Dashboard** — `app/trace.py` appends every decision (candidate
  action, decision, risk score, reason codes, explanation, digest) as a
  hash-chained JSONL line to `traces/run.jsonl`. `dashboard/app.py` is a
  read-only FastAPI viewer that tails that file — it never calls the
  simulator or the defense API itself. See `dashboard/README.md`.

## Hard rules this project holds itself to

- Four outcomes only: allow / block / escalate / rewrite.
- Never decide from scenario identifiers, filenames, or expected outcomes —
  only from policy fields, trust ranks, and sensitivity. Generic detection,
  not a hidden-test competition.
- No chain-of-thought in `/v1/decision` responses — short explanation +
  reason codes only.
- All thresholds/tunables live in `configs/policy.yaml`, never hard-coded.

## Running it

**Defense API:**
```bash
uv run --no-project uvicorn app.main:app --port 8080
```
Then point the simulator at it: `sentinel run --scenario <scenario.yaml>
--defense-url http://127.0.0.1:8080/v1/decision --model ollama:qwen3:8b`
(or a mock model for scripted sweeps).

**Tests:**
```bash
uv run --no-project pytest
```

**Dashboard** (reads `traces/run.jsonl` written by a run above):
```bash
uv run --no-project uvicorn dashboard.app:app --reload --port 8501
```
Open http://127.0.0.1:8501. Full details in `dashboard/README.md`.

## Repo layout

- `app/` — defense proxy (FastAPI). Owned by Fedi.
- `configs/policy.yaml` — severity weights, thresholds, benign-read
  allowlist. Owned by Fedi.
- `dashboard/` — read-only trace viewer.
- `reports/` — technical report, scenario results table, video script.
- `docs/` — shared; `contract.md` is the verified simulator contract
  (gold source), `trace-schema.md` documents the trace JSONL shape. Pull
  before editing.
- `traces/` — run output (`run.jsonl`, hash-chained decision log;
  `raw-payloads.jsonl`, every raw request body for debugging).

## Status

See `progress.md` for the day-by-day log and standing TODOs, and
`reports/technical-report.md` for the full write-up (results/ablations
sections pending the post-fix sweep re-run).
