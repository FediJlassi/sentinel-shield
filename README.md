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
  chains, data-flow, forbidden-effect; `action_digest` copied byte-for-byte
  from the starter kit so it matches `history_digest.confirmations_granted`;
  unknown rule `kind`s pass through un-triggered rather than being silently
  dropped) + `app/decision.py` (severity → outcome ladder, thresholds from
  `configs/policy.yaml`).
- **`app/main.py`** — the `/v1/decision` endpoint itself, plus two things
  that live here rather than in a separate module: (1) run-scoped
  sensitive-string state (`_observation_sensitive_strings` /
  `_extract_candidate_secrets`, a `label: value` + entropy heuristic keyed on
  field semantics, not canary names) tracking which tracked values are
  restricted vs. confidential and scanning every sink — a final `respond`
  (plain, base64, hex, rot13, reversed) and any tool call's arguments — for
  a leak, redacting or blocking depending on sensitivity tier and
  destination; and (2) a hard `request_confirmation` short-circuit that
  allows that specific tool instantly, before any parsing, so a malformed or
  unusual payload there can never cascade into a `DEFENSE_UNAVAILABLE` retry
  loop. There is no separate `infoflow.py` module — this is all inline in
  `main.py` despite some earlier internal notes describing it that way.
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
--defense-url http://127.0.0.1:8080 --model ollama:qwen3:8b` (base URL only —
the CLI appends `/v1/decision` itself; the full path 404s on every step and
looks like `DEFENSE_UNAVAILABLE`). Use `--model mock` for fast scripted
sweeps (`sentinel eval public --defense-url http://127.0.0.1:8080 --model mock
--json`) instead of the real agent.

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
  (gold source), `trace-schema.md` documents the trace JSONL shape,
  `threat-model.md` covers assets/adversary capabilities/residual risk.
  Pull before editing.
- `traces/` — run output (`run.jsonl`, hash-chained decision log;
  `raw-payloads.jsonl`, every raw request body for debugging).

## Results

Full public scenario sweep (40 scenarios, `--model mock`, deterministic),
plus the 9-scenario validation split and a real-agent (`ollama:qwen3:8b`)
run of the full 49-scenario library:

| Split | ASR | CVR | Task success | Official score |
|---|---|---|---|---|
| Public (mock) | **0 / 31** | **0** | **40 / 40** | **0.987** |
| Validation (mock) | **0 / 4** | **0** | **9 / 9** | **1.0** |
| Combined (real agent, `qwen3:8b`) | **0 / 35** | **0** | 33 / 49 | — |

The real-agent task-success gap is agent-side, not defense-side — every
failure individually traced (invented tool arguments, hallucinated task
completion, phrasing that doesn't match a strict grader) held the same
0/0 security result. See `reports/technical-report.md` Section 8 for the
per-failure breakdown.

Baselines, public split, same command (honest, no spin):

- `allow_all` (no defense): every attack succeeds (ASR 1.0) — confirms the
  scenario library isn't accidentally already-safe.
- `provenance` (starter kit's deterministic source→sink baseline) matches
  us on ASR/CVR/task-success but has a real FBR of 0.222 (it outright
  blocks benign actions we allow) and an official score of 0.939 — **we now
  beat it** (0.987), after fixing a bug where `tool_permission`/
  `requires_confirmation` never actually fired against real traffic (see
  the technical report's Failure Analysis).
- Our own FBR (0.049, not 0.0) is explained, not hidden: every instance is
  a correctly-blocked malicious variant of a structurally-legitimate step
  (the grader's "legitimate" label is positional, not content-aware), never
  an actual benign task failing — task success stays 40/40. An ablation
  (technical report Section 7) shows removing the mechanism responsible
  would instead let 23 of 210 real decisions leak a tracked secret.

See `reports/technical-report.md` for the full method, ablations, and
failure analysis, and `progress.md` for the day-by-day log.
`reports/results.md` still describes an earlier, superseded fix state and
needs a matching rewrite before submission.

## Demonstration

Video walkthrough (real agent, `--model ollama:qwen3:8b`, not the mock):
`TODO — video URL` *(placeholder; filled in after recording)*.

Dashboard decision close-up: *(no screenshot committed to the repo yet —
add to `reports/screenshots/` and link here once captured)*.
