# dashboard/ — SENTINEL Shield trace viewer

Minimal, read-only local page that tails `traces/run.jsonl` (the hash-chained
trace file the defense proxy writes on every `/v1/decision` call) and shows
a run timeline. It does not call the simulator or the defense API itself —
point it at a trace file while or after a run.

## What it shows

One row per trace event: timestamp, `step_id`, `run_id`, candidate action
(`name(args)`), decision as a color-coded badge (green=allow, red=block,
yellow=escalate, blue=rewrite), `risk_score`, `reason_codes`, and
`explanation`. Click a row to expand the full raw JSON for that event
(including `rewritten_action`, `provenance`/`observation_trust`, etc., when
present).

It polls `/api/events` every 2s (toggle "auto-refresh" to stop) so you can
watch a run land in real time, and has a manual "Reload" button.

## Run it

From the repo root:

```bash
uv sync --no-install-project   # first time only, installs fastapi/uvicorn into .venv
uv run --no-project uvicorn dashboard.app:app --reload --port 8501
```

Then open http://127.0.0.1:8501 in a browser.

(`--no-project` is used because the repo's `uv_build` package layout isn't
set up yet on this branch — unrelated to the dashboard; plain `uv run
uvicorn dashboard.app:app --port 8501` will also work once that's fixed.)

By default it reads `traces/run.jsonl` relative to the repo root. Point it
at a different file with:

```bash
SENTINEL_TRACE_PATH=/path/to/other/run.jsonl uv run --no-project uvicorn dashboard.app:app --port 8501
```

## Behavior on bad/missing input

- No `traces/run.jsonl` yet: page loads and says so, no error.
- Empty file: page loads, shows "trace file is empty".
- Malformed line(s) (bad JSON, or JSON that isn't an object): that line is
  skipped and reported in a warning strip above the table; the rest of the
  file still renders.
- Event missing expected fields (e.g. no `confidence`, no `explanation`):
  rendered as `-` instead of erroring.

## Files

- `app.py` — FastAPI app. `GET /` serves the page, `GET /api/events` serves
  the parsed trace as JSON (used by the page's own polling), `GET /healthz`
  for a liveness check.
- No templates/build step: the page is a single self-contained HTML/CSS/JS
  response, no external assets, works fully offline.

## Notes for reviewers

- Read-only: never writes to `traces/`, `app/`, or `configs/`.
- Row/detail rendering builds DOM nodes and sets `textContent`, not
  `innerHTML`, so adversarial content that ends up in a trace (e.g. a
  candidate action's `args` containing HTML/script from an untrusted
  observation) renders as inert text, not executable markup.
