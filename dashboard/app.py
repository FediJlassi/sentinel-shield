"""SENTINEL Shield dashboard.

Minimal, read-only local viewer for traces/run.jsonl. Does not import or
depend on anything in app/ or configs/ - it only reads the trace file the
proxy writes at runtime.

Run: uv run uvicorn dashboard.app:app --reload --port 8501
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="SENTINEL Shield Dashboard")

DEFAULT_TRACE_PATH = Path(__file__).resolve().parent.parent / "traces" / "run.jsonl"


def trace_path() -> Path:
    """Path to the trace file. Override with SENTINEL_TRACE_PATH."""
    override = os.environ.get("SENTINEL_TRACE_PATH")
    return Path(override).expanduser() if override else DEFAULT_TRACE_PATH


def load_events() -> tuple[list[dict[str, Any]], list[str]]:
    """Read the JSONL trace file.

    Tolerates a missing file, an empty file, blank lines, and malformed
    lines (each bad line is reported instead of aborting the whole read).
    """
    path = trace_path()
    events: list[dict[str, Any]] = []
    errors: list[str] = []

    if not path.exists():
        return events, errors

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"could not read trace file: {exc}")
        return events, errors

    for line_no, line in enumerate(raw.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {line_no}: invalid JSON ({exc.msg})")
            continue
        if isinstance(parsed, dict):
            events.append(parsed)
        else:
            errors.append(f"line {line_no}: not a JSON object")

    return events, errors


@app.get("/api/events")
def api_events() -> JSONResponse:
    events, errors = load_events()
    return JSONResponse(
        {
            "trace_path": str(trace_path()),
            "exists": trace_path().exists(),
            "count": len(events),
            "errors": errors,
            "events": events,
        }
    )


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return PAGE_HTML


PAGE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SENTINEL Shield - Run Trace</title>
<style>
  :root {
    --bg: #0f1115;
    --panel: #171a21;
    --border: #2a2e37;
    --text: #e4e7ec;
    --muted: #9aa2af;
    --allow: #2fae5f;
    --block: #e5484d;
    --escalate: #d9a521;
    --rewrite: #4a90e2;
    --unknown: #6b7280;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 13px;
  }
  header {
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 16px;
    flex-wrap: wrap;
  }
  header h1 {
    font-size: 15px;
    margin: 0;
    font-weight: 600;
  }
  header .path {
    color: var(--muted);
    font-size: 12px;
  }
  header .spacer { flex: 1; }
  button {
    background: var(--panel);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 6px 12px;
    cursor: pointer;
    font-family: inherit;
    font-size: 12px;
  }
  button:hover { border-color: var(--muted); }
  label.toggle {
    color: var(--muted);
    font-size: 12px;
    display: flex;
    align-items: center;
    gap: 5px;
    cursor: pointer;
  }
  #status-bar {
    padding: 8px 20px;
    color: var(--muted);
    font-size: 12px;
    border-bottom: 1px solid var(--border);
  }
  #status-bar.error { color: var(--block); }
  #errors {
    padding: 8px 20px;
    color: var(--escalate);
    font-size: 12px;
    border-bottom: 1px solid var(--border);
    white-space: pre-wrap;
  }
  main { padding: 0 20px 40px; }
  table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 14px;
  }
  thead th {
    text-align: left;
    color: var(--muted);
    font-weight: 500;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    padding: 6px 10px;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    background: var(--bg);
  }
  tbody tr.event-row {
    cursor: pointer;
    border-bottom: 1px solid var(--border);
  }
  tbody tr.event-row:hover { background: var(--panel); }
  td {
    padding: 7px 10px;
    vertical-align: top;
  }
  td.mono-cell { white-space: nowrap; }
  td.truncate {
    max-width: 320px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    color: #0f1115;
  }
  .badge-allow { background: var(--allow); }
  .badge-block { background: var(--block); color: #fff; }
  .badge-escalate { background: var(--escalate); }
  .badge-rewrite { background: var(--rewrite); color: #fff; }
  .badge-unknown { background: var(--unknown); color: #fff; }
  tr.detail-row td {
    background: var(--panel);
    padding: 12px 10px 16px;
  }
  tr.detail-row pre {
    margin: 0;
    white-space: pre-wrap;
    word-break: break-word;
    color: var(--text);
  }
  .hidden { display: none; }
  .empty-state {
    padding: 60px 0;
    text-align: center;
    color: var(--muted);
  }
  .reason-code {
    display: inline-block;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 1px 6px;
    margin: 1px 3px 1px 0;
    font-size: 11px;
    color: var(--muted);
  }
  .trust-badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: 600;
    border: 1px solid var(--escalate);
    color: var(--escalate);
  }
  .trust-badge.high {
    border-color: var(--block);
    color: var(--block);
  }
  #filter-bar {
    padding: 8px 20px;
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    border-bottom: 1px solid var(--border);
  }
  #filter-bar .group-label {
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }
  .filter-toggle {
    background: var(--panel);
    color: var(--muted);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 10px;
    cursor: pointer;
    font-family: inherit;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .filter-toggle .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--unknown);
  }
  .filter-toggle[data-active="true"] { color: var(--text); border-color: var(--muted); }
  .filter-toggle[data-decision="allow"][data-active="true"] .dot { background: var(--allow); }
  .filter-toggle[data-decision="block"][data-active="true"] .dot { background: var(--block); }
  .filter-toggle[data-decision="escalate"][data-active="true"] .dot { background: var(--escalate); }
  .filter-toggle[data-decision="rewrite"][data-active="true"] .dot { background: var(--rewrite); }
  #run-select {
    background: var(--panel);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 8px;
    font-family: inherit;
    font-size: 12px;
  }
  #legend {
    padding: 8px 20px;
    display: flex;
    align-items: center;
    gap: 14px;
    flex-wrap: wrap;
    border-bottom: 1px solid var(--border);
    color: var(--muted);
    font-size: 11px;
  }
  #legend .legend-item {
    display: flex;
    align-items: center;
    gap: 5px;
  }
  #legend .swatch {
    width: 9px;
    height: 9px;
    border-radius: 2px;
  }
  #legend .swatch.allow { background: var(--allow); }
  #legend .swatch.block { background: var(--block); }
  #legend .swatch.escalate { background: var(--escalate); }
  #legend .swatch.rewrite { background: var(--rewrite); }
  #legend .swatch.trust { background: none; border: 1px solid var(--escalate); }
</style>
</head>
<body>
<header>
  <h1>SENTINEL Shield &mdash; Run Trace</h1>
  <span class="path" id="trace-path"></span>
  <div class="spacer"></div>
  <label class="toggle"><input type="checkbox" id="auto-refresh" checked> auto-refresh</label>
  <button id="reload-btn">Reload</button>
</header>
<div id="filter-bar">
  <span class="group-label">Decision</span>
  <button class="filter-toggle" data-decision="allow" data-active="true"><span class="dot"></span>allow</button>
  <button class="filter-toggle" data-decision="block" data-active="true"><span class="dot"></span>block</button>
  <button class="filter-toggle" data-decision="escalate" data-active="true"><span class="dot"></span>escalate</button>
  <button class="filter-toggle" data-decision="rewrite" data-active="true"><span class="dot"></span>rewrite</button>
  <span class="group-label" style="margin-left:10px">Run</span>
  <select id="run-select">
    <option value="">All runs</option>
  </select>
</div>
<div id="legend">
  <span class="legend-item"><span class="swatch allow"></span>allow &mdash; permitted, no policy concern</span>
  <span class="legend-item"><span class="swatch block"></span>block &mdash; denied, policy violation</span>
  <span class="legend-item"><span class="swatch escalate"></span>escalate &mdash; sent to human confirmation</span>
  <span class="legend-item"><span class="swatch rewrite"></span>rewrite &mdash; response redacted before returning</span>
  <span class="legend-item"><span class="swatch trust"></span>trust badge &mdash; evidence rank &gt; 1 (never authorizes)</span>
</div>
<div id="status-bar"></div>
<div id="errors" class="hidden"></div>
<main>
  <table id="events-table">
    <thead>
      <tr>
        <th>Time</th>
        <th>Step</th>
        <th>Run</th>
        <th>Candidate Action</th>
        <th>Decision</th>
        <th>Trust</th>
        <th>Risk</th>
        <th>Reason Codes</th>
        <th>Explanation</th>
      </tr>
    </thead>
    <tbody id="events-body"></tbody>
  </table>
  <div id="empty-state" class="empty-state hidden"></div>
</main>

<script>
const DECISION_CLASS = {
  allow: "badge-allow",
  block: "badge-block",
  escalate: "badge-escalate",
  rewrite: "badge-rewrite",
};

function el(tag, opts) {
  const node = document.createElement(tag);
  if (!opts) return node;
  if (opts.text !== undefined) node.textContent = opts.text;
  if (opts.className) node.className = opts.className;
  return node;
}

function fmtTime(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? String(iso) : d.toLocaleTimeString();
}

function fmtAction(action) {
  if (!action || typeof action !== "object") return String(action ?? "-");
  const name = action.name ?? "?";
  let args = "";
  try {
    args = JSON.stringify(action.args ?? {});
  } catch (e) {
    args = "?";
  }
  return name + "(" + args + ")";
}

function fmtRisk(v) {
  return typeof v === "number" ? v.toFixed(2) : "-";
}

const TRUST_RANK_RE = /^TRUST_RANK_(\d+)$/;

function maxTrustRank(event) {
  const codes = Array.isArray(event.reason_codes) ? event.reason_codes : [];
  let max = null;
  for (const code of codes) {
    const m = TRUST_RANK_RE.exec(String(code));
    if (m) {
      const rank = parseInt(m[1], 10);
      if (max === null || rank > max) max = rank;
    }
  }
  return max;
}

function fmtTrust(event) {
  const rank = maxTrustRank(event);
  if (rank === null) return el("span", { text: "-" });
  const badge = el("span", {
    className: "trust-badge" + (rank >= 4 ? " high" : ""),
    text: "RANK " + rank,
  });
  return badge;
}

function buildRow(event, idx) {
  const row = el("tr", { className: "event-row" });

  const tTime = el("td", { className: "mono-cell", text: fmtTime(event.timestamp) });
  const tStep = el("td", { className: "mono-cell", text: event.step_id ?? "-" });
  const tRun = el("td", { className: "mono-cell truncate", text: event.run_id ?? "-" });
  const tAction = el("td", { className: "truncate", text: fmtAction(event.candidate_action) });

  const decision = (event.decision ?? "unknown").toString();
  const tDecision = el("td");
  const badge = el("span", {
    className: "badge " + (DECISION_CLASS[decision] || "badge-unknown"),
    text: decision,
  });
  tDecision.appendChild(badge);

  const tTrust = el("td", { className: "mono-cell" });
  tTrust.appendChild(fmtTrust(event));

  const tRisk = el("td", { className: "mono-cell", text: fmtRisk(event.risk_score) });

  const tReasons = el("td");
  const reasonCodes = Array.isArray(event.reason_codes) ? event.reason_codes : [];
  if (reasonCodes.length === 0) {
    tReasons.textContent = "-";
  } else {
    for (const code of reasonCodes) {
      tReasons.appendChild(el("span", { className: "reason-code", text: String(code) }));
    }
  }

  const tExplanation = el("td", { className: "truncate", text: event.explanation ?? "-" });

  row.append(tTime, tStep, tRun, tAction, tDecision, tTrust, tRisk, tReasons, tExplanation);

  const detailRow = el("tr", { className: "detail-row hidden" });
  const detailCell = el("td");
  detailCell.colSpan = 9;
  const pre = el("pre", { text: JSON.stringify(event, null, 2) });
  detailCell.appendChild(pre);
  detailRow.appendChild(detailCell);

  row.addEventListener("click", () => {
    detailRow.classList.toggle("hidden");
  });

  return [row, detailRow];
}

let allEvents = [];
const activeDecisions = new Set(["allow", "block", "escalate", "rewrite"]);
let selectedRun = "";

function populateRunSelect(events) {
  const select = document.getElementById("run-select");
  const runIds = [...new Set(events.map((e) => e.run_id).filter((r) => r))].sort();
  const previous = select.value;
  select.innerHTML = "";
  select.appendChild(el("option", { text: "All runs" }));
  select.querySelector("option").value = "";
  for (const runId of runIds) {
    const opt = el("option", { text: runId });
    opt.value = runId;
    select.appendChild(opt);
  }
  // Keep the previous selection if it's still a valid run_id, else fall back to "All runs".
  select.value = runIds.includes(previous) ? previous : "";
  selectedRun = select.value;
}

function filteredEvents() {
  return allEvents.filter((e) => {
    const decision = (e.decision ?? "unknown").toString();
    if (!activeDecisions.has(decision)) return false;
    if (selectedRun && e.run_id !== selectedRun) return false;
    return true;
  });
}

function renderTable() {
  const tbody = document.getElementById("events-body");
  const emptyState = document.getElementById("empty-state");
  const table = document.getElementById("events-table");

  tbody.innerHTML = "";
  const events = filteredEvents();

  if (events.length === 0) {
    emptyState.classList.remove("hidden");
    emptyState.textContent = allEvents.length === 0
      ? "Nothing to show yet. Start a run against the defense proxy to populate traces/run.jsonl."
      : "No events match the current filters.";
    table.classList.add("hidden");
    return;
  }

  emptyState.classList.add("hidden");
  table.classList.remove("hidden");

  events.forEach((event, idx) => {
    const [row, detailRow] = buildRow(event, idx);
    tbody.appendChild(row);
    tbody.appendChild(detailRow);
  });
}

async function refresh() {
  const statusBar = document.getElementById("status-bar");
  const errorsBox = document.getElementById("errors");
  const emptyState = document.getElementById("empty-state");
  const pathLabel = document.getElementById("trace-path");

  let data;
  try {
    const resp = await fetch("/api/events", { cache: "no-store" });
    data = await resp.json();
  } catch (e) {
    statusBar.textContent = "Failed to reach dashboard backend: " + e;
    statusBar.classList.add("error");
    return;
  }

  statusBar.classList.remove("error");
  pathLabel.textContent = data.trace_path;

  if (!data.exists) {
    statusBar.textContent = "No trace file found yet at " + data.trace_path + " - waiting for a run.";
  } else {
    statusBar.textContent = data.count + " event(s) - " + new Date().toLocaleTimeString();
  }

  if (data.errors && data.errors.length > 0) {
    errorsBox.classList.remove("hidden");
    errorsBox.textContent = "Skipped " + data.errors.length + " malformed line(s):\\n" + data.errors.join("\\n");
  } else {
    errorsBox.classList.add("hidden");
    errorsBox.textContent = "";
  }

  allEvents = data.events || [];
  if (!data.exists || allEvents.length === 0) {
    emptyState.classList.remove("hidden");
    emptyState.textContent = data.exists
      ? "Trace file is empty."
      : "Nothing to show yet. Start a run against the defense proxy to populate traces/run.jsonl.";
    document.getElementById("events-table").classList.add("hidden");
    document.getElementById("events-body").innerHTML = "";
    return;
  }

  populateRunSelect(allEvents);
  renderTable();
}

document.getElementById("reload-btn").addEventListener("click", refresh);

for (const btn of document.querySelectorAll(".filter-toggle")) {
  btn.addEventListener("click", () => {
    const decision = btn.dataset.decision;
    const isActive = btn.dataset.active === "true";
    // Never allow toggling to zero active filters - that's indistinguishable from
    // "no events" and hides the table instead of communicating "nothing selected".
    if (isActive && activeDecisions.size === 1) return;
    if (isActive) {
      activeDecisions.delete(decision);
      btn.dataset.active = "false";
    } else {
      activeDecisions.add(decision);
      btn.dataset.active = "true";
    }
    renderTable();
  });
}

document.getElementById("run-select").addEventListener("change", (e) => {
  selectedRun = e.target.value;
  renderTable();
});

let intervalId = null;
function setupAutoRefresh() {
  const checkbox = document.getElementById("auto-refresh");
  if (intervalId) clearInterval(intervalId);
  if (checkbox.checked) {
    intervalId = setInterval(refresh, 2000);
  }
}
document.getElementById("auto-refresh").addEventListener("change", setupAutoRefresh);

refresh();
setupAutoRefresh();
</script>
</body>
</html>
"""
