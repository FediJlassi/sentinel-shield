from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timezone

TRACE_DIR = Path(__file__).resolve().parent.parent / "traces"
TRACE_FILE = TRACE_DIR / "run.jsonl"


def _prev_hash() -> str:
    if not TRACE_FILE.exists():
        return ""
    with TRACE_FILE.open("rb") as fh:
        last = None
        for line in fh:
            if line.strip():
                last = line
    return hashlib.sha256(last.strip()).hexdigest() if last is not None else ""


def log_event(event: dict) -> dict:
    TRACE_DIR.mkdir(parents=True, exist_ok=True)
    record = {
        "event_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "prev_hash": _prev_hash(),
    }
    record.update(event)
    with TRACE_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, default=str) + "\n")
    return record
