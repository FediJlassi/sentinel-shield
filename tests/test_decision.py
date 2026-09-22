from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas import CandidateAction, DefenseDecision

TRACE_FILE = Path(__file__).resolve().parent.parent / "traces" / "run.jsonl"

VALID_BODY = {
    "run_id": "r1",
    "step_id": 0,
    "user_goal": "send the report",
    "candidate_action": {"tool_name": "send_email", "arguments": {"to": "a@b.c"}},
}


@pytest.fixture
def client():
    TRACE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if TRACE_FILE.exists():
        TRACE_FILE.unlink()
    with TestClient(app) as c:
        yield c
    if TRACE_FILE.exists():
        TRACE_FILE.unlink()


def test_valid_request(client):
    resp = client.post("/v1/decision", json=VALID_BODY)
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "allow"
    for field in (
        "decision",
        "risk_score",
        "confidence",
        "reason_codes",
        "explanation",
        "rewritten_action",
        "metadata",
    ):
        assert field in data


def test_trace_hash_chain(client):
    client.post("/v1/decision", json=VALID_BODY)
    client.post("/v1/decision", json=VALID_BODY)

    lines = [line for line in TRACE_FILE.read_text().splitlines() if line.strip()]
    assert len(lines) == 2

    line1_hash = hashlib.sha256(lines[0].encode("utf-8")).hexdigest()
    line2 = json.loads(lines[1])
    assert line2["prev_hash"] == line1_hash


def test_rewritten_action_forbidden_for_allow():
    with pytest.raises(ValueError):
        DefenseDecision(
            decision="allow",
            risk_score=0.0,
            confidence=1.0,
            reason_codes=["X"],
            explanation="e",
            rewritten_action=CandidateAction(tool_name="send_email", arguments={}),
            metadata={},
        )
