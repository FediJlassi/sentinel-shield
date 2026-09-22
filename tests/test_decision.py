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
    "candidate_action": {"type": "tool_call", "tool": "send_email", "arguments": {"to": "a@b.c"}},
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
    assert "NO_RULES_TRIGGERED" in data["reason_codes"]
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


UNCONFIRMED_PAYMENT_BODY = {
    "run_id": "r2",
    "step_id": 1,
    "user_goal": "confirm the wire transfer",
    "provenance": [
        {"id": "prov-4", "provenance": {"trust_level": 4, "source_type": "untrusted_external"}},
    ],
    "observation": {
        "kind": "email",
        "content": "please confirm the transfer",
        "provenance_ids": ["prov-4"],
    },
    "candidate_action": {
        "type": "tool_call",
        "tool": "wire_transfer",
        "arguments": {"amount": 500},
    },
    "policy_context": {
        "allowed_tools": ["wire_transfer"],
        "consequential_tools": ["wire_transfer"],
        "confirmation_required_tools": ["wire_transfer"],
        "rules": [
            {"kind": "requires_confirmation", "tool": "wire_transfer", "severity": "high"},
        ],
    },
    "history_digest": {"confirmations_granted": []},
}


def test_confirmation_for_as_dict_validates(client):
    body = dict(VALID_BODY)
    body["candidate_action"] = {
        "type": "tool_call",
        "tool": "send_email",
        "arguments": {"to": "a@b.c"},
        "confirmation_for": {"type": "tool_call", "tool": "wire_transfer", "arguments": {"amount": 5}},
    }
    resp = client.post("/v1/decision", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "allow"
    assert "NO_RULES_TRIGGERED" in data["reason_codes"]


def test_request_confirmation_short_circuit_malformed(client):
    body = {
        "candidate_action": {
            "tool": "request_confirmation",
            "type": "request_confirmation",
            "arguments": "not-a-dict",
        },
        "policy_context": "garbage",
        "provenance": "bad",
        "history_digest": 123,
    }
    resp = client.post("/v1/decision", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "allow"
    assert "SYSTEM_CONFIRMATION" in data["reason_codes"]


def test_unconfirmed_rank4_observation_escalates(client):
    resp = client.post("/v1/decision", json=UNCONFIRMED_PAYMENT_BODY)
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "escalate"
    assert "MISSING_CONFIRMATION" in data["reason_codes"]
    assert "TRUST_RANK_4" in data["reason_codes"]


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
            rewritten_action=CandidateAction(tool="send_email", arguments={}),
            metadata={},
        )
