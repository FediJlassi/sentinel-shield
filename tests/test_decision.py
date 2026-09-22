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


REDACTION = "[REDACTED — restricted per policy]"
CANARY = "CANARY_SECRET_987654321"


def _observation_step(run_id, sensitivity="restricted"):
    return {
        "run_id": run_id,
        "step_id": 0,
        "user_goal": "research",
        "observation": {
            "kind": "doc",
            "content": '{"note": "' + CANARY + '", "ok": true}',
            "provenance_ids": ["prov-r"],
        },
        "candidate_action": {"type": "tool_call", "tool": "read_file", "arguments": {}},
        "provenance": [
            {"id": "prov-r", "provenance": {"source_type": "untrusted_external", "trust_level": 3, "sensitivity": sensitivity}},
        ],
        "policy_context": {"allowed_tools": ["read_file"], "rules": []},
    }


def _respond_step(run_id, content, final=True):
    return {
        "run_id": run_id,
        "step_id": 1,
        "user_goal": "research",
        "candidate_action": {"type": "respond", "tool": None, "arguments": {}, "content": content, "final": final},
        "policy_context": {"rules": []},
    }


def test_sensitive_respond_redaction(client):
    import base64

    run_id = "sens-synthetic-1"

    obs = client.post("/v1/decision", json=_observation_step(run_id))
    assert obs.status_code == 200

    leak = client.post("/v1/decision", json=_respond_step(run_id, f"Here is the answer: {CANARY}"))
    assert leak.status_code == 200
    d = leak.json()
    assert d["decision"] == "rewrite"
    assert "SENSITIVE_TO_USER_SINK" in d["reason_codes"]
    assert "REDACTED" in d["reason_codes"]
    assert CANARY not in d["rewritten_action"]["content"]
    assert REDACTION in d["rewritten_action"]["content"]
    assert "restricted" in d["explanation"]

    clean = client.post("/v1/decision", json=_respond_step(run_id, "The benign facts are 1+1=2."))
    assert clean.status_code == 200
    assert clean.json()["decision"] == "allow"

    b64 = base64.b64encode(CANARY.encode()).decode()
    encoded = client.post("/v1/decision", json=_respond_step(run_id, b64))
    assert encoded.status_code == 200
    ed = encoded.json()
    assert ed["decision"] == "rewrite"
    assert CANARY not in ed["rewritten_action"]["content"]


def test_respond_skips_tool_permission(client):
    run_id = "sens-synthetic-2"
    body = {
        "run_id": run_id,
        "step_id": 1,
        "user_goal": "x",
        "candidate_action": {"type": "respond", "tool": None, "arguments": {}, "content": "hi", "final": True},
        "policy_context": {
            "allowed_tools": [],
            "rules": [{"kind": "tool_permission", "tool": "read_file", "severity": "high"}],
        },
    }
    resp = client.post("/v1/decision", json=body)
    assert resp.status_code == 200
    assert "RULE_TOOL_PERMISSION" not in resp.json()["reason_codes"]
