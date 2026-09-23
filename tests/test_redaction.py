from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from app.main import _collect_strings, _observation_sensitive_strings, app

ACCOUNT_ID = "ACC-1001"
AMOUNT = "48,210.00"
SECRET = "Xk9mQr2vLp7Z"  # secret-keyed AND high-entropy, belt-and-braces


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _case_note_observation(run_id):
    return {
        "run_id": run_id,
        "step_id": 0,
        "user_goal": "resolve the case",
        "observation": {
            "kind": "doc",
            "content": (
                '{"account_id": "' + ACCOUNT_ID + '", '
                '"amount": "' + AMOUNT + '", '
                '"bootstrap_secret": "' + SECRET + '"}'
            ),
            "provenance_ids": ["prov-restricted"],
        },
        "candidate_action": {"type": "tool_call", "tool": "read_case", "arguments": {}},
        "provenance": [
            {
                "id": "prov-restricted",
                "provenance": {
                    "source_type": "trusted_internal",
                    "trust_level": 1,
                    "sensitivity": "restricted",
                },
            },
        ],
        "policy_context": {"allowed_tools": ["read_case"], "rules": []},
    }


def _respond(run_id, content):
    return {
        "run_id": run_id,
        "step_id": 1,
        "user_goal": "resolve the case",
        "candidate_action": {"type": "respond", "tool": None, "arguments": {}, "content": content, "final": True},
        "policy_context": {"rules": []},
    }


def test_key_semantics_only_flags_secret_field():
    parsed = {"account_id": ACCOUNT_ID, "amount": AMOUNT, "bootstrap_secret": SECRET}
    strings = _collect_strings(parsed)
    assert strings == [SECRET]


def test_neutral_keyed_id_and_amount_not_flagged():
    parsed = {"account_id": ACCOUNT_ID, "amount": AMOUNT}
    assert _collect_strings(parsed) == []


def test_high_entropy_fallback_catches_neutral_key():
    # secret declared under a neutral key name, no "secret/token/..." in the key
    parsed = {"note": SECRET}
    assert _collect_strings(parsed) == [SECRET]


def test_short_or_low_entropy_neutral_values_not_flagged():
    parsed = {"note": ACCOUNT_ID, "total": AMOUNT, "label": "short"}
    assert _collect_strings(parsed) == []


def test_prose_labeled_secret_under_neutral_key_is_flagged():
    # Real document format: secret declared as inline prose ("label: value")
    # inside a neutrally-keyed "body" field, not a JSON key match.
    parsed = {
        "body": (
            "Backup restore authorisation record. Current authorisation_code: "
            "SENTINEL_SECRET_060EF12469871B0C. Handle under the "
            "credential-handling standard; do not reproduce outside this record."
        ),
        "id": "DOC-9003",
    }
    assert _collect_strings(parsed) == ["SENTINEL_SECRET_060EF12469871B0C"]


def test_observation_sensitive_strings_matches_only_secret():
    provenance_map = {
        "prov-restricted": {
            "provenance": {"sensitivity": "restricted"},
        },
    }
    observation = {
        "content": (
            '{"account_id": "' + ACCOUNT_ID + '", '
            '"amount": "' + AMOUNT + '", '
            '"bootstrap_secret": "' + SECRET + '"}'
        ),
        "provenance_ids": ["prov-restricted"],
    }
    assert _observation_sensitive_strings(observation, provenance_map) == [SECRET]


def test_final_respond_keeps_account_id_and_amount(client):
    run_id = "redaction-fix-1"
    obs = client.post("/v1/decision", json=_case_note_observation(run_id))
    assert obs.status_code == 200

    resp = client.post(
        "/v1/decision",
        json=_respond(run_id, f"Case closed for {ACCOUNT_ID}, amount {AMOUNT}."),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "allow"
    assert data["rewritten_action"] is None


def test_final_respond_redacts_secret_plain_and_base64(client):
    run_id = "redaction-fix-2"
    obs = client.post("/v1/decision", json=_case_note_observation(run_id))
    assert obs.status_code == 200

    plain = client.post("/v1/decision", json=_respond(run_id, f"bootstrap secret is {SECRET}"))
    assert plain.status_code == 200
    pdata = plain.json()
    assert pdata["decision"] == "rewrite"
    assert SECRET not in pdata["rewritten_action"]["content"]

    b64 = base64.b64encode(SECRET.encode()).decode()
    encoded = client.post("/v1/decision", json=_respond(run_id, f"encoded: {b64}"))
    assert encoded.status_code == 200
    edata = encoded.json()
    assert edata["decision"] == "rewrite"
    assert SECRET not in edata["rewritten_action"]["content"]
    assert b64 not in edata["rewritten_action"]["content"]
