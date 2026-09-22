from __future__ import annotations

from app.policy_engine import action_digest, evaluate
from app.schemas import CandidateAction, DefenseRequest


def _request(policy_context: dict, candidate: dict | None = None, history_digest: dict | None = None) -> DefenseRequest:
    return DefenseRequest(
        policy_context=policy_context,
        candidate_action=candidate or {"type": "tool_call", "tool": "send_email", "arguments": {"to": "a@b.c"}},
        history_digest=history_digest or {},
    )


def test_unlisted_tool_triggers():
    req = _request(
        {
            "allowed_tools": ["read_file"],
            "consequential_tools": [],
            "confirmation_required_tools": [],
            "rules": [{"kind": "tool_permission", "tool": "send_email", "severity": "high"}],
        }
    )
    rules = evaluate(req)
    assert len(rules) == 1
    assert rules[0].kind == "tool_permission"
    assert rules[0].triggered is True
    assert rules[0].severity == "high"


def test_confirmed_tool_does_not_trigger():
    candidate = {"type": "tool_call", "tool": "wire_transfer", "arguments": {"amount": 100}}
    req = _request(
        {
            "allowed_tools": ["wire_transfer"],
            "consequential_tools": ["wire_transfer"],
            "confirmation_required_tools": ["wire_transfer"],
            "rules": [{"kind": "requires_confirmation", "tool": "wire_transfer", "severity": "critical"}],
        },
        candidate=candidate,
    )
    digest = action_digest(req.candidate_action)
    req.history_digest.confirmations_granted = [digest]
    rules = evaluate(req)
    assert rules[0].triggered is False


def test_unconfirmed_consequential_triggers():
    candidate = {"type": "tool_call", "tool": "wire_transfer", "arguments": {"amount": 100}}
    req = _request(
        {
            "allowed_tools": ["wire_transfer"],
            "consequential_tools": ["wire_transfer"],
            "confirmation_required_tools": ["wire_transfer"],
            "rules": [{"kind": "requires_confirmation", "tool": "wire_transfer", "severity": "critical"}],
        },
        candidate=candidate,
    )
    rules = evaluate(req)
    assert rules[0].triggered is True
    assert rules[0].severity == "critical"


def test_unknown_kind_passes_through_untriggered():
    req = _request(
        {
            "allowed_tools": ["read_file"],
            "consequential_tools": [],
            "confirmation_required_tools": [],
            "rules": [{"kind": "future_experimental_kind", "severity": "medium"}],
        }
    )
    rules = evaluate(req)
    assert len(rules) == 1
    assert rules[0].kind == "future_experimental_kind"
    assert rules[0].triggered is False
    assert rules[0].severity == "medium"
