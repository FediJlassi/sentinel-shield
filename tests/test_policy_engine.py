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
    # The real simulator never scopes a tool_permission rule to one tool name
    # (defense_context only ever sends {id, kind, severity, description}) --
    # it's a blanket rule checked against whichever tool is being called.
    req = _request(
        {
            "allowed_tools": ["read_file"],
            "consequential_tools": [],
            "confirmation_required_tools": [],
            "rules": [{"kind": "tool_permission", "severity": "high"}],
        }
    )
    rules = evaluate(req)
    assert len(rules) == 1
    assert rules[0].kind == "tool_permission"
    assert rules[0].triggered is True
    assert rules[0].severity == "high"


def test_allowed_tool_does_not_trigger_permission():
    req = _request(
        {
            "allowed_tools": ["send_email"],
            "consequential_tools": [],
            "confirmation_required_tools": [],
            "rules": [{"kind": "tool_permission", "severity": "high"}],
        }
    )
    rules = evaluate(req)
    assert rules[0].triggered is False


def test_confirmed_tool_does_not_trigger():
    candidate = {"type": "tool_call", "tool": "wire_transfer", "arguments": {"amount": 100}}
    req = _request(
        {
            "allowed_tools": ["wire_transfer"],
            "consequential_tools": ["wire_transfer"],
            "confirmation_required_tools": ["wire_transfer"],
            "rules": [{"kind": "requires_confirmation", "severity": "critical"}],
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
            "rules": [{"kind": "requires_confirmation", "severity": "critical"}],
        },
        candidate=candidate,
    )
    rules = evaluate(req)
    assert rules[0].triggered is True
    assert rules[0].severity == "critical"


def test_execute_without_confirm_predecessor_triggers_prerequisite():
    candidate = {"type": "tool_call", "tool": "payment_execute", "arguments": {}}
    req = _request(
        {
            "allowed_tools": ["payment_prepare", "payment_confirm", "payment_execute"],
            "consequential_tools": ["payment_execute"],
            "confirmation_required_tools": [],
            "rules": [{"kind": "prerequisite", "severity": "high"}],
        },
        candidate=candidate,
        history_digest={"tool_calls": [{"tool": "payment_prepare"}]},
    )
    rules = evaluate(req)
    assert rules[0].kind == "prerequisite"
    assert rules[0].triggered is True


def test_execute_with_confirm_predecessor_does_not_trigger_prerequisite():
    candidate = {"type": "tool_call", "tool": "payment_execute", "arguments": {}}
    req = _request(
        {
            "allowed_tools": ["payment_prepare", "payment_confirm", "payment_execute"],
            "consequential_tools": ["payment_execute"],
            "confirmation_required_tools": [],
            "rules": [{"kind": "prerequisite", "severity": "high"}],
        },
        candidate=candidate,
        history_digest={"tool_calls": [{"tool": "payment_prepare"}, {"tool": "payment_confirm"}]},
    )
    rules = evaluate(req)
    assert rules[0].triggered is False


def test_execute_without_prepare_triggers_prerequisite_no_confirm_tool():
    candidate = {"type": "tool_call", "tool": "remediation_execute", "arguments": {}}
    req = _request(
        {
            "allowed_tools": ["remediation_prepare", "remediation_execute"],
            "consequential_tools": ["remediation_execute"],
            "confirmation_required_tools": [],
            "rules": [{"kind": "prerequisite", "severity": "high"}],
        },
        candidate=candidate,
        history_digest={"tool_calls": []},
    )
    rules = evaluate(req)
    assert rules[0].triggered is True


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


def test_benign_read_does_not_escalate():
    # wiki_search / email_search are benign reads: even if listed in
    # confirmation_required_tools with no granted confirmation, they must NOT
    # trigger MISSING_CONFIRMATION (YAML benign-read classification wins).
    req = _request(
        {
            "allowed_tools": ["wiki_search"],
            "consequential_tools": [],
            "confirmation_required_tools": ["wiki_search"],
            "rules": [{"kind": "requires_confirmation", "severity": "high"}],
        },
        candidate={"type": "tool_call", "tool": "wiki_search", "arguments": {"q": "status"}},
    )
    rules = evaluate(req)
    assert rules[0].kind == "requires_confirmation"
    assert rules[0].triggered is False


def test_state_changing_requires_confirmation_still_triggers():
    req = _request(
        {
            "allowed_tools": ["wire_transfer"],
            "consequential_tools": ["wire_transfer"],
            "confirmation_required_tools": ["wire_transfer"],
            "rules": [{"kind": "requires_confirmation", "severity": "high"}],
        },
        candidate={"type": "tool_call", "tool": "wire_transfer", "arguments": {"amount": 100}},
    )
    rules = evaluate(req)
    assert rules[0].triggered is True


def test_closing_status_escalates_an_otherwise_benign_tool():
    # ticket_update/incident_update are benign for a plain note, but the
    # simulator's own is_consequential() is argument-dependent: closing a
    # ticket/incident is consequential even though the static
    # consequential_tools/confirmation_required_tools lists never say so.
    req = _request(
        {
            "allowed_tools": ["ticket_update"],
            "consequential_tools": [],
            "confirmation_required_tools": [],
            "rules": [{"kind": "requires_confirmation", "severity": "high"}],
        },
        candidate={
            "type": "tool_call",
            "tool": "ticket_update",
            "arguments": {"ticket_id": "TCK-1", "status": "closed", "note": "done"},
        },
    )
    rules = evaluate(req)
    assert rules[0].triggered is True


def test_plain_note_on_benign_tool_still_allowed():
    req = _request(
        {
            "allowed_tools": ["ticket_update"],
            "consequential_tools": [],
            "confirmation_required_tools": [],
            "rules": [{"kind": "requires_confirmation", "severity": "high"}],
        },
        candidate={
            "type": "tool_call",
            "tool": "ticket_update",
            "arguments": {"ticket_id": "TCK-1", "note": "still open"},
        },
    )
    rules = evaluate(req)
    assert rules[0].triggered is False
