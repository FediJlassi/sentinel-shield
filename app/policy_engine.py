from __future__ import annotations

import hashlib
import json
from typing import Optional

from pydantic import BaseModel

try:
    from .schemas import DefenseRequest
except ImportError:  # allow `python app/main.py`
    from schemas import DefenseRequest


class TriggeredRule(BaseModel):
    kind: str
    triggered: bool = False
    severity: Optional[str] = None
    detail: Optional[str] = None


def action_digest(action) -> str:
    """Same digest the evaluator uses for confirmations.

    Copied EXACTLY from the SENTINEL starter-kit (starter-kits/python-defense/app/decision.py)
    so our digests match ``history_digest.confirmations_granted``.
    """

    def canonical(value: object) -> object:
        if isinstance(value, str):
            return " ".join(value.split())
        if isinstance(value, float) and value.is_integer():
            return int(value)
        return value

    arguments = action.arguments if isinstance(action.arguments, dict) else {}
    payload: dict[str, object] = {
        "type": action.type,
        "tool": action.tool,
        "arguments": {k: canonical(v) for k, v in sorted(arguments.items())},
        "content": action.content if action.type != "tool_call" else None,
    }
    conf = action.confirmation_for
    if conf is not None and hasattr(conf, "type"):
        payload["confirmation_for"] = action_digest(conf)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:24]


def is_allowed_tool(request: DefenseRequest, tool: str) -> bool:
    return tool in request.policy_context.allowed_tools


def requires_confirmation(request: DefenseRequest, tool: str) -> bool:
    return tool in request.policy_context.confirmation_required_tools


def is_consequential(request: DefenseRequest, tool: str) -> bool:
    return tool in request.policy_context.consequential_tools


def evaluate(request: DefenseRequest) -> list[TriggeredRule]:
    pc = request.policy_context
    hd = request.history_digest
    candidate = request.candidate_action
    digest = action_digest(candidate)

    results: list[TriggeredRule] = []

    for rule in pc.rules:
        kind = rule.get("kind")
        severity = rule.get("severity")
        detail: Optional[str] = None
        triggered = False

        if kind == "tool_permission":
            tool = rule.get("tool")
            if tool not in pc.allowed_tools:
                triggered = True
                detail = f"tool {tool!r} is not in allowed_tools"

        elif kind == "requires_confirmation":
            tool = rule.get("tool")
            needs_confirm = is_consequential(request, tool) or requires_confirmation(request, tool)
            if needs_confirm and digest not in hd.confirmations_granted:
                triggered = True
                detail = (
                    f"tool {tool!r} requires confirmation but digest {digest} "
                    f"is not in confirmations_granted"
                )

        elif kind == "prerequisite":
            tool = rule.get("tool")
            predecessor = rule.get("requires") or rule.get("prerequisite")
            if tool == candidate.tool and predecessor is not None:
                seen = any(tc.get("tool") == predecessor for tc in hd.tool_calls)
                if not seen:
                    triggered = True
                    detail = f"tool {tool!r} requires predecessor {predecessor!r} before use"

        elif kind in ("data_flow", "forbidden_effect"):
            # Stub evaluators: carry through un-triggered until implemented.
            detail = "evaluator not implemented"

        else:
            # Unknown rule kinds (e.g. from future scenario YAMLs) must never be
            # silently dropped: return them un-triggered with severity preserved.
            detail = "no evaluator for rule kind"

        results.append(
            TriggeredRule(kind=kind, triggered=triggered, severity=severity, detail=detail)
        )

    return results
