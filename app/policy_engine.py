from __future__ import annotations

import hashlib
import json
from typing import Optional

from pydantic import BaseModel

try:
    from .schemas import DefenseRequest
    from .decision import load_config
    from .firewall import build_trust_map, observation_trust
except ImportError:  # allow `python app/main.py`
    from schemas import DefenseRequest
    from decision import load_config
    from firewall import build_trust_map, observation_trust


def observation_rank(request: DefenseRequest) -> Optional[int]:
    trust_map = build_trust_map(request.provenance)
    return observation_trust(request.observation, trust_map)


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


def _is_benign_tool(tool: object, config: dict) -> bool:
    if not isinstance(tool, str):
        return False
    benign = config.get("benign_tools", {}) or {}
    suffixes = benign.get("suffixes", []) or []
    tools = set(benign.get("tools", []) or [])
    if tool in tools:
        return True
    return any(tool.endswith(s) for s in suffixes)


def evaluate(request: DefenseRequest, config: Optional[dict] = None) -> list[TriggeredRule]:
    if config is None:
        config = load_config()
    pc = request.policy_context
    hd = request.history_digest
    candidate = request.candidate_action
    digest = action_digest(candidate)

    max_trusted_rank = config.get("benign_tools", {}).get("max_trusted_rank", 2)

    results: list[TriggeredRule] = []

    candidate_tool = candidate.tool

    for rule in pc.rules:
        kind = rule.get("kind")
        severity = rule.get("severity")
        rule_tool = rule.get("tool")
        detail: Optional[str] = None
        triggered = False

        if kind == "tool_permission":
            # Scope to the candidate tool named by the rule; respond actions (no tool)
            # never emit RULE_TOOL_PERMISSION, and benign non-destructive tools are
            # allowed by default.
            if (
                candidate_tool is not None
                and candidate_tool == rule_tool
                and not _is_benign_tool(candidate_tool, config)
                and candidate_tool not in pc.allowed_tools
            ):
                triggered = True
                detail = f"tool {candidate_tool!r} is not in allowed_tools"

        elif kind == "requires_confirmation":
            # Only applies to the candidate tool named by the rule.
            if candidate_tool is not None and candidate_tool == rule_tool:
                needs_confirm = is_consequential(request, candidate_tool) or requires_confirmation(
                    request, candidate_tool
                )
                if needs_confirm and digest not in hd.confirmations_granted:
                    # Consult the YAML benign classification: non-destructive tools
                    # (reads / note-append / comment) are allowed by default, especially
                    # when the observation trust rank <= 2. Only state-changing money-moving
                    # tools (payment_execute, wire_transfer, ...) escalate.
                    obs_rank = observation_rank(request)
                    if _is_benign_tool(candidate_tool, config) and (
                        obs_rank is None or obs_rank <= max_trusted_rank
                    ):
                        triggered = False
                        detail = f"tool {candidate_tool!r} is a benign non-destructive action; allowed without confirmation"
                    else:
                        triggered = True
                        detail = (
                            f"tool {candidate_tool!r} requires confirmation but digest {digest} "
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
