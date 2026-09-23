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


def _has_consequential_argument(candidate, config: dict) -> bool:
    """Some tools (ticket_update, incident_update, ...) are benign for a plain
    note but consequential when they close/resolve a record -- the simulator's
    own ToolInfo.is_consequential() is argument-dependent, but defense_context()
    only ever exposes a static per-tool consequential_tools list, so that
    distinction never reaches us there. Read it off the arguments directly
    instead, generically, via configs/policy.yaml (never a specific tool name).
    """
    fields = config.get("consequential_arguments", {}).get("fields", {}) or {}
    args = candidate.arguments if isinstance(candidate.arguments, dict) else {}
    for key, values in fields.items():
        value = args.get(key)
        if isinstance(value, str) and value.lower() in {str(v).lower() for v in values}:
            return True
    return False


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
        detail: Optional[str] = None
        triggered = False

        # NOTE: the real simulator's defense_context() only ever sends
        # {id, kind, severity, description} for every rule -- it never scopes a
        # rule to one tool name or carries prerequisite pairs (verified against
        # captured traces/raw-payloads.jsonl for enterprise_standard/
        # finance_standard/soc_standard). Rules are blanket, per-kind directives
        # that apply to whichever tool the agent is calling right now; matching
        # on a `rule.get("tool")` that never arrives silently disables the rule.

        if kind == "tool_permission":
            # allowed_tools is the simulator's own hard boundary -- never bypassed
            # by the "benign tool" heuristic below, which only governs whether a
            # permitted tool still needs confirmation.
            if candidate_tool is not None and candidate_tool not in pc.allowed_tools:
                triggered = True
                detail = f"tool {candidate_tool!r} is not in allowed_tools"

        elif kind == "requires_confirmation":
            if candidate_tool is not None:
                closing = _has_consequential_argument(candidate, config)
                needs_confirm = (
                    is_consequential(request, candidate_tool)
                    or requires_confirmation(request, candidate_tool)
                    or closing
                )
                if needs_confirm and digest not in hd.confirmations_granted:
                    # Consult the YAML benign classification: non-destructive tools
                    # (reads / note-append / comment) are allowed by default, especially
                    # when the observation trust rank <= 2. Only state-changing money-moving
                    # tools (payment_execute, wire_transfer, ...) escalate. A closing/resolving
                    # argument always escalates even for an otherwise-benign tool name.
                    obs_rank = observation_rank(request)
                    if (
                        not closing
                        and _is_benign_tool(candidate_tool, config)
                        and (obs_rank is None or obs_rank <= max_trusted_rank)
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
            # Inferred generically from the candidate tool's own "<prefix>_execute"
            # naming convention plus this policy's own allowed_tools -- covers
            # payment_prepare->payment_confirm->payment_execute and
            # remediation_prepare->remediation_execute alike without hard-coding
            # either domain.
            if isinstance(candidate_tool, str) and candidate_tool.endswith("_execute"):
                prefix = candidate_tool[: -len("_execute")]
                predecessor = None
                for suffix in ("_confirm", "_prepare"):
                    if f"{prefix}{suffix}" in pc.allowed_tools:
                        predecessor = f"{prefix}{suffix}"
                        break
                if predecessor is not None:
                    seen = any(tc.get("tool") == predecessor for tc in hd.tool_calls)
                    if not seen:
                        triggered = True
                        detail = f"tool {candidate_tool!r} requires predecessor {predecessor!r} before use"

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
