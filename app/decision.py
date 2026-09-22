from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

import yaml

try:
    from .schemas import DefenseDecision, DefenseRequest
except ImportError:  # allow `python app/main.py`
    from schemas import DefenseDecision, DefenseRequest

_CODE_SANITIZE = re.compile(r"[^A-Z0-9_]")


def _code_part(kind: Optional[str]) -> str:
    """Normalize an arbitrary rule kind into UPPER_SNAKE_CASE (^[A-Z0-9_]+$)."""
    return _CODE_SANITIZE.sub("_", (kind or "UNKNOWN").upper())

RANK_NAMES: dict[int, str] = {
    0: "system_policy",
    1: "authenticated_user",
    2: "trusted_internal",
    3: "untrusted_internal",
    4: "untrusted_external",
    5: "adversary_controlled",
}

META_TYPES = {"respond", "request_confirmation", "ask_user"}
META_TOOLS = {"respond", "request_confirmation", "ask_user"}

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "configs" / "policy.yaml"


def _is_meta_tool(request: DefenseRequest) -> bool:
    action = request.candidate_action
    return (action.type in META_TYPES) or (action.tool in META_TOOLS)


def load_config(path: Optional[str] = None) -> dict[str, Any]:
    cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
    with cfg_path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _severity_weight(config: dict[str, Any], severity: Optional[str]) -> float:
    weights = config.get("severity_weights", {})
    if severity is None:
        return 0.0
    try:
        return float(weights.get(severity, 0.0))
    except (TypeError, ValueError):
        return 0.0


def compose(
    request: DefenseRequest,
    triggered_rules: list,
    trust_signals: dict[str, Optional[int]],
    config: dict[str, Any],
) -> DefenseDecision:
    triggered = [r for r in triggered_rules if r.triggered]
    risk_score = min(1.0, sum(_severity_weight(config, r.severity) for r in triggered))
    rules_fired = bool(triggered)

    reason_codes: list[str] = []
    explanation_parts: list[str] = []

    decision = "allow"
    confidence = 0.75

    obs_rank = trust_signals.get("observation_rank")
    args_rank = trust_signals.get("args_rank")

    critical = [r for r in triggered if r.severity == "critical"]
    data_flow = [r for r in triggered if r.kind == "data_flow"]
    requires_conf = [r for r in triggered if r.kind == "requires_confirmation"]
    high = [r for r in triggered if r.severity == "high"]

    adversary = (obs_rank == 5) or (args_rank == 5)
    is_meta = _is_meta_tool(request)

    if critical:
        decision = "block"
        confidence = 0.95
        for r in critical:
            reason_codes.append(f"RULE_CRITICAL_{_code_part(r.kind)}")
        explanation_parts.append("critical policy rule triggered")
    elif (data_flow or adversary) and not is_meta:
        decision = "block"
        confidence = 0.95 if adversary else 0.9
        for r in data_flow:
            reason_codes.append(f"DATA_FLOW_{_code_part(r.kind)}")
        if adversary:
            reason_codes.append("ADVERSARY_CONTROL")
            explanation_parts.append("adversary-controlled content (rank 5) detected")
        if data_flow:
            explanation_parts.append("data-flow violation detected")
    elif (requires_conf or high) and not is_meta:
        decision = "escalate"
        confidence = 0.9
        for r in [r for r in triggered if r in requires_conf or r in high]:
            reason_codes.append("MISSING_CONFIRMATION")
            reason_codes.append(f"RULE_{_code_part(r.kind)}")
        explanation_parts.append(
            "high-severity or unconfirmed consequential action requires escalation"
        )
    else:
        for r in triggered:
            reason_codes.append(f"TRIGGERED_{_code_part(r.kind)}")
        if triggered:
            explanation_parts.append("lower-severity rules triggered")
        if is_meta and not critical:
            explanation_parts.append("built-in system tool allowed")

    if (obs_rank is not None and obs_rank > 1) or (args_rank is not None and args_rank > 1):
        if obs_rank is not None and obs_rank > 1:
            reason_codes.append(f"TRUST_RANK_{obs_rank}")
        if args_rank is not None and args_rank > 1:
            reason_codes.append(f"TRUST_RANK_{args_rank}")
        obs_name = RANK_NAMES.get(obs_rank, str(obs_rank)) if obs_rank is not None else "none"
        args_name = RANK_NAMES.get(args_rank, str(args_rank)) if args_rank is not None else "none"
        explanation_parts.append(
            "only system_policy or authenticated_user can authorize sensitive actions; "
            f"observation is rank {obs_rank} ({obs_name}), args rank {args_rank} ({args_name})"
        )

    if not reason_codes:
        reason_codes.append("NO_RULES_TRIGGERED")
        explanation_parts.append("no policy rules triggered")

    if decision == "allow" and rules_fired:
        confidence = 0.9

    explanation = "; ".join(explanation_parts)
    if len(explanation) > 500:
        explanation = explanation[:497] + "..."

    return DefenseDecision(
        decision=decision,
        risk_score=risk_score,
        confidence=confidence,
        reason_codes=reason_codes[:16],
        explanation=explanation,
        rewritten_action=None,
        metadata={
            "triggered_rule_count": len(triggered),
            "observation_rank": obs_rank,
            "args_rank": args_rank,
        },
    )
