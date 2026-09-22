from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import yaml

from .schemas import DefenseDecision, DefenseRequest

RANK_NAMES: dict[int, str] = {
    0: "system_policy",
    1: "authenticated_user",
    2: "trusted_internal",
    3: "untrusted_internal",
    4: "untrusted_external",
    5: "adversary_controlled",
}

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "configs" / "policy.yaml"


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
    tool = request.candidate_action.tool
    consequential = tool in request.policy_context.consequential_tools

    critical = [r for r in triggered if r.severity == "critical"]
    data_flow = [r for r in triggered if r.kind == "data_flow"]
    requires_conf = [r for r in triggered if r.kind == "requires_confirmation"]
    high = [r for r in triggered if r.severity == "high"]

    if critical:
        decision = "block"
        confidence = 0.95
        for r in critical:
            reason_codes.append(f"RULE_CRITICAL:{r.kind}")
        explanation_parts.append("critical policy rule triggered")
    elif data_flow:
        decision = "block"
        confidence = 0.9
        for r in data_flow:
            reason_codes.append(f"DATA_FLOW:{r.kind}")
        explanation_parts.append("data-flow violation detected")
    elif requires_conf:
        decision = "escalate"
        confidence = 0.9
        for r in requires_conf:
            reason_codes.append("MISSING_CONFIRMATION")
            reason_codes.append(f"RULE_ID:{r.kind}")
        explanation_parts.append("consequential action without recorded human confirmation")
    elif high:
        if consequential:
            decision = "escalate"
            confidence = 0.9
            reason_codes.append("HIGH_SEVERITY_CONSEQUENTIAL")
            explanation_parts.append("high-severity rule on a consequential tool")
        else:
            decision = "block"
            confidence = 0.9
            reason_codes.append("HIGH_SEVERITY")
            explanation_parts.append("high-severity rule triggered")
    else:
        for r in triggered:
            reason_codes.append(f"TRIGGERED:{r.kind}")
        if triggered:
            explanation_parts.append("lower-severity rules triggered")

    obs_rank = trust_signals.get("observation_rank")
    args_rank = trust_signals.get("args_rank")
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
