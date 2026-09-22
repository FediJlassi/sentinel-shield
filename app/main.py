from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, Request

try:
    from .schemas import DefenseDecision, DefenseRequest
    from .trace import log_event
    from .policy_engine import evaluate
    from .firewall import build_trust_map, observation_trust, args_trust
    from .decision import compose, load_config
except ImportError:  # allow `python app/main.py`
    from schemas import DefenseDecision, DefenseRequest
    from trace import log_event
    from policy_engine import evaluate
    from firewall import build_trust_map, observation_trust, args_trust
    from decision import compose, load_config

RAW_PAYLOADS_FILE = Path(__file__).resolve().parent.parent / "traces" / "raw-payloads.jsonl"
CONFIG = load_config()

app = FastAPI(title="sentinel-shield")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


def _append_raw(payload: dict) -> None:
    RAW_PAYLOADS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with RAW_PAYLOADS_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload) + "\n")


@app.post("/v1/decision", response_model=DefenseDecision)
async def decide(request: Request) -> DefenseDecision:
    raw = await request.json()
    _append_raw(raw)

    # Hard short-circuit: the agent calls request_confirmation after a human
    # denial to receive the verdict. This must NEVER reach policy_engine — any
    # exception here causes infinite DEFENSE_UNAVAILABLE retry loops.
    ca = raw.get("candidate_action") if isinstance(raw, dict) else None
    if isinstance(ca, dict) and ca.get("tool") == "request_confirmation" or (
        isinstance(ca, dict) and ca.get("type") == "request_confirmation"
    ):
        decision = DefenseDecision(
            decision="allow",
            risk_score=0.0,
            confidence=1.0,
            reason_codes=["SYSTEM_CONFIRMATION"],
            explanation="system confirmation relay",
            rewritten_action=None,
            metadata={},
        )
        try:
            log_event(
                {
                    "run_id": raw.get("run_id") if isinstance(raw, dict) else None,
                    "step_id": raw.get("step_id") if isinstance(raw, dict) else None,
                    "user_goal": raw.get("user_goal") if isinstance(raw, dict) else None,
                    "candidate_action": {"name": ca.get("tool"), "args": ca.get("arguments")},
                    "decision": decision.decision,
                    "risk_score": decision.risk_score,
                    "confidence": decision.confidence,
                    "reason_codes": decision.reason_codes,
                    "explanation": decision.explanation,
                    "rewritten_action": None,
                }
            )
        except Exception:
            pass
        return decision

    parsed = DefenseRequest.model_validate(raw)

    triggered_rules = evaluate(parsed)
    trust_map = build_trust_map(parsed.provenance)
    observation_rank = observation_trust(parsed.observation, trust_map)
    args_rank = args_trust(parsed.candidate_action.arguments, parsed.conversation, trust_map)
    trust_signals = {"observation_rank": observation_rank, "args_rank": args_rank}

    decision = compose(parsed, triggered_rules, trust_signals, CONFIG)

    log_event(
        {
            "run_id": parsed.run_id,
            "step_id": parsed.step_id,
            "user_goal": parsed.user_goal,
            "candidate_action": {
                "name": parsed.candidate_action.tool,
                "args": parsed.candidate_action.arguments,
            },
            "observation_rank": observation_rank,
            "args_rank": args_rank,
            "decision": decision.decision,
            "risk_score": decision.risk_score,
            "confidence": decision.confidence,
            "reason_codes": decision.reason_codes,
            "explanation": decision.explanation,
            "rewritten_action": (
                decision.rewritten_action.model_dump()
                if decision.rewritten_action is not None
                else None
            ),
        }
    )

    return decision


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8080)
