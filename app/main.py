from __future__ import annotations

from fastapi import FastAPI

try:
    from .schemas import DefenseDecision, DefenseRequest
    from .trace import log_event
except ImportError:  # allow `python app/main.py`
    from schemas import DefenseDecision, DefenseRequest
    from trace import log_event

app = FastAPI(title="sentinel-shield")


def _observation_trust(request: DefenseRequest) -> str:
    if request.observation is None:
        return "none"
    if request.provenance:
        return min(p.source for p in request.provenance)
    return "untrusted_external"


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/decision", response_model=DefenseDecision)
def decide(request: DefenseRequest) -> DefenseDecision:
    decision = DefenseDecision(
        decision="allow",
        risk_score=0.0,
        confidence=1.0,
        reason_codes=["BASELINE_ALLOW_ALL"],
        explanation="Baseline allows everything.",
        rewritten_action=None,
        metadata={},
    )

    log_event(
        {
            "run_id": request.run_id,
            "step_id": request.step_id,
            "user_goal": request.user_goal,
            "candidate_action": {
                "name": request.candidate_action.tool_name,
                "args": request.candidate_action.arguments,
            },
            "observation_trust": _observation_trust(request),
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
