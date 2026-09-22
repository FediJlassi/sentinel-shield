from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, Request

try:
    from .schemas import DefenseDecision, DefenseRequest
    from .trace import log_event
except ImportError:  # allow `python app/main.py`
    from schemas import DefenseDecision, DefenseRequest
    from trace import log_event

RAW_PAYLOADS_FILE = Path(__file__).resolve().parent.parent / "traces" / "raw-payloads.jsonl"

app = FastAPI(title="sentinel-shield")


def _observation_trust(request: DefenseRequest) -> str:
    if request.observation is None:
        return "none"
    levels = [p.provenance.trust_level for p in request.provenance if p.provenance.trust_level is not None]
    if levels:
        return min(levels)
    return "untrusted_external"


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

    parsed = DefenseRequest.model_validate(raw)

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
            "run_id": parsed.run_id,
            "step_id": parsed.step_id,
            "user_goal": parsed.user_goal,
            "candidate_action": {
                "name": parsed.candidate_action.tool,
                "args": parsed.candidate_action.arguments,
            },
            "observation_trust": _observation_trust(parsed),
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
