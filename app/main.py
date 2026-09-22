from __future__ import annotations

from fastapi import FastAPI

try:
    from .schemas import DefenseDecision, DefenseRequest
except ImportError:  # allow `python app/main.py`
    from schemas import DefenseDecision, DefenseRequest

app = FastAPI(title="sentinel-shield")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/decision", response_model=DefenseDecision)
def decide(request: DefenseRequest) -> DefenseDecision:
    return DefenseDecision(
        decision="allow",
        risk_score=0.0,
        confidence=1.0,
        reason_codes=["BASELINE_ALLOW_ALL"],
        explanation="Baseline allows everything.",
        rewritten_action=None,
        metadata={},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8080)
