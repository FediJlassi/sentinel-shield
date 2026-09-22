from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

ALLOWED_DECISIONS: frozenset[str] = frozenset({"allow", "block", "escalate", "rewrite"})


class ConversationItem(BaseModel):
    role: str
    content: str


class ProvenanceRecord(BaseModel):
    source: str
    trust_level: int
    detail: Optional[str] = None


class ObservationView(BaseModel):
    raw: dict[str, Any] = Field(default_factory=dict)


class CandidateAction(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class HistoryDigest(BaseModel):
    summary: str = ""
    items: list[dict[str, Any]] = Field(default_factory=list)


class DefenseRequest(BaseModel):
    run_id: str
    step_id: int
    user_goal: str
    conversation: list[ConversationItem] = Field(default_factory=list)
    observation: Optional[ObservationView] = None
    candidate_action: CandidateAction
    policy_context: dict[str, Any] = Field(default_factory=dict)
    provenance: list[ProvenanceRecord] = Field(default_factory=list)
    history_digest: HistoryDigest = Field(default_factory=HistoryDigest)


class DefenseDecision(BaseModel):
    decision: str
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: list[str] = Field(default_factory=list)
    explanation: Optional[str] = None
    rewritten_action: Optional[CandidateAction] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("decision")
    @classmethod
    def _validate_decision(cls, v: str) -> str:
        value = v.lower()
        if value not in ALLOWED_DECISIONS:
            raise ValueError(
                f"decision must be one of {sorted(ALLOWED_DECISIONS)}, got {v!r}"
            )
        return value

    @field_validator("explanation")
    @classmethod
    def _validate_explanation(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) > 500:
            raise ValueError("explanation must be at most 500 chars")
        return v

    @model_validator(mode="after")
    def _validate_rewritten_action(self) -> "DefenseDecision":
        if self.decision == "rewrite" and self.rewritten_action is None:
            raise ValueError("rewritten_action is required when decision == 'rewrite'")
        if self.decision != "rewrite" and self.rewritten_action is not None:
            raise ValueError("rewritten_action must be None unless decision == 'rewrite'")
        return self
