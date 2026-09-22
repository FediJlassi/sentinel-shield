from __future__ import annotations

from typing import Any, Literal, Optional, Union

import re
from pydantic import BaseModel, Field, field_validator, model_validator

REASON_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
ALLOWED_DECISIONS: frozenset[str] = frozenset({"allow", "block", "escalate", "rewrite"})


class CandidateAction(BaseModel):
    model_config = {"extra": "allow"}
    type: str = ""
    tool: Optional[str] = None
    arguments: Optional[dict[str, Any]] = Field(default_factory=dict)
    content: Optional[str] = None
    final: bool = False
    confirmation_for: Optional[str] = None


class ProvenanceDetail(BaseModel):
    model_config = {"extra": "allow"}
    source_type: Optional[str] = None
    source_id: Optional[str] = None
    trust_level: Optional[Union[str, int]] = None
    origin_actor: Optional[str] = None
    retrieved_via: Optional[str] = None
    sensitivity: Optional[str] = None
    timestamp: Optional[str] = None
    parent_event_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class ProvenanceRecord(BaseModel):
    model_config = {"extra": "allow"}
    id: str = ""
    provenance: ProvenanceDetail = Field(default_factory=ProvenanceDetail)


class ObservationView(BaseModel):
    model_config = {"extra": "allow"}
    kind: Optional[str] = None
    content: Optional[str] = None
    provenance_ids: list[str] = Field(default_factory=list)


class PolicyContext(BaseModel):
    model_config = {"extra": "allow"}
    policy_id: Optional[str] = None
    policy_version: Optional[Union[str, int]] = None
    allowed_tools: list[str] = Field(default_factory=list)
    confirmation_required_tools: list[str] = Field(default_factory=list)
    consequential_tools: list[str] = Field(default_factory=list)
    rules: list[dict[str, Any]] = Field(default_factory=list)


class HistoryDigest(BaseModel):
    model_config = {"extra": "allow"}
    steps_taken: Optional[int] = None
    turn_index: Optional[int] = None
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    confirmations_granted: list[Any] = Field(default_factory=list)
    blocked_count: int = 0
    escalated_count: int = 0
    least_trusted_seen: Optional[Any] = None
    most_sensitive_seen: Optional[Any] = None


class DefenseRequest(BaseModel):
    model_config = {"extra": "allow"}
    run_id: str = ""
    step_id: int = 0
    user_goal: str = ""
    conversation: list[dict[str, Any]] = Field(default_factory=list)
    observation: Optional[ObservationView] = None
    candidate_action: CandidateAction = Field(default_factory=CandidateAction)
    policy_context: PolicyContext = Field(default_factory=PolicyContext)
    provenance: list[ProvenanceRecord] = Field(default_factory=list)
    history_digest: HistoryDigest = Field(default_factory=HistoryDigest)


class DefenseDecision(BaseModel):
    decision: str
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: list[str] = Field(default_factory=list, max_length=16)
    explanation: Optional[str] = None
    rewritten_action: Optional[CandidateAction] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("reason_codes")
    @classmethod
    def _validate_reason_codes(cls, v: list[str]) -> list[str]:
        for code in v:
            if not isinstance(code, str) or not REASON_CODE_RE.match(code):
                raise ValueError(f"reason code {code!r} must be UPPER_SNAKE_CASE")
        return v

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
