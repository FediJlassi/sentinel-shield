from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

from fastapi import FastAPI, Request

try:
    from .schemas import CandidateAction, DefenseDecision, DefenseRequest
    from .trace import log_event
    from .policy_engine import evaluate
    from .firewall import build_trust_map, observation_trust, args_trust
    from .decision import compose, load_config
except ImportError:  # allow `python app/main.py`
    from schemas import CandidateAction, DefenseDecision, DefenseRequest
    from trace import log_event
    from policy_engine import evaluate
    from firewall import build_trust_map, observation_trust, args_trust
    from decision import compose, load_config

RAW_PAYLOADS_FILE = Path(__file__).resolve().parent.parent / "traces" / "raw-payloads.jsonl"
CONFIG = load_config()

# Run-scoped sensitive-content tracking. Keyed off the provenance `sensitivity`
# field (not trust rank): canary docs are trusted_internal but sensitivity=restricted.
# Value: {"strings": set[str], "sensitivity": str | None}
run_state: dict[str, dict] = {}

SENSITIVE_SENSITIVITIES = {"restricted", "confidential"}
REDACTION_TOKEN = "[REDACTED — restricted per policy]"


def _d(obj: object, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


# Field semantics, not scenario/canary names: a value is only redaction-worthy
# if it sits under a secret-shaped key, or is declared inline as prose
# ("Current bootstrap_secret: ...", the real document format), or — as a
# fallback for secrets declared under a neutral key with no label at all —
# looks high-entropy. Neutral-keyed facts the task legitimately needs back
# (account IDs, formatted amounts) must NOT be swept in just for being a
# long string.
SENSITIVE_KEY_RE = re.compile(r"secret|token|key|code|credential|password|passphrase", re.IGNORECASE)
# Inline "label: value" declarations inside prose/document text, e.g.
# "Current authorisation_code: SENTINEL_SECRET_...". label stays unanchored
# (word chars/hyphen only) so it lines up with SENSITIVE_KEY_RE either way.
LABELED_VALUE_RE = re.compile(r"([A-Za-z][A-Za-z0-9_\-]*)\s*:\s*([^\s.,;]+)")


def _is_high_entropy(s: str) -> bool:
    if len(s) < 12 or not s.isalnum():
        return False
    has_upper = any(c.isupper() for c in s)
    has_lower = any(c.islower() for c in s)
    has_digit = any(c.isdigit() for c in s)
    return has_upper and has_lower and has_digit


def _labeled_values(text: str) -> list[str]:
    out = []
    for label, value in LABELED_VALUE_RE.findall(text):
        if SENSITIVE_KEY_RE.search(label) and len(value) >= 8:
            out.append(value)
    return out


def _collect_strings(obj, key_hint: str | None = None) -> list[str]:
    out: list[str] = []
    if isinstance(obj, str):
        key_match = bool(key_hint and SENSITIVE_KEY_RE.search(key_hint))
        if (key_match and len(obj) >= 8) or _is_high_entropy(obj):
            out.append(obj)
        out.extend(_labeled_values(obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_collect_strings(v, key_hint=str(k)))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_collect_strings(v, key_hint=key_hint))
    return out


def _observation_sensitive_strings(observation, provenance_map) -> list[str]:
    if observation is None:
        return []
    pids = _d(observation, "provenance_ids") or []
    sensitive = False
    for pid in pids:
        rec = provenance_map.get(pid)
        if rec is None:
            continue
        prov = _d(rec, "provenance")
        prov = prov if isinstance(prov, dict) else getattr(prov, "__dict__", {})
        if (prov.get("sensitivity") or "").lower() in SENSITIVE_SENSITIVITIES:
            sensitive = True
            break
    if not sensitive:
        return []
    content = _d(observation, "content")
    if not isinstance(content, str):
        return []
    try:
        parsed = json.loads(content)
    except (ValueError, TypeError):
        parsed = content
    return _collect_strings(parsed)


def update_run_state(request: DefenseRequest) -> list[str]:
    provenance_map: dict = {}
    for rec in request.provenance:
        rid = _d(rec, "id")
        if rid is not None:
            provenance_map[rid] = rec

    strings = _observation_sensitive_strings(request.observation, provenance_map)
    if not strings:
        return []

    state = run_state.setdefault(request.run_id, {"strings": set(), "sensitivity": None})
    new_hashes: list[str] = []
    for s in strings:
        if s not in state["strings"]:
            state["strings"].add(s)
            new_hashes.append(hashlib.sha256(s.encode("utf-8")).hexdigest())

    for pid in _d(request.observation, "provenance_ids") or []:
        rec = provenance_map.get(pid)
        if rec is None:
            continue
        prov = _d(rec, "provenance")
        prov = prov if isinstance(prov, dict) else getattr(prov, "__dict__", {})
        sens = (prov.get("sensitivity") or "").lower()
        if sens == "restricted":
            state["sensitivity"] = "restricted"
        elif sens == "confidential" and state["sensitivity"] != "restricted":
            state["sensitivity"] = "confidential"
    return new_hashes


def _leaked(content: str, sensitive: set) -> bool:
    if not content:
        return False
    for s in sensitive:
        if not s:
            continue
        for variant in (
            s,
            base64.b64encode(s.encode()).decode(),
            s.encode().hex(),
            s[::-1],
        ):
            if variant and variant in content:
                return True
    return False


def _redact(content: str, sensitive: set) -> str:
    redacted = content
    for s in sensitive:
        if not s:
            continue
        for variant in (
            s,
            base64.b64encode(s.encode()).decode(),
            s.encode().hex(),
            s[::-1],
        ):
            if variant and variant in redacted:
                redacted = redacted.replace(variant, REDACTION_TOKEN)
    return redacted


def scan_respond(request: DefenseRequest) -> DefenseDecision | None:
    candidate = request.candidate_action
    is_respond = bool(candidate.final) or candidate.type == "respond"
    if not is_respond:
        return None
    state = run_state.get(request.run_id)
    if not state:
        return None
    sensitive = state["strings"]
    content = candidate.content or ""
    if not _leaked(content, sensitive):
        return None
    sensitivity = state.get("sensitivity") or "restricted"
    rewritten = CandidateAction(
        type=candidate.type,
        tool=candidate.tool,
        arguments=candidate.arguments,
        content=_redact(content, sensitive),
        final=candidate.final,
        confirmation_for=candidate.confirmation_for,
    )
    return DefenseDecision(
        decision="rewrite",
        risk_score=0.9,
        confidence=0.9,
        reason_codes=["SENSITIVE_TO_USER_SINK", "REDACTED"],
        explanation=(
            f"response leaks content from a {sensitivity}-sensitivity source; redacted per policy"
        ),
        rewritten_action=rewritten,
        metadata={},
    )

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

    # Run-scoped sensitive-content tracking (keyed off sensitivity, not trust rank).
    # Never log raw values — only sha256 hashes.
    sensitive_hashes = update_run_state(parsed)

    triggered_rules = evaluate(parsed)
    trust_map = build_trust_map(parsed.provenance)
    observation_rank = observation_trust(parsed.observation, trust_map)
    args_rank = args_trust(parsed.candidate_action.arguments, parsed.conversation, trust_map)
    trust_signals = {"observation_rank": observation_rank, "args_rank": args_rank}

    # Respond/final actions: scan content for leaked sensitive strings (override compose).
    decision = scan_respond(parsed)
    if decision is None:
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
            "sensitive_hashes": sensitive_hashes,
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
