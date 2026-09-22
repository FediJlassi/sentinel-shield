from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

TRUST_RANKS: dict[str, int] = {
    "system_policy": 0,
    "authenticated_user": 1,
    "trusted_internal": 2,
    "untrusted_internal": 3,
    "untrusted_external": 4,
    "adversary_controlled": 5,
}
FAIL_CLOSED_RANK = 5


def _as_dict(obj: Any) -> dict[str, Any]:
    if isinstance(obj, dict):
        return obj
    return getattr(obj, "__dict__", {})


def _rank_of(trust_level: Any) -> int:
    if trust_level is None:
        logger.warning("missing trust_level; failing closed to rank %d", FAIL_CLOSED_RANK)
        return FAIL_CLOSED_RANK

    if isinstance(trust_level, bool):
        logger.warning("unexpected boolean trust_level %r; failing closed", trust_level)
        return FAIL_CLOSED_RANK

    if isinstance(trust_level, int):
        if 0 <= trust_level <= 5:
            return trust_level
        logger.warning("out-of-range trust_level %r; failing closed", trust_level)
        return FAIL_CLOSED_RANK

    if isinstance(trust_level, str):
        token = trust_level.strip().lower()
        if token in TRUST_RANKS:
            return TRUST_RANKS[token]
        try:
            numeric = int(token)
        except (TypeError, ValueError):
            logger.warning("unknown trust_level %r; failing closed", trust_level)
            return FAIL_CLOSED_RANK
        if 0 <= numeric <= 5:
            return numeric
        logger.warning("out-of-range trust_level %r; failing closed", trust_level)
        return FAIL_CLOSED_RANK

    logger.warning("unsupported trust_level type %r; failing closed", type(trust_level))
    return FAIL_CLOSED_RANK


def build_trust_map(provenance_records: list[Any]) -> dict[str, dict[str, Any]]:
    trust_map: dict[str, dict[str, Any]] = {}
    for record in provenance_records:
        rec = _as_dict(record)
        record_id = rec.get("id")
        if record_id is None:
            continue
        provenance = _as_dict(rec.get("provenance"))
        trust_level = provenance.get("trust_level")
        rank = _rank_of(trust_level)
        trust_map[record_id] = {
            "rank": rank,
            "trust_level": trust_level,
            "provenance": provenance,
        }
    return trust_map


def observation_trust(observation: Any, trust_map: dict[str, dict[str, Any]]) -> Optional[int]:
    if observation is None:
        return None
    obs = _as_dict(observation)
    provenance_ids = obs.get("provenance_ids") or []
    if not provenance_ids:
        return None

    ranks: list[int] = []
    for pid in provenance_ids:
        entry = trust_map.get(pid)
        if entry is None:
            logger.warning("observation references provenance_id %r missing from trust map; failing closed", pid)
            ranks.append(FAIL_CLOSED_RANK)
        else:
            ranks.append(entry["rank"])
    return max(ranks)


def _string_values(arguments: Any) -> list[str]:
    values: list[str] = []
    if isinstance(arguments, dict):
        for v in arguments.values():
            values.extend(_string_values(v))
    elif isinstance(arguments, list):
        for v in arguments:
            values.extend(_string_values(v))
    elif isinstance(arguments, str):
        values.append(arguments)
    return values


def args_trust(
    arguments: Any,
    conversation: Any = None,
    trust_map: dict[str, dict[str, Any]] = None,
) -> Optional[int]:
    if trust_map is None:
        return None
    ranks: list[int] = []
    for text in _string_values(arguments):
        for pid, entry in trust_map.items():
            if pid and pid in text:
                ranks.append(entry["rank"])
    if not ranks:
        return None
    return max(ranks)
