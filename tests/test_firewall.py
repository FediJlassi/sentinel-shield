from __future__ import annotations

import logging

from app.firewall import args_trust, build_trust_map, observation_trust

SAMPLE = [
    {"id": "prov-0", "provenance": {"source_type": "system_policy", "trust_level": 0}},
    {"id": "prov-1", "provenance": {"trust_level": "authenticated_user"}},
    {"id": "prov-4", "provenance": {"trust_level": "untrusted_external"}},
    {"id": "prov-5", "provenance": {"trust_level": "adversary_controlled"}},
    {"id": "prov-int", "provenance": {"trust_level": 2}},
    {"id": "prov-missing", "provenance": {"trust_level": "mystery_source"}},
    {"id": "prov-none", "provenance": {}},
]


def test_nested_shape():
    tm = build_trust_map(SAMPLE)
    assert tm["prov-0"]["rank"] == 0
    assert tm["prov-1"]["rank"] == 1
    assert tm["prov-4"]["rank"] == 4


def test_mixed_int_str_ranks():
    tm = build_trust_map(SAMPLE)
    assert tm["prov-int"]["rank"] == 2
    assert tm["prov-5"]["rank"] == 5


def test_unknown_trust_level_fails_closed():
    tm = build_trust_map(SAMPLE)
    assert tm["prov-missing"]["rank"] == 5


def test_missing_trust_level_fails_closed():
    tm = build_trust_map(SAMPLE)
    assert tm["prov-none"]["rank"] == 5


def test_observation_trust_worst_rank():
    tm = build_trust_map(SAMPLE)
    obs = {"kind": "email", "content": "x", "provenance_ids": ["prov-0", "prov-4"]}
    assert observation_trust(obs, tm) == 4


def test_observation_untagged_returns_none():
    tm = build_trust_map(SAMPLE)
    assert observation_trust({"kind": "email", "content": "x", "provenance_ids": []}, tm) is None
    assert observation_trust(None, tm) is None


def test_observation_missing_id_fails_closed():
    tm = build_trust_map(SAMPLE)
    obs = {"provenance_ids": ["prov-0", "ghost-id"]}
    assert observation_trust(obs, tm) == 5


def test_args_trust_references_ids():
    tm = build_trust_map(SAMPLE)
    args = {"body": "see prov-1 and prov-4 for details", "to": "a@b.c"}
    assert args_trust(args, None, tm) == 4


def test_args_trust_no_reference_returns_none():
    tm = build_trust_map(SAMPLE)
    assert args_trust({"body": "nothing relevant"}, None, tm) is None
