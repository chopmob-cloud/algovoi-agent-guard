"""Interop gate: reproduce the vendored public frozen-L1 conformance vectors.

Vectors are copied verbatim from chopmob-cloud/algovoi-jcs-conformance-vectors
(see tests/vectors/PROVENANCE.md). Every positive must recompute to its expected
ref; every "differ" negative must recompute to recomputes_to AND diverge from the
claimed ref; every "reject" negative must raise L1Error. Cross-set continuity:
the guardrail set's mandate_1/mandate_2 equal the mandate set's pm-001/pm-002.
"""
import json
import pathlib

import pytest

from algovoi_agent_guard import L1Error, guardrail_ref, mandate_ref

VEC = pathlib.Path(__file__).parent / "vectors"
PM = json.loads((VEC / "payment_mandate_lite_v1.json").read_text(encoding="utf-8"))
SG = json.loads((VEC / "spend_guardrail_lite_v1.json").read_text(encoding="utf-8"))


def _pm(v):
    return mandate_ref(v["payer"], v["cap"], v["period"], v["revocation_state"])


def _sg(v):
    return guardrail_ref(v["agent_ref"], v["mandate_ref"], v["policy_bound_ref"], v["verdict"])


@pytest.mark.parametrize("v", PM["vectors"], ids=[v["id"] for v in PM["vectors"]])
def test_mandate_positives(v):
    assert _pm(v) == v["expected_mandate_ref"]


@pytest.mark.parametrize("v", SG["vectors"], ids=[v["id"] for v in SG["vectors"]])
def test_guardrail_positives(v):
    assert _sg(v) == v["expected_guardrail_ref"]


@pytest.mark.parametrize("v", PM["negatives"], ids=[v["id"] for v in PM["negatives"]])
def test_mandate_negatives(v):
    if v["must"] == "reject":
        with pytest.raises(L1Error):
            _pm(v)
    else:
        got = _pm(v)
        assert got == v["recomputes_to"]
        assert got != v["claimed_mandate_ref"]


@pytest.mark.parametrize("v", SG["negatives"], ids=[v["id"] for v in SG["negatives"]])
def test_guardrail_negatives(v):
    if v["must"] == "reject":
        with pytest.raises(L1Error):
            _sg(v)
    else:
        got = _sg(v)
        assert got == v["recomputes_to"]
        assert got != v["claimed_guardrail_ref"]


def test_cross_set_continuity():
    pm = {v["id"]: v["expected_mandate_ref"] for v in PM["vectors"]}
    assert SG["mandates"]["mandate_1"] == pm["pm-001"]
    assert SG["mandates"]["mandate_2"] == pm["pm-002"]


def test_field_distinctness_invariant():
    refs = {_pm(v) for v in PM["vectors"]}
    refs |= {_pm(v) for v in PM["negatives"] if v["must"] == "differ"}
    assert len(refs) == 6  # pm-001..003 + payer-swap + cap-tamper + period-tamper (revocation == pm-003)


def test_closed_verdict_enum():
    base = SG["vectors"][0]
    for bad in ("MAYBE", "allow", "", None):
        with pytest.raises(L1Error):
            guardrail_ref(base["agent_ref"], base["mandate_ref"], base["policy_bound_ref"], bad)
