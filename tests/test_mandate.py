"""The mandate envelope: frozen L1 ref + human signature over the whole body.

Attack cases: cap raise without the human key, field tamper (frozen AND
additive), forgery under another key, expiry, revocation. Each check has one
isolating test so a mutation that disables exactly one guard is caught.
"""
from datetime import datetime, timedelta, timezone

import pytest

from algovoi_agent_guard import keys, mandate
from algovoi_agent_guard.l1 import mandate_ref

NOW = datetime(2026, 11, 23, 8, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def human():
    return keys.generate_keypair()


@pytest.fixture()
def m(human):
    priv, _ = human
    return mandate.issue_mandate(
        payer="0x00000000000000000000000000000000DEADBEEF",
        cap="1000", period="monthly", payee="vendor-1",
        scope=["inference"], max_per_charge="250",
        human_priv=priv, now=NOW,
    )


def test_issue_verifies(m):
    ok, reasons = mandate.verify_mandate(m, now=NOW)
    assert ok, reasons


def test_frozen_ref_matches_l1(m):
    assert m["mandate_ref"] == mandate_ref(
        "0x00000000000000000000000000000000DEADBEEF", "1000", "monthly", "active")


@pytest.mark.parametrize("field,value", [
    ("cap", "2000"),
    ("payer", "0xATTACKER"),
    ("period", "weekly"),
    ("revocation_state", "revoked"),
])
def test_frozen_field_tamper_breaks_ref_and_sig(m, field, value):
    m[field] = value
    ok, reasons = mandate.verify_mandate(m, now=NOW)
    assert not ok
    assert any("l1:" in r or "sig:" in r for r in reasons)


def test_additive_field_tamper_breaks_sig(m):
    # payee is NOT in the frozen L1 ref, but IS under the human signature.
    before = m["mandate_ref"]
    m["payee"] = "attacker"
    assert m["mandate_ref"] == before  # frozen ref unchanged...
    ok, reasons = mandate.verify_mandate(m, now=NOW)
    assert not ok and any("sig:" in r for r in reasons)  # ...but signature fails


def test_cap_raise_without_human_key_impossible(m, human):
    priv, pub = human
    forged = dict(m)
    forged["cap"] = "999999"
    forged["mandate_ref"] = mandate_ref(m["payer"], "999999", m["period"], "active")
    # agent re-signs with ITS OWN key, not the human's
    agent_priv, agent_pub = keys.generate_keypair()
    forged["human_pub"] = agent_pub
    forged["kid"] = keys.kid_for(agent_pub)
    body = mandate.mandate_body(forged)
    from algovoi_agent_guard.jcs import canonicalise
    forged["sig"] = keys.sign(agent_priv, canonicalise(body))
    ok, reasons = mandate.verify_mandate(forged, now=NOW)
    # The forgery is self-consistent under the AGENT's key, but the original
    # human key rejects it — and the guard pins the original key (test_guard).
    assert keys.verify(m["human_pub"], canonicalise(mandate.mandate_body(forged)),
                       forged["sig"]) is False
    # ...and it is a DIFFERENT authority: different kid, different mandate_ref
    assert forged["kid"] != m["kid"]
    assert forged["mandate_ref"] != m["mandate_ref"]


def test_expiry(m):
    ok, reasons = mandate.verify_mandate(m, now=NOW + timedelta(days=400))
    assert not ok and any("expired" in r for r in reasons)


def test_revocation_new_ref_and_rejection(m, human):
    priv, _ = human
    revoked = mandate.revoke(m, priv)
    assert revoked["mandate_ref"] != m["mandate_ref"]
    assert revoked["mandate_ref"] == mandate_ref(m["payer"], m["cap"], m["period"], "revoked")
    ok, reasons = mandate.verify_mandate(revoked, now=NOW)
    assert not ok and any("revoked" in r for r in reasons)


def test_float_cap_refused(human):
    priv, _ = human
    with pytest.raises(mandate.MandateError):
        mandate.issue_mandate(payer="p", cap=1000.0, human_priv=priv, now=NOW)


@pytest.mark.parametrize("bad", [None, [], "x", {}, {"cap": "1000"}])
def test_hostile_input_never_raises(bad):
    ok, reasons = mandate.verify_mandate(bad, now=NOW)
    assert ok is False and reasons
