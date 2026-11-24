"""Countersign: displayed-text compatible, no hidden fields, bound refs."""
from datetime import datetime, timedelta, timezone

import pytest

from algovoi_agent_guard import intent, keys, mandate
from algovoi_agent_guard.l1 import guardrail_ref

NOW = datetime(2026, 11, 23, 8, 0, 0, tzinfo=timezone.utc)
EXPIRES = "2026-11-23T08:10:00Z"
AGENT = "sha256:" + "b3" * 32
POLICY = "sha256:" + "aa" * 32


@pytest.fixture()
def env():
    priv, pub = keys.generate_keypair()
    m = mandate.issue_mandate(payer="payer-1", cap="1000", human_priv=priv, now=NOW)
    i = intent.make_intent(charge_id="c-1", mandate_ref=m["mandate_ref"],
                           payee="vendor-1", amount=100, at=NOW)
    gref = guardrail_ref(agent_ref=AGENT, mandate_ref_=m["mandate_ref"],
                         policy_bound_ref=POLICY, verdict="ALLOW")
    return priv, pub, m, i, gref


def test_approval_roundtrip(env):
    priv, pub, m, i, gref = env
    a = intent.approve(gref, i, priv, EXPIRES)
    ok, reasons = intent.verify_approval(a, gref, i, pub, now=NOW)
    assert ok, reasons


def test_displayed_text_countersign_compatible(env):
    priv, pub, m, i, gref = env
    a = intent.approve(gref, i, priv, EXPIRES)
    assert a["approval_text"] == (
        f"Approve #{gref}: pay 100 USDC to vendor-1 (expires 2026-11-23 08:10 UTC)")


def test_hidden_field_amount_swap_rejected(env):
    priv, pub, m, i, gref = env
    a = intent.approve(gref, i, priv, EXPIRES)
    sneaky = dict(i, amount=999)  # agent inflates the charge after approval
    ok, reasons = intent.verify_approval(a, gref, sneaky, pub, now=NOW)
    assert not ok
    assert any("text:" in r or "ref:" in r for r in reasons)


def test_different_guardrail_ref_rejected(env):
    priv, pub, m, i, gref = env
    a = intent.approve(gref, i, priv, EXPIRES)
    other = guardrail_ref(agent_ref=AGENT, mandate_ref_=m["mandate_ref"],
                          policy_bound_ref=POLICY, verdict="DENY")
    ok, reasons = intent.verify_approval(a, other, i, pub, now=NOW)
    assert not ok and any("ref:" in r or "text:" in r for r in reasons)


def test_expired_countersign_rejected(env):
    priv, pub, m, i, gref = env
    a = intent.approve(gref, i, priv, EXPIRES)
    ok, reasons = intent.verify_approval(a, gref, i, pub, now=NOW + timedelta(minutes=11))
    assert not ok and any("expired" in r for r in reasons)


def test_wrong_human_key_rejected(env):
    priv, pub, m, i, gref = env
    a = intent.approve(gref, i, priv, EXPIRES)
    _, other_pub = keys.generate_keypair()
    ok, reasons = intent.verify_approval(a, gref, i, other_pub, now=NOW)
    assert not ok and any("key:" in r for r in reasons)


def test_forged_countersign_under_agent_key_rejected(env):
    priv, pub, m, i, gref = env
    agent_priv, agent_pub = keys.generate_keypair()
    forged = intent.approve(gref, i, agent_priv, EXPIRES)
    ok, reasons = intent.verify_approval(forged, gref, i, pub, now=NOW)
    assert not ok and any("key:" in r for r in reasons)


@pytest.mark.parametrize("bad", [None, [], "x", {}, {"sig": "AA"}])
def test_hostile_approval_never_raises(env, bad):
    priv, pub, m, i, gref = env
    ok, reasons = intent.verify_approval(bad, gref, i, pub, now=NOW)
    assert ok is False and reasons


def test_intent_schema_guards():
    with pytest.raises(intent.IntentError):
        intent.make_intent(charge_id="c", mandate_ref="sha256:" + "00" * 32,
                           payee="v", amount=0)
    with pytest.raises(intent.IntentError):
        intent.make_intent(charge_id="c", mandate_ref="sha256:" + "00" * 32,
                           payee="v", amount=1.5)
    with pytest.raises(intent.IntentError):
        intent.make_intent(charge_id="c", mandate_ref="not-a-ref", payee="v", amount=1)
