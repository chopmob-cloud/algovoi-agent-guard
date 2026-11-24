"""The guard: one isolating DENY test per check, ALLOW only with countersign."""
from datetime import datetime, timedelta, timezone

import pytest

from algovoi_agent_guard import intent, keys, mandate
from algovoi_agent_guard.guard import Guard, GuardError
from algovoi_agent_guard.ledger import Ledger
from algovoi_agent_guard.verify import verify_decision

NOW = datetime(2026, 11, 23, 8, 0, 0, tzinfo=timezone.utc)
AGENT = "sha256:" + "b3" * 32
EXPIRES = "2026-11-23T09:00:00Z"


@pytest.fixture()
def rig(tmp_path):
    priv, pub = keys.generate_keypair()
    env = mandate.issue_mandate(
        payer="payer-1", cap="1000", period="monthly", payee="vendor-1",
        scope=["inference"], max_per_charge="250", human_priv=priv, now=NOW)
    lg = Ledger(tmp_path / "l.jsonl")
    clock = [NOW]
    g = Guard(env, lg, AGENT, now_fn=lambda: clock[0])
    return {"priv": priv, "pub": pub, "env": env, "lg": lg, "g": g, "clock": clock}


def mk_intent(rig, cid="c-1", amount=100, payee="vendor-1", scope="inference", mref=None):
    return intent.make_intent(charge_id=cid, mandate_ref=mref or rig["env"]["mandate_ref"],
                              payee=payee, amount=amount, at=rig["clock"][0], scope=scope)


def allow(rig, i):
    gref = rig["g"]._gref("ALLOW")
    a = intent.approve(gref, i, rig["priv"], EXPIRES)
    return rig["g"].decide(i, a)


def test_happy_allow_commits_and_recomputes(rig):
    i = mk_intent(rig)
    r = allow(rig, i)
    assert r["verdict"] == "ALLOW", r["reasons"]
    assert rig["lg"].has_charge("c-1")
    ok, reasons = verify_decision(rig["env"], r, rig["lg"].snapshot())
    assert ok, reasons


def test_missing_countersign_denies(rig):
    r = rig["g"].decide(mk_intent(rig))
    assert r["verdict"] == "DENY"
    assert any("countersign: required" in x for x in r["reasons"])
    assert not rig["lg"].has_charge("c-1")


def test_forged_countersign_denies(rig):
    i = mk_intent(rig)
    agent_priv, _ = keys.generate_keypair()
    a = intent.approve(rig["g"]._gref("ALLOW"), i, agent_priv, EXPIRES)
    r = rig["g"].decide(i, a)
    assert r["verdict"] == "DENY" and any("countersign:" in x for x in r["reasons"])


def test_wrong_payee_denies(rig):
    i = mk_intent(rig, payee="attacker")
    r = allow(rig, i)
    assert r["verdict"] == "DENY" and "policy: payee_not_allowed" in r["reasons"]


def test_wrong_scope_denies(rig):
    i = mk_intent(rig, scope="exfiltration")
    r = allow(rig, i)
    assert r["verdict"] == "DENY" and "policy: scope_not_allowed" in r["reasons"]


def test_per_charge_cap_denies(rig):
    i = mk_intent(rig, amount=251)
    r = allow(rig, i)
    assert r["verdict"] == "DENY" and "policy: per_charge_cap" in r["reasons"]


def test_period_cap_denies(rig):
    r1 = allow(rig, mk_intent(rig, cid="c-1", amount=250))
    assert r1["verdict"] == "ALLOW"
    r2 = allow(rig, mk_intent(rig, cid="c-2", amount=250))
    r3 = allow(rig, mk_intent(rig, cid="c-3", amount=250))
    r4 = allow(rig, mk_intent(rig, cid="c-4", amount=250))
    assert r4["verdict"] == "ALLOW"  # exactly at cap 1000
    r5 = allow(rig, mk_intent(rig, cid="c-5", amount=1))
    assert r5["verdict"] == "DENY" and "policy: period_cap" in r5["reasons"]


def test_replay_denies(rig):
    i = mk_intent(rig)
    assert allow(rig, i)["verdict"] == "ALLOW"
    r = allow(rig, mk_intent(rig))  # same charge_id
    assert r["verdict"] == "DENY" and "policy: replay" in r["reasons"]


def test_foreign_authority_denies(rig):
    other = mandate.issue_mandate(payer="payer-2", cap="9999", human_priv=rig["priv"], now=NOW)
    i = mk_intent(rig, mref=other["mandate_ref"])
    r = allow(rig, i)
    assert r["verdict"] == "DENY" and any("different authority" in x for x in r["reasons"])


def test_revocation_midlife_denies(rig):
    assert allow(rig, mk_intent(rig, cid="c-1"))["verdict"] == "ALLOW"
    revoked = mandate.revoke(rig["env"], rig["priv"])
    rig["g"].set_envelope(revoked)
    r = allow(rig, mk_intent(rig, cid="c-2"))
    assert r["verdict"] == "DENY"


def test_agent_cannot_swap_in_self_signed_mandate(rig):
    agent_priv, agent_pub = keys.generate_keypair()
    forged = mandate.issue_mandate(payer="payer-1", cap="999999", human_priv=agent_priv, now=NOW)
    with pytest.raises(GuardError, match="different human key"):
        rig["g"].set_envelope(forged)


def test_expired_mandate_denies(rig):
    rig["clock"][0] = NOW + timedelta(days=400)
    i = mk_intent(rig)
    r = allow(rig, i)
    assert r["verdict"] == "DENY" and any("expired" in x for x in r["reasons"])


@pytest.mark.parametrize("bad", [None, [], "x", {}, {"amount": 1.5},
                                 {"charge_id": "c", "amount": -5}])
def test_hostile_intent_never_raises(rig, bad):
    r = rig["g"].decide(bad)
    assert r["verdict"] == "DENY" and r["reasons"]


def test_deny_receipt_recomputes(rig):
    r = rig["g"].decide(mk_intent(rig, payee="attacker"))
    ok, reasons = verify_decision(rig["env"], r)
    assert ok, reasons


def test_deny_with_valid_approval_recomputes(rig):
    # A countersign was presented but the payee check failed first: the DENY
    # receipt must embed the presented approval so reasons recompute exactly.
    i = mk_intent(rig, payee="attacker")
    a = intent.approve(rig["g"]._gref("ALLOW"), i, rig["priv"], EXPIRES)
    r = rig["g"].decide(i, a)
    assert r["verdict"] == "DENY" and r["countersign"] is not None
    ok, reasons = verify_decision(rig["env"], r)
    assert ok, reasons
