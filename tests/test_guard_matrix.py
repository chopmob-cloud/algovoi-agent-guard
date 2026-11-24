"""Parametrised guard matrices: policy boundaries, hostile-input robustness.

Each case asserts a specific refusal reason (or ALLOW at the exact boundary), so a
weakened check is caught rather than merely 'something denied'.
"""
from datetime import datetime, timezone

import pytest

from algovoi_agent_guard import intent, keys, mandate
from algovoi_agent_guard.guard import Guard
from algovoi_agent_guard.ledger import Ledger

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
    g = Guard(env, lg, AGENT, now_fn=lambda: NOW)
    return {"priv": priv, "env": env, "lg": lg, "g": g}


def mk(rig, cid="c-1", amount=100, payee="vendor-1", scope="inference"):
    return intent.make_intent(charge_id=cid, mandate_ref=rig["env"]["mandate_ref"],
                              payee=payee, amount=amount, at=NOW, scope=scope)


def allow(rig, i):
    a = intent.approve(rig["g"]._gref("ALLOW"), i, rig["priv"], EXPIRES)
    return rig["g"].decide(i, a)


@pytest.mark.parametrize("payee", ["attacker", "vendor-2", "Vendor-1", "vendor-1 "])
def test_payee_matrix_denies(rig, payee):
    r = allow(rig, mk(rig, payee=payee))
    assert r["verdict"] == "DENY"
    assert "policy: payee_not_allowed" in r["reasons"]


@pytest.mark.parametrize("scope", ["exfiltration", "transfer", "Inference", " inference"])
def test_scope_matrix_denies(rig, scope):
    r = allow(rig, mk(rig, scope=scope))
    assert r["verdict"] == "DENY"
    assert "policy: scope_not_allowed" in r["reasons"]


@pytest.mark.parametrize("amount,verdict", [(1, "ALLOW"), (249, "ALLOW"),
                                            (250, "ALLOW"), (251, "DENY"), (1000, "DENY")])
def test_per_charge_boundary(rig, amount, verdict):
    r = allow(rig, mk(rig, amount=amount))
    assert r["verdict"] == verdict
    if verdict == "DENY":
        assert "policy: per_charge_cap" in r["reasons"]


@pytest.mark.parametrize("bad", [
    None, [], "x", 42, {}, {"amount": 1.5}, {"charge_id": "c", "amount": -5},
    {"charge_id": "c"}, {"charge_id": "c", "amount": "100"},
    {"charge_id": 123, "amount": 100}, {"charge_id": "c", "amount": True},
    {"charge_id": "c", "amount": 100, "payee": None},
    {"charge_id": "c", "amount": 100, "scope": None},
    {"charge_id": "c", "amount": 10 ** 30},
])
def test_hostile_intent_matrix_never_raises(rig, bad):
    r = rig["g"].decide(bad)  # no approval: must DENY, never raise
    assert r["verdict"] == "DENY" and r["reasons"]


def test_replay_matrix_across_ids(rig):
    assert allow(rig, mk(rig, cid="r-1"))["verdict"] == "ALLOW"
    assert allow(rig, mk(rig, cid="r-1"))["verdict"] == "DENY"
    assert allow(rig, mk(rig, cid="r-2"))["verdict"] == "ALLOW"
    r = allow(rig, mk(rig, cid="r-2"))
    assert r["verdict"] == "DENY" and "policy: replay" in r["reasons"]
