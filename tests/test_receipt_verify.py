"""Settlement binding + offline recomputation, including tamper detection."""
from datetime import datetime, timezone

import pytest

from algovoi_agent_guard import intent, keys, mandate, receipt
from algovoi_agent_guard.guard import Guard
from algovoi_agent_guard.ledger import Ledger
from algovoi_agent_guard.verify import verify_decision, verify_settlement

NOW = datetime(2026, 11, 23, 8, 0, 0, tzinfo=timezone.utc)
AGENT = "sha256:" + "b3" * 32
EXPIRES = "2026-11-23T09:00:00Z"


@pytest.fixture()
def rig(tmp_path):
    priv, pub = keys.generate_keypair()
    env = mandate.issue_mandate(payer="payer-1", cap="1000", human_priv=priv, now=NOW)
    lg = Ledger(tmp_path / "l.jsonl")
    g = Guard(env, lg, AGENT, now_fn=lambda: NOW)
    i = intent.make_intent(charge_id="c-1", mandate_ref=env["mandate_ref"],
                           payee="vendor-1", amount=100, at=NOW)
    a = intent.approve(g._gref("ALLOW"), i, priv, EXPIRES)
    r = g.decide(i, a)
    assert r["verdict"] == "ALLOW"
    return priv, env, lg, g, i, r


def test_settlement_binding_verifies_with_ledger(rig):
    priv, env, lg, g, i, r = rig
    s = receipt.bind_settlement(r, "tx:0xabc123")
    ok, reasons = verify_settlement(env, r, s, lg.snapshot())
    assert ok, reasons


def test_settlement_without_ledger_skips_commit_check(rig):
    priv, env, lg, g, i, r = rig
    s = receipt.bind_settlement(r, "tx:0xabc123")
    ok, reasons = verify_decision(env, r)  # no snapshot: arithmetic only
    assert ok, reasons


def test_deny_cannot_bind_settlement(rig):
    priv, env, lg, g, i, r = rig
    bad = g.decide(intent.make_intent(charge_id="c-2", mandate_ref=env["mandate_ref"],
                                      payee="attacker", amount=1, at=NOW))
    assert bad["verdict"] == "DENY"
    with pytest.raises(receipt.ReceiptError):
        receipt.bind_settlement(bad, "tx:0xabc")


def test_tampered_settlement_amount_rejected(rig):
    priv, env, lg, g, i, r = rig
    s = receipt.bind_settlement(r, "tx:0xabc123")
    s["amount"] = 999
    ok, reasons = verify_settlement(env, r, s)
    assert not ok and any("amount" in x or "ref:" in x for x in reasons)


def test_tampered_receipt_rejected(rig):
    priv, env, lg, g, i, r = rig
    r2 = dict(r)
    r2["intent"] = dict(r["intent"], amount=999)
    ok, reasons = verify_decision(env, r2, lg.snapshot())
    assert not ok


def test_allow_without_countersign_rejected(rig):
    priv, env, lg, g, i, r = rig
    r2 = dict(r, countersign=None)
    from algovoi_agent_guard.jcs import ref
    r2["receipt_ref"] = ref({k: v for k, v in r2.items() if k != "receipt_ref"})
    ok, reasons = verify_decision(env, r2, lg.snapshot())
    assert not ok and any("countersign" in x for x in reasons)


def test_rewritten_ledger_rejected(rig):
    priv, env, lg, g, i, r = rig
    snap = lg.snapshot()
    snap["entries"][0]["amount"] = 1  # agent shrinks recorded spend
    ok, reasons = verify_decision(env, r, snap)
    assert not ok and any("ledger" in x for x in reasons)


def test_out_of_enum_verdict_rejected(rig):
    priv, env, lg, g, i, r = rig
    r2 = dict(r, verdict="MAYBE")
    ok, reasons = verify_decision(env, r2)
    assert not ok and any("enum" in x for x in reasons)
