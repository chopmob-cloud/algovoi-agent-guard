"""Parametrised tamper matrix: every mutated receipt/settlement field must fail
offline recomputation. Proves the receipt is bound to its content, not just signed.
"""
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
    r = g.decide(i, intent.approve(g._gref("ALLOW"), i, priv, EXPIRES))
    assert r["verdict"] == "ALLOW"
    return priv, env, lg, r


def _mutate(r, path, value):
    import copy
    r2 = copy.deepcopy(r)
    node = r2
    parts = path.split(".")
    for p in parts[:-1]:
        node = node[p]
    node[parts[-1]] = value
    return r2


@pytest.mark.parametrize("path,value", [
    ("verdict", "MAYBE"),
    ("intent.amount", 999),
    ("intent.payee", "attacker"),
    ("intent.charge_id", "other"),
    ("intent.scope", "exfiltration"),
    ("countersign", None),
    ("receipt_ref", "sha256:" + "00" * 32),
    ("mandate_ref", "sha256:" + "11" * 32),
])
def test_receipt_field_tamper_rejected(rig, path, value):
    priv, env, lg, r = rig
    ok, reasons = verify_decision(env, _mutate(r, path, value), lg.snapshot())
    assert not ok, f"tampering {path} must fail recomputation"


@pytest.mark.parametrize("path,value", [
    ("amount", 999),
    ("tx", "tx:0xdead"),
    ("receipt_ref", "sha256:" + "00" * 32),
])
def test_settlement_field_tamper_rejected(rig, path, value):
    priv, env, lg, r = rig
    s = receipt.bind_settlement(r, "tx:0xabc123")
    ok, reasons = verify_settlement(env, r, _mutate(s, path, value), lg.snapshot())
    assert not ok


def test_ledger_entry_tamper_matrix(rig):
    priv, env, lg, r = rig
    for field, value in [("amount", 1), ("payee", "attacker"), ("charge_id", "x")]:
        snap = lg.snapshot()
        snap["entries"][0][field] = value
        ok, _ = verify_decision(env, r, snap)
        assert not ok, f"ledger {field} tamper must fail"
