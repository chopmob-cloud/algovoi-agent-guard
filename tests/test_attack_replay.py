"""End-to-end rogue-agent replay: the demo's claims, asserted as tests.

The agent holds its own key and full read/write access to its workspace. It
tries, in order: (1) raise its own cap, (2) replay a settled charge, (3) forge
the human countersign, (4) rewrite the ledger to hide spend, (5) pay a foreign
payee. Every attempt must end in DENY or a failed offline verification; the
honest path must ALLOW and bind to settlement.
"""
from datetime import datetime, timezone

from algovoi_agent_guard import intent, keys, mandate, receipt
from algovoi_agent_guard.guard import Guard, GuardError
from algovoi_agent_guard.ledger import Ledger, verify_chain
from algovoi_agent_guard.verify import verify_decision, verify_settlement

NOW = datetime(2026, 11, 23, 8, 0, 0, tzinfo=timezone.utc)
AGENT = "sha256:" + "b3" * 32
EXPIRES = "2026-11-23T09:00:00Z"


def test_rogue_agent_replay(tmp_path):
    human_priv, human_pub = keys.generate_keypair()
    agent_priv, agent_pub = keys.generate_keypair()  # the only key the agent holds
    env = mandate.issue_mandate(payer="payer-1", cap="1000", payee="vendor-1",
                                max_per_charge="250", human_priv=human_priv, now=NOW)
    lg = Ledger(tmp_path / "l.jsonl")
    g = Guard(env, lg, AGENT, now_fn=lambda: NOW)

    def mk(cid, amount=100, payee="vendor-1", mref=None):
        return intent.make_intent(charge_id=cid, mandate_ref=mref or env["mandate_ref"],
                                  payee=payee, amount=amount, at=NOW)

    def try_allow(i, priv):
        a = intent.approve(g._gref("ALLOW"), i, priv, EXPIRES)
        return g.decide(i, a)

    # 1. cap raise: forge a richer mandate under the agent's key, try to install
    forged = mandate.issue_mandate(payer="payer-1", cap="999999", human_priv=agent_priv, now=NOW)
    try:
        g.set_envelope(forged)
        installed = True
    except GuardError:
        installed = False
    assert not installed
    # ...and an intent bound to the forged authority is refused by the pinned guard
    r = try_allow(mk("c-forge", mref=forged["mandate_ref"]), agent_priv)
    assert r["verdict"] == "DENY"

    # honest spend lands
    r_ok = try_allow(mk("c-1"), human_priv)
    assert r_ok["verdict"] == "ALLOW"

    # 2. replay the settled charge
    r = try_allow(mk("c-1"), human_priv)
    assert r["verdict"] == "DENY" and "policy: replay" in r["reasons"]

    # 3. forge the countersign with the agent key
    r = try_allow(mk("c-2"), agent_priv)
    assert r["verdict"] == "DENY" and any("countersign:" in x for x in r["reasons"])

    # 4. rewrite the ledger to hide the spend, then verify offline
    snap = lg.snapshot()
    snap["entries"][0]["amount"] = 1
    ok, reasons = verify_chain(snap["entries"])
    assert not ok
    ok, reasons = verify_decision(env, r_ok, snap)
    assert not ok

    # 5. pay a foreign payee
    r = try_allow(mk("c-3", payee="attacker"), human_priv)
    assert r["verdict"] == "DENY" and "policy: payee_not_allowed" in r["reasons"]

    # the honest path: ALLOW + settlement binding + full offline recomputation
    s = receipt.bind_settlement(r_ok, "tx:0xsettled")
    ok, reasons = verify_decision(env, r_ok, lg.snapshot())
    assert ok, reasons
    ok, reasons = verify_settlement(env, r_ok, s, lg.snapshot())
    assert ok, reasons
