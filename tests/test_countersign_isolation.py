"""Isolating test for the countersign SIGNATURE check (intent.verify_approval).

A countersign that is structurally perfect — correct displayed text, bound refs,
correct human_pub and kid, valid expiry — but signed with the AGENT's key instead
of the human's. Every check except the Ed25519 signature passes, so this test
fails if and only if the signature verification is disabled. Proven load-bearing
by the countersign-key mutation probe (mutating intent.py:154 makes this fail).
"""
from datetime import datetime, timedelta, timezone

from algovoi_agent_guard import intent as intent_mod
from algovoi_agent_guard import keys, mandate
from algovoi_agent_guard.guard import Guard
from algovoi_agent_guard.jcs import canonicalise
from algovoi_agent_guard.ledger import Ledger

NOW = datetime(2026, 11, 23, 12, 0, 0, tzinfo=timezone.utc)


def test_countersign_signed_by_wrong_key_is_denied(tmp_path):
    priv_h, pub_h = keys.generate_keypair()
    priv_a, _pub_a = keys.generate_keypair()
    env = mandate.issue_mandate(
        payer="payer-1", cap="1000", period="monthly",
        payee="vendor-1", scope=["inference"], max_per_charge="250",
        human_priv=priv_h, now=NOW,
    )
    g = Guard(env, Ledger(tmp_path / "l.json"),
              agent_ref="sha256:" + "a" * 64, now_fn=lambda: NOW)
    i = intent_mod.make_intent(
        charge_id="c1", mandate_ref=env["mandate_ref"], payee="vendor-1",
        amount=100, scope="inference", at=NOW,
    )
    allow_ref = g._gref("ALLOW")
    expires = (NOW + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Correct human key id / pub / text / refs — but signed by the agent key.
    body = intent_mod.approval_body(allow_ref, i, expires, pub_h)
    body["sig"] = keys.sign(priv_a, canonicalise({k: v for k, v in body.items() if k != "sig"}))

    r = g.decide(i, approval=body)
    assert r["verdict"] == "DENY", r["reasons"]
    assert any("sig: countersign signature invalid" in x for x in r["reasons"]), r["reasons"]
    # nothing committed for a denied charge
    assert not g.ledger.has_charge("c1")