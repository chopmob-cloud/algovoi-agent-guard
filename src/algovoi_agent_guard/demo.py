"""Self-checking rogue-agent attack replay.

The agent holds its own Ed25519 key and full read/write access to its
workspace. It tries to (1) raise its own cap, (2) replay a settled charge,
(3) forge the human countersign, (4) rewrite the ledger to hide spend,
(5) pay a foreign payee. Every attempt must end in DENY or a failed offline
verification. The honest path must ALLOW, bind to settlement, and recompute
offline. All artifacts are written to outdir for independent inspection.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from . import intent, keys, mandate, receipt
from .guard import Guard, GuardError
from .ledger import Ledger, verify_chain
from .verify import verify_decision, verify_settlement

NOW = datetime(2026, 11, 23, 8, 0, 0, tzinfo=timezone.utc)
AGENT_REF = "sha256:" + "b3" * 32
EXPIRES = "2026-11-23T09:00:00Z"


def _w(outdir, name, obj):
    with open(os.path.join(outdir, name), "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")


def run_demo(outdir: str) -> int:
    os.makedirs(outdir, exist_ok=True)
    lines = []
    failures = []

    def say(s):
        lines.append(s)
        print(s)

    def check(label, cond):
        say(f"  [{'PASS' if cond else 'FAIL'}] {label}")
        if not cond:
            failures.append(label)

    human_priv, human_pub = keys.generate_keypair()
    agent_priv, agent_pub = keys.generate_keypair()
    _w(outdir, "human.pub.json", {"human_pub": human_pub, "kid": keys.kid_for(human_pub)})
    _w(outdir, "agent.pub.json", {"agent_pub": agent_pub})
    # The human private key is NEVER written into the agent workspace.
    env = mandate.issue_mandate(
        payer="0x00000000000000000000000000000000DEADBEEF", cap="1000",
        period="monthly", payee="vendor-1", scope=["inference"],
        max_per_charge="250", human_priv=human_priv, now=NOW)
    _w(outdir, "mandate.json", env)
    lg = Ledger(os.path.join(outdir, "ledger.jsonl"))
    g = Guard(env, lg, AGENT_REF, now_fn=lambda: NOW)

    def mk(cid, amount=100, payee="vendor-1", mref=None):
        return intent.make_intent(charge_id=cid, mandate_ref=mref or env["mandate_ref"],
                                  payee=payee, amount=amount, at=NOW, scope="inference")

    def try_allow(i, priv, tag):
        a = intent.approve(g._gref("ALLOW"), i, priv, EXPIRES)
        _w(outdir, f"approval-{tag}.json", a)
        r = g.decide(i, a)
        _w(outdir, f"receipt-{tag}.json", r)
        return r

    say("algovoi-agent-guard — rogue-agent attack replay")
    say(f"mandate_ref {env['mandate_ref']}")
    say(f"human kid   {env['kid']} (private key held outside the agent workspace)")
    say("")

    say("ATTACK 1 — agent forges a richer mandate under its own key and tries to install it")
    forged = mandate.issue_mandate(payer=env["payer"], cap="999999", human_priv=agent_priv, now=NOW)
    _w(outdir, "forged-mandate.json", forged)
    try:
        g.set_envelope(forged)
        installed = True
    except GuardError as exc:
        installed = False
        say(f"  set_envelope refused: {exc}")
    check("self-signed mandate cannot be installed", not installed)
    r = try_allow(mk("c-forge", mref=forged["mandate_ref"]), agent_priv, "forge")
    check("intent bound to the forged authority is DENY", r["verdict"] == "DENY")
    say(f"  reasons: {r['reasons']}")
    say("")

    say("HONEST PATH — human countersigns a 100-unit charge to vendor-1")
    r_ok = try_allow(mk("c-1"), human_priv, "ok")
    check("honest charge ALLOW", r_ok["verdict"] == "ALLOW")
    say(f"  guardrail_ref {r_ok['guardrail_ref']}")
    say("")

    say("ATTACK 2 — agent replays the settled charge_id")
    r = try_allow(mk("c-1"), human_priv, "replay")
    check("replay DENY", r["verdict"] == "DENY" and "policy: replay" in r["reasons"])
    say("")

    say("ATTACK 3 — agent forges the countersign with its own key")
    r = try_allow(mk("c-2"), agent_priv, "csforge")
    check("forged countersign DENY", r["verdict"] == "DENY"
          and any(x.startswith("countersign:") for x in r["reasons"]))
    say("")

    say("ATTACK 4 — agent rewrites the ledger to hide its spend")
    snap = lg.snapshot()
    snap["entries"][0]["amount"] = 1
    _w(outdir, "tampered-ledger.json", snap)
    ok_chain, _ = verify_chain(snap["entries"])
    ok_ver, reasons = verify_decision(env, r_ok, snap)
    check("tampered chain fails offline verification", not ok_chain)
    check("ALLOW receipt no longer verifies against tampered ledger", not ok_ver)
    say(f"  reasons: {reasons[:2]}")
    say("")

    say("ATTACK 5 — agent pays a foreign payee under a valid countersign")
    r = try_allow(mk("c-3", payee="attacker"), human_priv, "payee")
    check("foreign payee DENY", r["verdict"] == "DENY" and "policy: payee_not_allowed" in r["reasons"])
    say("")

    say("SETTLEMENT — bind the honest ALLOW to the rail's transaction reference")
    s = receipt.bind_settlement(r_ok, "tx:0xsettled")
    _w(outdir, "settlement.json", s)
    ok1, why1 = verify_decision(env, r_ok, lg.snapshot())
    ok2, why2 = verify_settlement(env, r_ok, s, lg.snapshot())
    check("ALLOW receipt recomputes offline from public material", ok1)
    check("settlement binding verifies offline", ok2)
    if not ok1:
        say(f"  {why1}")
    if not ok2:
        say(f"  {why2}")
    say("")

    _w(outdir, "transcript.json", {"lines": lines, "failures": failures})
    if failures:
        say(f"DEMO FAILED: {len(failures)} check(s)")
        return 1
    say("DEMO PASSED — every attack denied or detected; honest path recomputes offline.")
    return 0
