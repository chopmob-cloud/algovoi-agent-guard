"""algovoi-agent-guard CLI — standalone, zero AlgoVoi runtime dependencies.

  keygen   --out DIR
  issue    --key PRIV --payer P --cap C [--period monthly] [--payee *]
           [--scope inference ...] [--max-per-charge M] [--ttl SECS] --out F
  intent   --mandate F --charge-id ID --payee P --amount N [--asset USDC]
           [--scope S] --out F
  approve  --key PRIV --mandate F --intent F --agent-ref REF --expires ISO --out F
  decide   --mandate F --ledger F --agent-ref REF --intent F [--approval F] --out F
  bind     --receipt F --settlement-ref TX --out F
  verify   --mandate F --receipt F [--ledger F] [--settlement F]
  revoke   --key PRIV --mandate F --out F
  demo     --outdir DIR
  redteam  --outdir DIR [--attacks N] [--adversary model|human|file|fuzz]
           [--provider qwen|mistral|nim|openai|local] [--base-url URL]
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from . import intent, keys, mandate, receipt
from .guard import Guard, policy_bound_ref
from .l1 import guardrail_ref
from .ledger import Ledger
from .verify import verify_decision, verify_settlement


def _load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _dump(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")


def _read_key(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read().strip()


def main(argv=None) -> int:
    from .redteam.engine import AI_DISCLAIMER
    p = argparse.ArgumentParser(prog="algovoi-agent-guard", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("keygen"); q.add_argument("--out", required=True)
    q = sub.add_parser("issue")
    for a in ("--key", "--payer", "--cap", "--out"):
        q.add_argument(a, required=True)
    q.add_argument("--period", default="monthly"); q.add_argument("--payee", default="*")
    q.add_argument("--scope", nargs="*", default=[]); q.add_argument("--max-per-charge")
    q.add_argument("--ttl", type=int, default=31_536_000)
    q = sub.add_parser("intent")
    for a in ("--mandate", "--charge-id", "--payee", "--amount", "--out"):
        q.add_argument(a, required=True)
    q.add_argument("--asset", default="USDC"); q.add_argument("--scope")
    q = sub.add_parser("approve")
    for a in ("--key", "--mandate", "--intent", "--agent-ref", "--expires", "--out"):
        q.add_argument(a, required=True)
    q = sub.add_parser("decide")
    for a in ("--mandate", "--ledger", "--agent-ref", "--intent", "--out"):
        q.add_argument(a, required=True)
    q.add_argument("--approval")
    q = sub.add_parser("bind")
    for a in ("--receipt", "--settlement-ref", "--out"):
        q.add_argument(a, required=True)
    q = sub.add_parser("verify")
    for a in ("--mandate", "--receipt"):
        q.add_argument(a, required=True)
    q.add_argument("--ledger"); q.add_argument("--settlement")
    q = sub.add_parser("revoke")
    for a in ("--key", "--mandate", "--out"):
        q.add_argument(a, required=True)
    q = sub.add_parser("demo"); q.add_argument("--outdir", required=True)
    q = sub.add_parser("redteam", epilog=("AI DISCLAIMER: " + AI_DISCLAIMER
                                         + " See DISCLAIMER.md."),
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    q.add_argument("--outdir", required=True)
    q.add_argument("--attacks", type=int, default=8); q.add_argument("--model")
    q.add_argument("--adversary", choices=["model", "human", "file", "fuzz"],
                   default="model")
    q.add_argument("--provider"); q.add_argument("--base-url")
    q.add_argument("--api-key-env"); q.add_argument("--attacks-file")
    q.add_argument("--seed", type=int, default=0)

    a = p.parse_args(argv)
    try:
        if a.cmd == "keygen":
            import os
            os.makedirs(a.out, exist_ok=True)
            priv, pub = keys.generate_keypair()
            kp = os.path.join(a.out, "human.key")
            with open(kp, "w", encoding="utf-8") as fh:
                fh.write(priv + "\n")
            _dump(os.path.join(a.out, "human.pub.json"),
                  {"human_pub": pub, "kid": keys.kid_for(pub)})
            print(f"kid {keys.kid_for(pub)}")
            print(f"private key: {kp} — keep it OUT of the agent's reach")
        elif a.cmd == "issue":
            env = mandate.issue_mandate(
                payer=a.payer, cap=a.cap, human_priv=_read_key(a.key),
                period=a.period, payee=a.payee, scope=a.scope,
                max_per_charge=a.max_per_charge, ttl_secs=a.ttl)
            _dump(a.out, env)
            print(f"mandate_ref {env['mandate_ref']}")
        elif a.cmd == "intent":
            env = _load(a.mandate)
            i = intent.make_intent(charge_id=a.charge_id, mandate_ref=env["mandate_ref"],
                                   payee=a.payee, amount=int(a.amount), asset=a.asset,
                                   scope=a.scope)
            _dump(a.out, i)
            print(f"intent_ref {intent.intent_ref(i)}")
        elif a.cmd == "approve":
            env, i = _load(a.mandate), _load(a.intent)
            pref = policy_bound_ref(env)
            gref = guardrail_ref(agent_ref=a.agent_ref, mandate_ref_=env["mandate_ref"],
                                 policy_bound_ref=pref, verdict="ALLOW")
            ap = intent.approve(gref, i, _read_key(a.key), a.expires)
            _dump(a.out, ap)
            print(ap["approval_text"])
        elif a.cmd == "decide":
            env, i = _load(a.mandate), _load(a.intent)
            ap = _load(a.approval) if a.approval else None
            g = Guard(env, Ledger(a.ledger), a.agent_ref)
            r = g.decide(i, ap)
            _dump(a.out, r)
            print(f"{r['verdict']} {r['guardrail_ref']}")
            for reason in r["reasons"]:
                print(f"  {reason}")
        elif a.cmd == "bind":
            s = receipt.bind_settlement(_load(a.receipt), a.settlement_ref)
            _dump(a.out, s)
            print(f"settlement_receipt_ref {s['settlement_receipt_ref']}")
        elif a.cmd == "verify":
            env, r = _load(a.mandate), _load(a.receipt)
            snap = Ledger(a.ledger).snapshot() if a.ledger else None
            if a.settlement:
                ok, reasons = verify_settlement(env, r, _load(a.settlement), snap)
            else:
                ok, reasons = verify_decision(env, r, snap)
            print("VERIFY OK" if ok else "VERIFY FAILED")
            for reason in reasons:
                print(f"  {reason}")
            return 0 if ok else 1
        elif a.cmd == "revoke":
            env = mandate.revoke(_load(a.mandate), _read_key(a.key))
            _dump(a.out, env)
            print(f"revoked mandate_ref {env['mandate_ref']}")
        elif a.cmd == "demo":
            from .demo import run_demo
            return run_demo(a.outdir)
        elif a.cmd == "redteam":
            from .redteam import run_redteam
            from .redteam.engine import AI_DISCLAIMER
            print("AI disclaimer: " + AI_DISCLAIMER)
            print("")
            return run_redteam(a.outdir, attacks=a.attacks, model=a.model,
                               adversary=a.adversary, provider=a.provider,
                               base_url=a.base_url, api_key_env=a.api_key_env,
                               attacks_file=a.attacks_file, seed=a.seed)
    except (mandate.MandateError, intent.IntentError, receipt.ReceiptError,
            keys.KeyFormatError, ValueError, OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
