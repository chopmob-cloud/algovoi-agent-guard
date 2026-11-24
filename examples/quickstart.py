"""Quickstart: drive AlgoVoi Agent Guard yourself, then extend it.

Run it (no arguments, no network, no funds move):

    pip install algovoi-agent-guard
    python examples/quickstart.py

What this shows, end to end:
  1. A HUMAN issues a spend mandate (the budget the agent cannot raise).
  2. An AGENT proposes a charge; the human countersigns; the guard ALLOWs it.
  3. Anyone recomputes that ALLOW offline from public material alone.
  4. The ALLOW is bound to a settlement reference and verified offline.
  5. A charge to a foreign payee is DENYed under the same valid countersign.

The human private key never enters the agent workspace. The guard moves no
funds — it only decides ALLOW/DENY and emits receipts a third party can verify.
Ed25519 "lite" keys are used here for a self-contained demo; production deployments
hold the human key in a signer outside the agent (see the README trust model).

Extend it: change `cap`, `payee`, `scope` or `max_per_charge` below; swap the
toy settlement ref for your rail's transaction id; persist the ledger and keys.
"""
from __future__ import annotations

import tempfile
from datetime import datetime, timezone

from algovoi_agent_guard import (
    Guard, Ledger, guardrail_ref, policy_bound_ref,
    intent, keys, mandate, receipt, verify_decision, verify_settlement,
)

# A fixed clock keeps the demo deterministic. In production use datetime.now(timezone.utc).
NOW = datetime(2026, 11, 23, 8, 0, 0, tzinfo=timezone.utc)
EXPIRES = "2026-11-23T09:00:00Z"
AGENT_REF = "sha256:" + "b3" * 32  # content address of the deployed agent policy


def main() -> int:
    # 1. Keys: the human signs the mandate; the agent has its own ( lesser ) key.
    human_priv, human_pub = keys.generate_keypair()
    agent_priv, _agent_pub = keys.generate_keypair()
    print(f"human kid {keys.kid_for(human_pub)}  (private key kept out of the agent)")

    # The HUMAN issues the mandate. The agent cannot issue or raise this.
    env = mandate.issue_mandate(
        payer="0x00000000000000000000000000000000DEADBEEF",
        cap="1000", period="monthly", payee="vendor-1",
        scope=["inference"], max_per_charge="250",
        human_priv=human_priv, now=NOW,
    )
    print(f"mandate_ref {env['mandate_ref']}")

    with tempfile.TemporaryDirectory() as tmp:
        lg = Ledger(f"{tmp}/ledger.jsonl")
        g = Guard(env, lg, AGENT_REF, now_fn=lambda: NOW)

        # The public ref of the prospective ALLOW decision (binds agent+mandate+policy).
        allow_ref = guardrail_ref(
            agent_ref=AGENT_REF, mandate_ref_=env["mandate_ref"],
            policy_bound_ref=policy_bound_ref(env), verdict="ALLOW",
        )

        def charge(charge_id: str, payee: str = "vendor-1", amount: int = 100):
            i = intent.make_intent(
                charge_id=charge_id, mandate_ref=env["mandate_ref"],
                payee=payee, amount=amount, at=NOW, scope="inference",
            )
            approval = intent.approve(allow_ref, i, human_priv, EXPIRES)  # human countersign
            return g.decide(i, approval)

        # 2. Honest charge -> ALLOW.
        r = charge("charge-1")
        print(f"\nhonest charge      -> {r['verdict']}")
        assert r["verdict"] == "ALLOW", r["reasons"]

        # 3. Recompute the ALLOW offline from public material (no private keys).
        ok, why = verify_decision(env, r, lg.snapshot())
        print(f"offline verify     -> {ok}  {why if not ok else ''}")
        assert ok, why

        # 4. Bind to settlement and verify the binding offline.
        s = receipt.bind_settlement(r, "tx:0xsettled")  # <- your rail's tx id here
        ok_s, why_s = verify_settlement(env, r, s, lg.snapshot())
        print(f"settlement verify  -> {ok_s}  {why_s if not ok_s else ''}")
        assert ok_s, why_s

        # 5. Same valid countersign, but a foreign payee -> DENY.
        bad = charge("charge-2", payee="attacker")
        print(f"foreign payee      -> {bad['verdict']}  {bad['reasons']}")
        assert bad["verdict"] == "DENY"

    print("\nOK — you just issued a mandate, charged under it, verified offline,")
    print("and saw a foreign payee denied. Edit the mandate above and re-run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())