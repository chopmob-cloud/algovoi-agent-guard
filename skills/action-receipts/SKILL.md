---
name: action-receipts
description: Recompute a spend decision and its settlement offline from public material, and verify the ledger hash chain. Use when you must prove what an agent was allowed to spend without trusting a mediator.
---

# Action receipts

Every `Guard.decide` returns a receipt carrying the `guardrail_ref`
`sha256(JCS({agent_ref, mandate_ref, policy_bound_ref, verdict}))`, the reasons,
and (for DENY) the presented countersign. Receipts are **recomputable**, not
mediator-signed: a verifier rebuilds the decision from the public mandate, the
intent and the ledger snapshot using the same pure `evaluate()` the guard uses.

## Recompute a decision offline

```python
from algovoi_agent_guard.verify import verify_decision, verify_settlement
ok, reasons = verify_decision(mandate_envelope, receipt, ledger_snapshot)
ok, reasons = verify_settlement(mandate_envelope, receipt, settlement, ledger_snapshot)
```

```bash
algovoi-agent-guard verify --mandate mandate.json --receipt receipt.json \
  --ledger ledger.jsonl
```

## Verify the ledger chain

The ledger is an append-only hash chain (full-history rewrite + atomic
`os.replace`). Tampering with any entry breaks recomputation:

```python
from algovoi_agent_guard.ledger import verify_chain
ok, reasons = verify_chain(snapshot["entries"])
# e.g. ['ledger: chain: entry 0 entry_ref does not recompute']
```

## Bind a settlement

```python
from algovoi_agent_guard.receipt import bind_settlement
settlement = bind_settlement(allow_receipt, "tx:0x...")   # rail transaction ref
```

The settlement binds the ALLOW receipt to the rail's transaction reference and
verifies offline against the same public material. No funds move here; the rail
consumes the canonical refs.