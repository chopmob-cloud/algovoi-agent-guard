---
name: spend-mandate
description: Issue and verify a human-signed spend mandate, then bind an agent to it. Use when you need a cap, payee allowlist and scope that the agent cannot widen on its own.
---

# Spend mandate

A mandate is a human-signed envelope: `{cap, payer, period, revocation_state,
payee, scope, max_per_charge, kid, human_pub, ...}`. Its `mandate_ref` is
`sha256(JCS({cap, payer, period, revocation_state}))` over the frozen lite format —
byte-identical to the published conformance vectors.

## Issue (human side — private key stays outside the agent workspace)

```bash
algovoi-agent-guard keygen --out ./human          # writes human.key + human.pub.json
algovoi-agent-guard issue --key ./human/human.key \
  --payer 0x00000000000000000000000000000000DEADBEEF \
  --cap 1000 --period monthly --payee vendor-1 \
  --scope inference --max-per-charge 250 --out mandate.json
```

## Install and decide (agent side)

```python
from algovoi_agent_guard.guard import Guard
from algovoi_agent_guard.ledger import Ledger
g = Guard(mandate_envelope, Ledger("ledger.jsonl"), agent_ref)
# g.set_envelope(...) refuses any envelope with a different human key or payer.
receipt = g.decide(intent, human_countersign)   # ALLOW or DENY, fail-closed
```

## Rules the guard enforces (in order)

1. intent schema (float-free, positive integer minor units)
2. authority binding — `intent.mandate_ref == installed mandate_ref`
3. mandate validity / revocation / period window
4. payee allowlist
5. scope allowlist
6. per-charge cap (`max_per_charge`)
7. period cap (accumulated settled spend)
8. replay (`charge_id` already settled)
9. human countersign bound to the exact intent ref and prospective verdict

A self-signed mandate cannot be installed: `set_envelope` raises
`envelope swap refused: different human key or payer`. The agent never holds the
human private key, so it cannot forge a countersign that verifies.

## Verify

```python
from algovoi_agent_guard.mandate import verify_mandate
ok, reasons = verify_mandate(mandate_envelope)   # signature, schema, revocation, window
```