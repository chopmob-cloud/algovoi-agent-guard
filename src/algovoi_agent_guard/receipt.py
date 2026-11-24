"""Settlement binding: tie an ALLOW decision to the payment that executed it.

The decision receipt is issued BEFORE payment (pre-payment admission). After
the rail settles, bind_settlement() produces a settlement receipt whose ref
covers the decision receipt ref AND the settlement reference (tx hash / x402
payment id). This is the property pipelock's receipts lack: the receipt is
bound to a settlement, not merely to a resource policy. The rail's own
signature over the settlement reference remains the rail's responsibility.
"""
from __future__ import annotations

from .jcs import ref

SETTLEMENT_TYPE = "algovoi_settlement_receipt"
SETTLEMENT_VERSION = "1"


class ReceiptError(ValueError):
    """Settlement binding input is invalid."""


def bind_settlement(decision_receipt: dict, settlement_ref: str) -> dict:
    if decision_receipt.get("verdict") != "ALLOW":
        raise ReceiptError("only an ALLOW decision can be bound to a settlement")
    if not isinstance(settlement_ref, str) or not settlement_ref:
        raise ReceiptError("settlement_ref must be a non-empty string")
    body = {
        "type": SETTLEMENT_TYPE,
        "version": SETTLEMENT_VERSION,
        "decision_receipt_ref": decision_receipt["receipt_ref"],
        "settlement_ref": settlement_ref,
        "mandate_ref": decision_receipt["mandate_ref"],
        "guardrail_ref": decision_receipt["guardrail_ref"],
        "intent_ref": ref(decision_receipt["intent"]),
        "charge_id": decision_receipt["intent"]["charge_id"],
        "amount": decision_receipt["intent"]["amount"],
        "asset": decision_receipt["intent"]["asset"],
        "payee": decision_receipt["intent"]["payee"],
    }
    body["settlement_receipt_ref"] = ref(body)
    return body
