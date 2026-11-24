"""Offline verification from public material only. No network, no secrets.

verify_decision() re-derives the verdict with the guard's own pure evaluate()
function: recomputes the frozen L1 refs and the policy ref, re-runs every check
against the envelope and (optionally) a ledger snapshot, and re-verifies the
human countersign for ALLOW. A receipt whose verdict or reasons do not
recompute is refused — there is no mediator signature to trust, only arithmetic
and the human key.

verify_settlement() additionally checks the settlement binding covers exactly
the decision it claims.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .guard import evaluate, policy_bound_ref
from .jcs import JcsError, ref
from .l1 import L1Error, VERDICTS, guardrail_ref
from .ledger import verify_chain


def _parse(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def verify_decision(envelope: dict, receipt, ledger_snapshot=None) -> tuple:
    reasons = []
    if not isinstance(receipt, dict):
        return False, ["schema: receipt must be an object"]
    need = ("type", "version", "verdict", "guardrail_ref", "mandate_ref", "agent_ref",
            "policy_bound_ref", "intent", "reasons", "countersign", "ledger_head",
            "issued_at", "receipt_ref")
    missing = [f for f in need if f not in receipt]
    if missing:
        return False, [f"schema: missing fields {missing}"]
    try:
        if receipt["receipt_ref"] != ref({k: v for k, v in receipt.items() if k != "receipt_ref"}):
            reasons.append("ref: receipt_ref does not recompute")
    except JcsError as exc:
        return False, [f"ref: receipt not canonicalisable: {exc}"]
    if receipt["verdict"] not in VERDICTS:
        return False, ["verdict: outside the closed ALLOW/DENY enum"]
    if not isinstance(envelope, dict) or "mandate_ref" not in envelope:
        return False, ["schema: envelope must carry a mandate_ref"]
    if receipt["mandate_ref"] != envelope["mandate_ref"]:
        reasons.append("ref: receipt mandate_ref != envelope mandate_ref")
    try:
        if receipt["policy_bound_ref"] != policy_bound_ref(envelope):
            reasons.append("ref: policy_bound_ref does not recompute from the envelope")
        expected_gref = guardrail_ref(
            agent_ref=receipt["agent_ref"], mandate_ref_=envelope["mandate_ref"],
            policy_bound_ref=receipt["policy_bound_ref"], verdict=receipt["verdict"])
        if receipt["guardrail_ref"] != expected_gref:
            reasons.append("ref: guardrail_ref does not recompute")
    except (L1Error, JcsError, KeyError) as exc:
        reasons.append(f"ref: cannot recompute decision refs: {exc}")
    entries = []
    if ledger_snapshot is not None:
        entries = ledger_snapshot.get("entries", [])
        ok, creasons = verify_chain(entries)
        if not ok:
            reasons += [f"ledger: {r}" for r in creasons]
    try:
        now = _parse(receipt["issued_at"])
    except (ValueError, TypeError):
        return False, ["schema: malformed issued_at"]
    try:
        ev = evaluate(envelope, receipt["intent"], receipt["countersign"], entries,
                      receipt["agent_ref"], now,
                      committed=(receipt["verdict"] == "ALLOW" and ledger_snapshot is not None))
    except (L1Error, JcsError, KeyError, TypeError, ValueError) as exc:
        return False, [f"recompute: hostile receipt material: {exc}"]
    if ev["verdict"] != receipt["verdict"]:
        reasons.append(f"verdict: recomputes as {ev['verdict']}, receipt claims {receipt['verdict']}")
    if list(ev["reasons"]) != list(receipt["reasons"]):
        reasons.append(f"reasons: refusal reasons do not recompute (recomputed: {ev['reasons']})")
    return (not reasons), reasons


def verify_settlement(envelope: dict, decision_receipt: dict, settlement,
                      ledger_snapshot=None) -> tuple:
    reasons = []
    if not isinstance(settlement, dict):
        return False, ["schema: settlement receipt must be an object"]
    try:
        body = {k: v for k, v in settlement.items() if k != "settlement_receipt_ref"}
        if settlement.get("settlement_receipt_ref") != ref(body):
            reasons.append("ref: settlement_receipt_ref does not recompute")
    except JcsError as exc:
        return False, [f"ref: settlement not canonicalisable: {exc}"]
    if settlement.get("decision_receipt_ref") != decision_receipt.get("receipt_ref"):
        reasons.append("ref: settlement bound to a different decision")
    for f in ("mandate_ref", "guardrail_ref"):
        if settlement.get(f) != decision_receipt.get(f):
            reasons.append(f"ref: settlement {f} mismatch")
    i = decision_receipt.get("intent", {})
    try:
        if settlement.get("intent_ref") != ref(i):
            reasons.append("ref: settlement intent_ref mismatch")
    except JcsError as exc:
        return False, [f"ref: intent not canonicalisable: {exc}"]
    for f in ("charge_id", "amount", "asset", "payee"):
        if settlement.get(f) != i.get(f):
            reasons.append(f"ref: settlement {f} mismatch")
    if not settlement.get("settlement_ref"):
        reasons.append("settlement: empty settlement_ref")
    ok, dreasons = verify_decision(envelope, decision_receipt, ledger_snapshot)
    if not ok:
        reasons += [f"decision: {r}" for r in dreasons]
    return (not reasons), reasons
