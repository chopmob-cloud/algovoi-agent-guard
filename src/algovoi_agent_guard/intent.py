"""Charge intents and the human countersignature.

The countersign is DISPLAYED-TEXT COMPATIBLE with the I-HITL Countersign
prototype (github.com/I-HITL/countersign, service/crypto.py:17-24): the human
approves the exact string

    Approve #{guardrail_ref}: pay {amount} {asset} to {payee} (expires {expiry})

so a hardware approval device (Keystore / Secure Enclave / Ledger) can produce
the signature without custom firmware. The reference and expiry sit inside the
visible text — no hidden fields. The verifier RECOMPUTES the text from the
intent and refuses any divergence, then checks the Ed25519 signature over the
JCS body that embeds that exact text.

The countersign binds the PROSPECTIVE ALLOW guardrail_ref: the guard computes
the ref the decision would have if allowed, the human signs it, and only a
valid countersign turns the decision into ALLOW. Missing/forged/stale
countersign -> DENY. The agent can initiate but never approve.
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import keys
from .jcs import canonicalise, ref
from .l1 import REF_RE

INTENT_TYPE = "charge_intent"
INTENT_VERSION = "1"


class IntentError(ValueError):
    """Intent or approval input is invalid."""


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def make_intent(
    *,
    charge_id: str,
    mandate_ref: str,
    payee: str,
    amount: int,
    asset: str = "USDC",
    at: datetime | None = None,
    settlement_ref: str | None = None,
    scope: str | None = None,
) -> dict:
    if not isinstance(charge_id, str) or not charge_id or len(charge_id) > 128:
        raise IntentError("charge_id must be a non-empty string <= 128 chars")
    if not isinstance(mandate_ref, str) or not REF_RE.match(mandate_ref):
        raise IntentError("mandate_ref must be a sha256: 64-hex reference")
    if not isinstance(payee, str) or not payee:
        raise IntentError("payee must be a non-empty string")
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        raise IntentError("amount must be a positive integer (minor units)")
    if not isinstance(asset, str) or not asset:
        raise IntentError("asset must be a non-empty string")
    if settlement_ref is not None and not isinstance(settlement_ref, str):
        raise IntentError("settlement_ref must be a string or None")
    if scope is not None and (not isinstance(scope, str) or not scope):
        raise IntentError("scope must be a non-empty string or None")
    at = at or datetime.now(timezone.utc)
    return {
        "type": INTENT_TYPE,
        "version": INTENT_VERSION,
        "charge_id": charge_id,
        "mandate_ref": mandate_ref,
        "payee": payee,
        "amount": amount,
        "asset": asset,
        "at": _iso(at),
        "settlement_ref": settlement_ref,
        "scope": scope,
    }


def intent_ref(i: dict) -> str:
    return ref(i)


def approval_text(guardrail_ref: str, intent: dict, expires_at: str) -> str:
    """The exact string shown to the human and covered by the countersign."""
    expires_str = _parse(expires_at).strftime("%Y-%m-%d %H:%M UTC")
    return (
        f"Approve #{guardrail_ref}: pay {intent['amount']} {intent['asset']} "
        f"to {intent['payee']} (expires {expires_str})"
    )


def approval_body(guardrail_ref: str, intent: dict, expires_at: str, human_pub: str) -> dict:
    return {
        "type": "algovoi_countersign",
        "version": "1",
        "approval_text": approval_text(guardrail_ref, intent, expires_at),
        "guardrail_ref": guardrail_ref,
        "intent_ref": intent_ref(intent),
        "expires_at": expires_at,
        "human_pub": human_pub,
        "kid": keys.kid_for(human_pub),
    }


def approve(guardrail_ref: str, intent: dict, human_priv: str, expires_at: str) -> dict:
    """Human countersign of the prospective ALLOW decision for this intent."""
    if not isinstance(guardrail_ref, str) or not REF_RE.match(guardrail_ref):
        raise IntentError("guardrail_ref must be a sha256: 64-hex reference")
    pub = keys.pub_from_priv(human_priv)
    body = approval_body(guardrail_ref, intent, expires_at, pub)
    body["sig"] = keys.sign(human_priv, canonicalise({k: v for k, v in body.items() if k != "sig"}))
    return body


def verify_approval(approval, guardrail_ref: str, intent: dict, human_pub: str,
                    now: datetime | None = None) -> tuple:
    """Offline check: (ok, reasons). Never raises.

    Recomputes the displayed text from the intent (no hidden fields), checks the
    bound refs, the key id, the signature and the expiry. The countersign must
    be under the SAME human key that signed the mandate.
    """
    reasons = []
    if not isinstance(approval, dict):
        return False, ["schema: approval must be an object"]
    need = ("approval_text", "guardrail_ref", "intent_ref", "expires_at", "human_pub", "kid", "sig")
    missing = [f for f in need if f not in approval]
    if missing:
        return False, [f"schema: missing fields {missing}"]
    try:
        expected_text = approval_text(guardrail_ref, intent, approval["expires_at"])
    except (KeyError, ValueError, TypeError) as exc:
        return False, [f"schema: cannot recompute approval text: {exc}"]
    if approval["approval_text"] != expected_text:
        reasons.append("text: displayed approval text does not match the intent (hidden fields)")
    if approval["guardrail_ref"] != guardrail_ref:
        reasons.append("ref: countersign bound to a different guardrail_ref")
    try:
        expected_intent_ref = intent_ref(intent)
    except (ValueError, TypeError) as exc:
        return False, [f"schema: cannot recompute intent_ref: {exc}"]
    if approval["intent_ref"] != expected_intent_ref:
        reasons.append("ref: countersign bound to a different intent")
    if approval["human_pub"] != human_pub:
        reasons.append("key: countersign not under the mandate's human key")
    try:
        if approval["kid"] != keys.kid_for(human_pub):
            reasons.append("key: kid does not match the mandate's human key")
    except keys.KeyFormatError:
        return False, ["key: malformed human_pub"]
    try:
        body = {k: v for k, v in approval.items() if k != "sig"}
        sig_ok = keys.verify(approval["human_pub"], canonicalise(body), approval["sig"])
    except (ValueError, TypeError, KeyError) as exc:
        return False, [f"schema: approval not canonicalisable: {exc}"]
    if not sig_ok:
        reasons.append("sig: countersign signature invalid")
    now = now or datetime.now(timezone.utc)
    try:
        if now >= _parse(approval["expires_at"]):
            reasons.append("expired: countersign past expires_at")
    except (ValueError, TypeError):
        reasons.append("schema: malformed expires_at")
    return (not reasons), reasons
