"""The human-signed mandate envelope around the frozen L1 spend authority.

The four frozen L1 fields (payer, cap, period, revocation_state) produce the
canonical mandate_ref exactly as the public conformance vectors define it.
The envelope ADDS payee/scope/per-charge ceiling, the human public key, validity
window and an Ed25519 signature over the whole body — it never alters the frozen
ref. Raising the cap means a new mandate_ref AND a new human signature; an agent
without the human key can produce neither.

Revocation is a new envelope with revocation_state="revoked" (a distinct L1 ref,
per vector pm-003), signed by the same human key.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from . import keys
from .jcs import canonicalise
from .l1 import L1Error, mandate_ref

ENVELOPE_TYPE = "algovoi_mandate_envelope"
ENVELOPE_VERSION = "1"
DECIMAL_RE = re.compile(r"^[1-9][0-9]*$")
REQUIRED = (
    "type", "version", "payer", "cap", "period", "revocation_state",
    "payee", "scope", "max_per_charge", "mandate_ref", "human_pub", "kid",
    "issued_at", "expires_at", "sig",
)


class MandateError(ValueError):
    """Mandate issuance input is invalid."""


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def mandate_body(m: dict) -> dict:
    """Everything the human signature covers (the envelope minus the sig)."""
    return {k: v for k, v in m.items() if k != "sig"}


def issue_mandate(
    *,
    payer: str,
    cap: str,
    human_priv: str,
    period: str = "monthly",
    payee: str = "*",
    scope=None,
    max_per_charge=None,
    ttl_secs: int = 31_536_000,
    now: datetime | None = None,
) -> dict:
    """Issue a mandate signed by the human key. cap is a decimal string of
    integer minor units (e.g. "1000"); floats are refused at the schema edge."""
    if not isinstance(payer, str) or not payer:
        raise MandateError("payer must be a non-empty string")
    if not isinstance(cap, str) or not DECIMAL_RE.match(cap):
        raise MandateError("cap must be a positive decimal string (minor units)")
    if not isinstance(period, str) or not period:
        raise MandateError("period must be a non-empty string")
    if not isinstance(payee, str) or not payee:
        raise MandateError("payee must be a non-empty string ('*' = any)")
    scope = list(scope) if scope else []
    if any(not isinstance(s, str) or not s for s in scope):
        raise MandateError("scope entries must be non-empty strings")
    if max_per_charge is not None and (
        not isinstance(max_per_charge, str) or not DECIMAL_RE.match(max_per_charge)
    ):
        raise MandateError("max_per_charge must be a positive decimal string or None")
    if not isinstance(ttl_secs, int) or ttl_secs < 60:
        raise MandateError("ttl_secs must be an integer >= 60")
    now = now or datetime.now(timezone.utc)
    pub = keys.pub_from_priv(human_priv)
    body = {
        "type": ENVELOPE_TYPE,
        "version": ENVELOPE_VERSION,
        "payer": payer,
        "cap": cap,
        "period": period,
        "revocation_state": "active",
        "payee": payee,
        "scope": scope,
        "max_per_charge": max_per_charge,
        "mandate_ref": mandate_ref(payer, cap, period, "active"),
        "human_pub": pub,
        "kid": keys.kid_for(pub),
        "issued_at": _iso(now),
        "expires_at": _iso(now + timedelta(seconds=ttl_secs)),
    }
    body["sig"] = keys.sign(human_priv, canonicalise(mandate_body(body)))
    return body


def revoke(m: dict, human_priv: str) -> dict:
    """Re-sign the same authority with revocation_state='revoked' (new L1 ref)."""
    ok, reasons = verify_mandate(m, now=_parse(m["issued_at"]))
    if not ok and "revoked" not in " ".join(reasons):
        raise MandateError(f"cannot revoke an invalid mandate: {reasons}")
    body = mandate_body(m)
    body["revocation_state"] = "revoked"
    body["mandate_ref"] = mandate_ref(
        body["payer"], body["cap"], body["period"], "revoked"
    )
    body["sig"] = keys.sign(human_priv, canonicalise(mandate_body(body)))
    return body


def verify_mandate(m, now: datetime | None = None) -> tuple:
    """Offline check: (ok, reasons). Never raises — hostile input is a refusal.

    Checks schema, the frozen L1 ref, the human key id, the envelope signature,
    revocation state and the validity window. No network, no private material.
    """
    reasons = []
    if not isinstance(m, dict):
        return False, ["schema: mandate must be an object"]
    missing = [f for f in REQUIRED if f not in m]
    if missing:
        return False, [f"schema: missing fields {missing}"]
    if m["type"] != ENVELOPE_TYPE or m["version"] != ENVELOPE_VERSION:
        reasons.append("schema: wrong type/version")
    try:
        expected_ref = mandate_ref(m["payer"], m["cap"], m["period"], m["revocation_state"])
    except L1Error as exc:
        return False, [f"l1: {exc}"]
    if m["mandate_ref"] != expected_ref:
        reasons.append("l1: mandate_ref does not recompute from the frozen fields")
    if not isinstance(m["human_pub"], str) or not isinstance(m["sig"], str):
        return False, ["schema: human_pub/sig must be strings"]
    try:
        if m["kid"] != keys.kid_for(m["human_pub"]):
            reasons.append("key: kid does not match human_pub")
    except keys.KeyFormatError:
        return False, ["key: malformed human_pub"]
    if not keys.verify(m["human_pub"], canonicalise(mandate_body(m)), m["sig"]):
        reasons.append("sig: envelope signature invalid under human_pub")
    if m["revocation_state"] != "active":
        reasons.append("revoked: mandate revocation_state is not active")
    now = now or datetime.now(timezone.utc)
    try:
        if now >= _parse(m["expires_at"]):
            reasons.append("expired: mandate past expires_at")
        if _parse(m["issued_at"]) > now:
            reasons.append("not_yet_valid: issued_at in the future")
    except (ValueError, TypeError):
        reasons.append("schema: malformed issued_at/expires_at")
    return (not reasons), reasons
