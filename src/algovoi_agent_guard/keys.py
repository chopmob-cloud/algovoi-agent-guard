"""Ed25519 human-anchor keys. Raw 32-byte keys, base64url (no padding).

The human holds the private key OUTSIDE the agent's reach; the agent only ever
sees public material. kid = sha256(raw_pub)[:16] — the estate's key-id convention.
verify() never raises: malformed material is a False, not an exception, so a
hostile payload cannot crash the guard into a fail-open state.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class KeyFormatError(ValueError):
    """Key material is malformed."""


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    if not isinstance(s, str):
        raise KeyFormatError("expected base64url string")
    pad = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except Exception as exc:
        raise KeyFormatError(f"bad base64url: {exc}") from exc


def generate_keypair() -> tuple:
    """Return (private_b64, public_b64) for a fresh Ed25519 key."""
    sk = Ed25519PrivateKey.generate()
    raw_priv = sk.private_bytes_raw()
    raw_pub = sk.public_key().public_bytes_raw()
    return _b64e(raw_priv), _b64e(raw_pub)


def pub_from_priv(priv_b64: str) -> str:
    raw = _b64d(priv_b64)
    if len(raw) != 32:
        raise KeyFormatError("private key must be 32 raw bytes")
    try:
        sk = Ed25519PrivateKey.from_private_bytes(raw)
    except Exception as exc:
        raise KeyFormatError(f"bad private key: {exc}") from exc
    return _b64e(sk.public_key().public_bytes_raw())


def kid_for(pub_b64: str) -> str:
    return hashlib.sha256(_b64d(pub_b64)).hexdigest()[:16]


def sign(priv_b64: str, data: bytes) -> str:
    raw = _b64d(priv_b64)
    if len(raw) != 32:
        raise KeyFormatError("private key must be 32 raw bytes")
    try:
        sk = Ed25519PrivateKey.from_private_bytes(raw)
    except Exception as exc:
        raise KeyFormatError(f"bad private key: {exc}") from exc
    return _b64e(sk.sign(data))


def verify(pub_b64: str, data: bytes, sig_b64: str) -> bool:
    """True iff sig is a valid Ed25519 signature by pub over data. Never raises."""
    try:
        raw_pub = _b64d(pub_b64)
        raw_sig = _b64d(sig_b64)
        if len(raw_pub) != 32 or len(raw_sig) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(raw_pub).verify(raw_sig, data)
        return True
    except (InvalidSignature, KeyFormatError, ValueError, TypeError):
        return False
