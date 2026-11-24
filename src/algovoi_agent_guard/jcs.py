"""RFC 8785 (JCS) canonicalisation for a float-free schema.

The estate's frozen L1 spend-authority refs are SHA-256 over RFC 8785 JCS.
This module is dependency-free so the package runs standalone; correctness is
gated by the vendored public conformance vectors and the RFC 8785 §3.2.3
canonicalisation example (including UTF-16 code-unit key ordering, which puts
supplementary-plane characters before U+FB33).

Schema restriction: strings, integers, booleans, null, lists and dicts with
string keys. Floats are rejected — money is integer minor units or a decimal
string, never a binary float, so a signature can never depend on float noise.
"""
from __future__ import annotations

import hashlib
import json


class JcsError(ValueError):
    """Input is outside the float-free JCS schema."""


def _string(s: str) -> str:
    # Reject lone surrogates: not valid UTF-8, not canonicalisable.
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise JcsError(f"string is not valid UTF-8: {exc}") from exc
    # ensure_ascii=False emits literal UTF-8; json escapes exactly the JSON
    # mandatory set (quote, backslash, U+0000-U+001F), which is RFC 8785 §3.2.2.2.
    return json.dumps(s, ensure_ascii=False, separators=(",", ":"))


def _serialise(obj) -> str:
    if obj is None:
        return "null"
    if isinstance(obj, bool):  # before int: bool is an int subclass in Python
        return "true" if obj else "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        raise JcsError("floats are outside the float-free schema")
    if isinstance(obj, str):
        return _string(obj)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_serialise(v) for v in obj) + "]"
    if isinstance(obj, dict):
        for k in obj:
            if not isinstance(k, str):
                raise JcsError("object keys must be strings")
        # RFC 8785 §3.2.3: sort by UTF-16 code units, not code points.
        keys = sorted(obj.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_string(k) + ":" + _serialise(obj[k]) for k in keys) + "}"
    raise JcsError(f"unsupported type: {type(obj).__name__}")


def canonicalise(obj) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes of a float-free JSON value."""
    return _serialise(obj).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ref(obj) -> str:
    """The estate's content-address form: sha256: + hex(SHA-256(JCS(obj)))."""
    return "sha256:" + sha256_hex(canonicalise(obj))
