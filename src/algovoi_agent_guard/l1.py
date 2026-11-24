"""Frozen L1 spend-authority references (byte-compatible with the public vectors).

Reproduces, exactly, the two published conformance sets:

* ``payment_mandate_lite/v1``:
  ``mandate_ref = "sha256:" + SHA-256(JCS({cap, payer, period, revocation_state}))``
  All four fields are non-empty strings (cap is a string); an empty or missing
  field is rejected, not hashed.

* ``spend_guardrail_lite/v1``:
  ``guardrail_ref = "sha256:" + SHA-256(JCS({agent_ref, mandate_ref,
  policy_bound_ref, verdict}))`` with verdict in the closed set {ALLOW, DENY}
  and each ref a ``sha256:`` + 64 lowercase hex reference.

These refs are the canonical ``mandate_ref`` / guardrail decision refs the
AlgoVoi keystone chain and fabric bind (keystone step ``mandate``, order 2).
This module adds no fields to the frozen format; the human-anchor signature
layer lives in ``anchor.py`` as an envelope *around* these refs.
"""
from __future__ import annotations

import re

from .jcs import ref

REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
VERDICTS = ("ALLOW", "DENY")
MANDATE_FIELDS = ("payer", "cap", "period", "revocation_state")


class L1Error(ValueError):
    """Input violates the frozen L1 format (rejected, not hashed)."""


def _nonempty_str(name: str, value) -> str:
    if not isinstance(value, str) or value == "":
        raise L1Error(f"{name} must be a non-empty string")
    return value


def _ref_form(name: str, value) -> str:
    if not isinstance(value, str) or not REF_RE.match(value):
        raise L1Error(f"{name} must be a sha256: 64-hex reference")
    return value


def mandate_ref(payer: str, cap: str, period: str, revocation_state: str) -> str:
    """Content address of a spend authority. cap is a string (e.g. "1000")."""
    payload = {
        "payer": _nonempty_str("payer", payer),
        "cap": _nonempty_str("cap", cap),
        "period": _nonempty_str("period", period),
        "revocation_state": _nonempty_str("revocation_state", revocation_state),
    }
    return ref(payload)


def guardrail_ref(agent_ref: str, mandate_ref_: str, policy_bound_ref: str, verdict: str) -> str:
    """Content address of a pre-payment ALLOW/DENY decision bound to its inputs."""
    if verdict not in VERDICTS:
        raise L1Error(f"verdict must be one of {VERDICTS}")
    payload = {
        "agent_ref": _ref_form("agent_ref", agent_ref),
        "mandate_ref": _ref_form("mandate_ref", mandate_ref_),
        "policy_bound_ref": _ref_form("policy_bound_ref", policy_bound_ref),
        "verdict": verdict,
    }
    return ref(payload)
