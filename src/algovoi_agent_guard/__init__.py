"""algovoi-agent-guard: the budget your agent can't raise.

Standalone, human-signed spend mandates with offline-verifiable receipts,
byte-compatible with the frozen AlgoVoi L1 spend-authority format.
"""
from . import intent, keys, mandate, receipt
from .guard import Guard, GuardError, evaluate, policy_bound_ref
from .jcs import JcsError, canonicalise, ref, sha256_hex
from .l1 import L1Error, VERDICTS, guardrail_ref, mandate_ref
from .ledger import Ledger, LedgerError, verify_chain
from .verify import verify_decision, verify_settlement

__version__ = "0.1.0"
__all__ = [
    "JcsError", "L1Error", "VERDICTS", "GuardError", "LedgerError",
    "canonicalise", "ref", "sha256_hex",
    "mandate_ref", "guardrail_ref", "policy_bound_ref", "evaluate",
    "Guard", "Ledger", "verify_chain", "verify_decision", "verify_settlement",
    "intent", "keys", "mandate", "receipt", "__version__",
]
