"""The guard: fail-closed admission over a human-signed mandate.

Stateless recomputable admission: the guard holds NO signing key. Every
decision (ALLOW or DENY) is a content-addressed receipt that any third party
can re-derive offline from the envelope, the intent, the countersign and the
ledger snapshot (see verify.py). There is no mediator signature to steal and
no guard secret to compromise — the trust anchor is the human key the agent
never holds.

evaluate() is the PURE decision function; Guard.decide() and
verify.verify_decision() both call it, so a receipt recomputes by construction.
Check order (mirrors the estate's commercial guardrail): intent schema ->
authority binding -> mandate validity -> payee -> scope -> per-charge cap ->
period cap -> replay -> human countersign. Any failure is DENY with reasons;
hostile input never raises and never fails open. Only ALLOW appends to the
ledger, and only after a valid countersign of the prospective ALLOW ref.
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import intent as intent_mod
from . import mandate
from .jcs import JcsError, canonicalise, ref
from .l1 import REF_RE, guardrail_ref
from .ledger import Ledger, LedgerError, period_key

RECEIPT_TYPE = "algovoi_decision_receipt"
RECEIPT_VERSION = "1"


class GuardError(ValueError):
    """Guard configuration is invalid (trusted deployment material)."""


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def policy_bound_ref(envelope: dict) -> str:
    """Content-addressed deployed policy. Rotating any rule rotates the ref."""
    return ref({
        "type": "algovoi_policy_bound",
        "version": "1",
        "payee": envelope["payee"],
        "scope": envelope["scope"],
        "max_per_charge": envelope["max_per_charge"],
        "cap": envelope["cap"],
        "period": envelope["period"],
    })


def _validate_intent(i) -> list:
    if not isinstance(i, dict):
        return ["intent: must be an object"]
    try:
        intent_mod.make_intent(
            charge_id=i.get("charge_id"), mandate_ref=i.get("mandate_ref"),
            payee=i.get("payee"), amount=i.get("amount"),
            asset=i.get("asset", "USDC"), settlement_ref=i.get("settlement_ref"),
            scope=i.get("scope"),
        )
    except intent_mod.IntentError as exc:
        return [f"intent: {exc}"]
    except (TypeError, ValueError) as exc:
        return [f"intent: {exc}"]
    if "at" not in i or not isinstance(i["at"], str):
        return ["intent: missing or non-string 'at'"]
    try:
        intent_mod._parse(i["at"])
    except (ValueError, TypeError) as exc:
        return [f"intent: malformed 'at': {exc}"]
    try:
        canonicalise(i)
    except JcsError as exc:
        return [f"intent: outside float-free schema: {exc}"]
    return []


def _safe_json(v):
    """Recursively map any value into the float-free, valid-UTF-8 JCS schema so
    a refusal receipt is always canonicalisable. Non-UTF-8 strings and exotic
    types become their repr; floats become strings; structure is preserved."""
    if v is None or isinstance(v, bool) or isinstance(v, int):
        return v
    if isinstance(v, float):
        return str(v)
    if isinstance(v, str):
        try:
            v.encode("utf-8")
            return v
        except UnicodeEncodeError:
            return repr(v)
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            kk = k if isinstance(k, str) else repr(k)
            try:
                kk.encode("utf-8")
            except UnicodeEncodeError:
                kk = repr(kk)
            out[kk] = _safe_json(x)
        return out
    if isinstance(v, (list, tuple)):
        return [_safe_json(x) for x in v]
    return repr(v)[:512]


def _safe_intent(i):
    """JSON-safe representation of a hostile intent for embedding in a DENY
    receipt. The refusal reasons are recomputed over this representation so the
    receipt verifies offline by construction (see Guard.decide / verify.py)."""
    if not isinstance(i, dict):
        return {"malformed": True, "repr": repr(i)[:512]}
    return _safe_json(i)


def evaluate(envelope: dict, i, approval, entries, agent_ref: str,
             now: datetime, committed: bool = False) -> dict:
    """Pure decision. Returns {verdict, reasons, policy_ref, allow_ref, deny_ref}.

    committed=True means the ledger snapshot is expected to already contain
    this charge exactly once (offline verification of an ALLOW receipt); the
    charge is then excluded from the period total and its single presence is
    the commit, not a replay.
    """
    policy_ref = policy_bound_ref(envelope)
    mref = envelope["mandate_ref"]
    allow_ref = guardrail_ref(agent_ref=agent_ref, mandate_ref_=mref,
                              policy_bound_ref=policy_ref, verdict="ALLOW")
    deny_ref = guardrail_ref(agent_ref=agent_ref, mandate_ref_=mref,
                             policy_bound_ref=policy_ref, verdict="DENY")
    reasons = _validate_intent(i)
    if not reasons:
        if i["mandate_ref"] != mref:
            reasons.append("mandate: intent bound to a different authority")
        ok, mreasons = mandate.verify_mandate(envelope, now=now)
        if not ok:
            reasons += [f"mandate: {r}" for r in mreasons]
        if envelope["payee"] != "*" and i["payee"] != envelope["payee"]:
            reasons.append("policy: payee_not_allowed")
        if envelope["scope"] and i.get("scope") not in envelope["scope"]:
            reasons.append("policy: scope_not_allowed")
        if envelope["max_per_charge"] is not None and i["amount"] > int(envelope["max_per_charge"]):
            reasons.append("policy: per_charge_cap")
        pk = period_key(envelope["period"], i["at"])
        total = sum(e["amount"] for e in entries
                    if e.get("period_key") == pk
                    and not (committed and e.get("charge_id") == i["charge_id"]))
        if total + i["amount"] > int(envelope["cap"]):
            reasons.append("policy: period_cap")
        mine = [e for e in entries if e.get("charge_id") == i["charge_id"]]
        if committed:
            if len(mine) != 1 or mine[0].get("guardrail_ref") != allow_ref:
                reasons.append("ledger: ALLOW charge not committed exactly once under this ref")
        elif mine:
            reasons.append("policy: replay")
        if approval is None:
            reasons.append("countersign: required")
        else:
            ok, areasons = intent_mod.verify_approval(
                approval, allow_ref, i, envelope["human_pub"], now=now)
            if not ok:
                reasons += [f"countersign: {r}" for r in areasons]
    return {
        "verdict": "DENY" if reasons else "ALLOW",
        "reasons": reasons,
        "policy_ref": policy_ref,
        "allow_ref": allow_ref,
        "deny_ref": deny_ref,
    }


class Guard:
    def __init__(self, envelope: dict, ledger: Ledger, agent_ref: str, now_fn=None):
        ok, reasons = mandate.verify_mandate(envelope)
        if not ok:
            raise GuardError(f"mandate invalid at construction: {reasons}")
        if not isinstance(agent_ref, str) or not REF_RE.match(agent_ref):
            raise GuardError("agent_ref must be a sha256: 64-hex reference")
        self.envelope = envelope
        self.human_pub = envelope["human_pub"]  # PINNED: never read from input
        self.mandate_ref_ = envelope["mandate_ref"]
        self.policy_ref = policy_bound_ref(envelope)
        self.agent_ref = agent_ref
        self.ledger = ledger
        self._now = now_fn or (lambda: datetime.now(timezone.utc))

    def set_envelope(self, envelope: dict) -> None:
        """Install a re-signed authority (e.g. revocation) from the SAME human
        key. A different kid is a different authority and is refused — an agent
        cannot swap in a self-signed mandate."""
        if envelope.get("kid") != self.envelope["kid"] or \
                envelope.get("human_pub") != self.human_pub or \
                envelope.get("payer") != self.envelope["payer"]:
            raise GuardError("envelope swap refused: different human key or payer")
        ok, reasons = mandate.verify_mandate(envelope)
        if not ok and not any("revoked" in r for r in reasons):
            raise GuardError(f"envelope invalid: {reasons}")
        self.envelope = envelope
        self.mandate_ref_ = envelope["mandate_ref"]
        self.policy_ref = policy_bound_ref(envelope)

    def _gref(self, verdict: str) -> str:
        return guardrail_ref(agent_ref=self.agent_ref, mandate_ref_=self.mandate_ref_,
                             policy_bound_ref=self.policy_ref, verdict=verdict)

    def decide(self, i, approval=None) -> dict:
        """Return a decision receipt. Never raises; hostile input -> DENY."""
        now = self._now()
        ev = evaluate(self.envelope, i, approval, self.ledger.entries,
                      self.agent_ref, now, committed=False)
        ledger_fault = None
        if ev["verdict"] == "ALLOW":
            try:
                self.ledger.append(
                    charge_id=i["charge_id"], amount=i["amount"], asset=i["asset"],
                    payee=i["payee"], period=self.envelope["period"],
                    guardrail_ref=ev["allow_ref"], ts=i["at"],
                )
            except LedgerError as exc:
                ledger_fault = f"ledger: {exc}"
        if ledger_fault is not None:
            # Append failed: the charge is NOT committed. This DENY is final.
            # Never re-run evaluate() here — the pure policy would recompute ALLOW
            # for the still-valid intent and emit an uncommitted ALLOW (fail-open).
            i = _safe_intent(i)
            approval = _safe_json(approval) if approval is not None else None
            ev = {"verdict": "DENY", "reasons": [ledger_fault],
                  "policy_ref": ev["policy_ref"],
                  "allow_ref": ev["allow_ref"], "deny_ref": ev["deny_ref"]}
        elif ev["verdict"] == "DENY":
            # Hostile-input refusal: embed a canonical-safe intent and recompute the
            # reasons over it so the refusal verifies offline by construction. A
            # refusal must NEVER flip to an ALLOW here (no append happens on this
            # path), so the verdict is pinned to DENY regardless of the recompute.
            i = _safe_intent(i)
            approval = _safe_json(approval) if approval is not None else None
            ev2 = evaluate(self.envelope, i, approval, self.ledger.entries,
                           self.agent_ref, now, committed=False)
            if ev2["verdict"] == "DENY":
                ev = ev2
            else:
                ev = {"verdict": "DENY",
                      "reasons": ["schema: refusal preserved after sanitisation"],
                      "policy_ref": ev["policy_ref"],
                      "allow_ref": ev["allow_ref"], "deny_ref": ev["deny_ref"]}
        return self._receipt(ev["verdict"],
                             ev["allow_ref"] if ev["verdict"] == "ALLOW" else ev["deny_ref"],
                             i, ev["reasons"], approval, now)

    def _receipt(self, verdict, gref, i, reasons, approval, now) -> dict:
        r = {
            "type": RECEIPT_TYPE,
            "version": RECEIPT_VERSION,
            "verdict": verdict,
            "guardrail_ref": gref,
            "mandate_ref": self.mandate_ref_,
            "agent_ref": self.agent_ref,
            "policy_bound_ref": self.policy_ref,
            "intent": i,
            "reasons": reasons,
            "countersign": approval,
            "ledger_head": self.ledger.head(),
            "issued_at": _iso(now),
        }
        r["receipt_ref"] = ref(r)
        return r
