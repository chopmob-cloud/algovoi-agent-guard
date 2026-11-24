"""Fault tolerance + error correction.

Contract under test (guard.py): hostile input never raises and never fails open;
every refusal is a receipt that recomputes offline; ledger faults are detected
and the atomic commit never leaves torn state. Each test isolates one property
so that disabling the corresponding check makes exactly this test fail.
"""
import copy
import os
from datetime import datetime, timezone

import pytest

from algovoi_agent_guard import guard, intent, jcs, keys, mandate, verify
from algovoi_agent_guard.ledger import Ledger, LedgerError, verify_chain

NOW = datetime(2026, 11, 23, 8, 0, 0, tzinfo=timezone.utc)
AGENT = "sha256:" + "b3" * 32
EXPIRES = "2026-11-23T09:00:00Z"
TS = "2026-11-23T08:00:00Z"


@pytest.fixture
def rig(tmp_path):
    priv, pub = keys.generate_keypair()
    env = mandate.issue_mandate(
        payer="payer-1", cap="1000", period="monthly", payee="vendor-1",
        scope=["inference"], max_per_charge="250", human_priv=priv, now=NOW)
    lg = Ledger(tmp_path / "l.jsonl")
    g = guard.Guard(env, lg, AGENT, now_fn=lambda: NOW)
    return {"priv": priv, "pub": pub, "env": env, "lg": lg, "g": g,
            "path": tmp_path / "l.jsonl"}


def _intent(rig, cid="c1", amount=100, payee="vendor-1", scope="inference"):
    return intent.make_intent(charge_id=cid, mandate_ref=rig["env"]["mandate_ref"],
                              payee=payee, amount=amount, at=NOW, scope=scope)


def _approve(rig, i):
    return intent.approve(rig["g"]._gref("ALLOW"), i, rig["priv"], EXPIRES)


def _forged(rig, i):
    return {"approval_text": "x", "guardrail_ref": rig["g"]._gref("ALLOW"),
            "intent_ref": "sha256:" + "0" * 64, "expires_at": EXPIRES,
            "human_pub": rig["pub"], "kid": keys.kid_for(rig["pub"]), "sig": "x"}


def _append(rig, cid, amount=10):
    rig["lg"].append(charge_id=cid, amount=amount, asset="USDC", payee="vendor-1",
                     period="monthly", guardrail_ref=rig["g"]._gref("ALLOW"), ts=TS)


# --- hostile intent: DENY, never raise -------------------------------------

@pytest.mark.parametrize("mutate", [
    lambda i: i.pop("at"),
    lambda i: i.update(payee="\ud800"),
    lambda i: i.update(charge_id="\ud800"),
    lambda i: i.update(amount=1.5),
    lambda i: i.update(amount=True),
    lambda i: i.update(amount=0),
    lambda i: i.update(amount=-5),
    lambda i: i.update(payee=""),
    lambda i: i.update(scope=["inference"]),
    lambda i: i.update(at="not-a-date"),
])
def test_hostile_intent_denied_without_raising(rig, mutate):
    i = _intent(rig)
    mutate(i)
    ev = guard.evaluate(rig["env"], i, _forged(rig, i), [], AGENT, NOW)
    assert ev["verdict"] == "DENY"
    assert ev["reasons"]


@pytest.mark.parametrize("bad", [None, "x", 42, [], 1.5])
def test_non_dict_intent_denied(rig, bad):
    ev = guard.evaluate(rig["env"], bad, None, [], AGENT, NOW)
    assert ev["verdict"] == "DENY"


def test_lone_surrogate_asset_no_approval_denied(rig):
    # Regression: a lone-surrogate asset must never reach a canonicalisable
    # ALLOW. The schema guard rejects it; countersign-required also denies here.
    i = _intent(rig)
    i["asset"] = "\ud800"
    ev = guard.evaluate(rig["env"], i, None, [], AGENT, NOW)
    assert ev["verdict"] == "DENY"


# --- error correction: hostile refusal receipts recompute offline ----------

@pytest.mark.parametrize("mutate", [
    lambda i: i.pop("at"),
    lambda i: i.update(payee="\ud800"),
    lambda i: i.update(charge_id="\ud800"),
    lambda i: i.update(amount=1.5),
])
def test_hostile_decide_receipt_is_recomputable(rig, mutate):
    i = _intent(rig)
    mutate(i)
    r = rig["g"].decide(i, _forged(rig, i))  # must not raise
    assert r["verdict"] == "DENY"
    ok, reasons = verify.verify_decision(rig["env"], r, rig["lg"].snapshot())
    assert ok, reasons


def test_hostile_approval_field_denied_and_recomputable(rig):
    i = _intent(rig)
    a = _approve(rig, i)
    a["approval_text"] = "\ud800"
    r = rig["g"].decide(i, a)
    assert r["verdict"] == "DENY"
    ok, reasons = verify.verify_decision(rig["env"], r, rig["lg"].snapshot())
    assert ok, reasons


def test_verify_approval_never_raises_on_hostile_intent(rig):
    i = _intent(rig)
    i["payee"] = "\ud800"
    ok, reasons = intent.verify_approval(
        _forged(rig, i), rig["g"]._gref("ALLOW"), i, rig["pub"], now=NOW)
    assert ok is False
    assert reasons


# --- JCS schema edge (correct refusal, not a fault) ------------------------

def test_jcs_refuses_float():
    with pytest.raises(jcs.JcsError):
        jcs.canonicalise({"x": 1.5})


def test_jcs_refuses_lone_surrogate():
    with pytest.raises(jcs.JcsError):
        jcs.canonicalise({"x": "\ud800"})


def test_jcs_escapes_control_chars():
    assert jcs.canonicalise({"x": "a\x00b"}) == b'{"x":"a\\u0000b"}'


# --- ledger fault detection ------------------------------------------------

def test_corrupt_ledger_file_refuses_to_operate(tmp_path):
    p = tmp_path / "l.jsonl"
    p.write_text("{broken\n", encoding="utf-8")
    with pytest.raises(LedgerError):
        Ledger(p)


def test_tampered_amount_detected(rig):
    i = _intent(rig)
    rig["g"].decide(i, _approve(rig, i))
    entries = rig["lg"].entries
    entries[0]["amount"] = 999
    ok, reasons = verify_chain(entries)
    assert not ok
    assert any("entry_ref does not recompute" in r for r in reasons)


def test_deleted_entry_breaks_chain(rig):
    for n in range(3):
        _append(rig, f"c{n}")
    entries = rig["lg"].entries
    del entries[1]
    ok, _ = verify_chain(entries)
    assert not ok


def test_reordered_entries_break_chain(rig):
    for n in range(3):
        _append(rig, f"c{n}")
    e = rig["lg"].entries
    e[0], e[1] = e[1], e[0]
    ok, _ = verify_chain(e)
    assert not ok


def test_duplicate_charge_detected(rig):
    _append(rig, "c1")
    e = rig["lg"].entries
    e.append(copy.deepcopy(e[0]))
    ok, reasons = verify_chain(e)
    assert not ok
    assert any("replay" in r for r in reasons)


def test_append_replay_refused(rig):
    _append(rig, "c1")
    with pytest.raises(LedgerError, match="replay"):
        _append(rig, "c1")


@pytest.mark.parametrize("amt", [1.5, True, 0, -5, "10"])
def test_append_rejects_non_integer_amount(rig, amt):
    with pytest.raises(LedgerError):
        rig["lg"].append(charge_id="c1", amount=amt, asset="USDC", payee="vendor-1",
                         period="monthly", guardrail_ref=rig["g"]._gref("ALLOW"), ts=TS)


def test_single_writer_lock(rig):
    lock = str(rig["path"]) + ".lock"
    fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    os.close(fd)
    try:
        with pytest.raises(LedgerError, match="another writer"):
            _append(rig, "c1")
    finally:
        os.unlink(lock)


# --- atomic commit: crash leaves no torn state, recovery works -------------

def test_atomic_commit_crash_leaves_original_intact(rig, monkeypatch):
    _append(rig, "c1")
    import algovoi_agent_guard.ledger as ledger_mod

    def boom(*a, **k):
        raise OSError("simulated crash before replace")

    with monkeypatch.context() as m:
        m.setattr(ledger_mod.os, "replace", boom)
        with pytest.raises(OSError):
            _append(rig, "c2")
    assert not os.path.exists(str(rig["path"]) + ".lock")  # lock released
    lg2 = Ledger(rig["path"])  # original intact, still verifies
    assert len(lg2.entries) == 1
    assert lg2.entries[0]["charge_id"] == "c1"
    _append(rig, "c2")  # recovery: a fresh append succeeds after the crash
    assert len(Ledger(rig["path"]).entries) == 2


def test_fault_located_and_prefix_recoverable(rig):
    for n in range(4):
        _append(rig, f"c{n}")
    entries = rig["lg"].entries
    entries[2]["amount"] = 999  # corrupt entry index 2
    ok, reasons = verify_chain(entries)
    assert not ok
    assert any(r.startswith("chain: entry 2") for r in reasons)
    prefix_ok, _ = verify_chain(entries[:2])  # verified prefix is recoverable
    assert prefix_ok


# --- receipt / settlement tamper detection ---------------------------------

def test_receipt_verdict_tamper_detected(rig):
    i = _intent(rig)
    r = rig["g"].decide(i, _approve(rig, i))
    assert r["verdict"] == "ALLOW"
    r2 = copy.deepcopy(r)
    r2["verdict"] = "DENY"
    ok, _ = verify.verify_decision(rig["env"], r2, rig["lg"].snapshot())
    assert not ok


def test_receipt_amount_tamper_detected(rig):
    i = _intent(rig)
    r = rig["g"].decide(i, _approve(rig, i))
    r2 = copy.deepcopy(r)
    r2["intent"]["amount"] = 999
    ok, _ = verify.verify_decision(rig["env"], r2, rig["lg"].snapshot())
    assert not ok


def test_settlement_binding_tamper_detected(rig):
    i = intent.make_intent(charge_id="c1", mandate_ref=rig["env"]["mandate_ref"],
                           payee="vendor-1", amount=100, at=NOW, scope="inference",
                           settlement_ref="settle-1")
    r = rig["g"].decide(i, _approve(rig, i))
    assert r["verdict"] == "ALLOW"
    s = {
        "decision_receipt_ref": r["receipt_ref"],
        "mandate_ref": r["mandate_ref"], "guardrail_ref": r["guardrail_ref"],
        "intent_ref": jcs.ref(r["intent"]),
        "charge_id": r["intent"]["charge_id"], "amount": r["intent"]["amount"],
        "asset": r["intent"]["asset"], "payee": r["intent"]["payee"],
        "settlement_ref": "settle-1",
    }
    s["settlement_receipt_ref"] = jcs.ref(s)
    ok, reasons = verify.verify_settlement(rig["env"], r, s, rig["lg"].snapshot())
    assert ok, reasons
    s2 = copy.deepcopy(s)
    s2["settlement_ref"] = "settle-OTHER"
    ok2, _ = verify.verify_settlement(rig["env"], r, s2, rig["lg"].snapshot())
    assert not ok2


# --- mandate / countersign faults ------------------------------------------

def test_expired_countersign_denied(rig):
    i = _intent(rig)
    a = intent.approve(rig["g"]._gref("ALLOW"), i, rig["priv"], "2026-11-23T07:00:00Z")
    ev = guard.evaluate(rig["env"], i, a, [], AGENT, NOW)
    assert ev["verdict"] == "DENY"
    assert any("expired" in r for r in ev["reasons"])


def test_malformed_mandate_missing_cap(rig):
    m = copy.deepcopy(rig["env"])
    del m["cap"]
    ok, _ = mandate.verify_mandate(m, now=NOW)
    assert not ok


def test_tampered_cap_breaks_ref_and_sig(rig):
    m = copy.deepcopy(rig["env"])
    m["cap"] = "9999"
    ok, reasons = mandate.verify_mandate(m, now=NOW)
    assert not ok
    assert any("mandate_ref does not recompute" in r for r in reasons)


def test_guard_construction_refuses_invalid_mandate(tmp_path):
    priv, _ = keys.generate_keypair()
    m = mandate.issue_mandate(payer="p", cap="1000", human_priv=priv, now=NOW)
    m["cap"] = "9999"
    lg = Ledger(tmp_path / "l.jsonl")
    with pytest.raises(guard.GuardError):
        guard.Guard(m, lg, AGENT)


def test_ledger_append_failure_denies_never_uncommitted_allow(rig, monkeypatch):
    # A valid intent + countersign would ALLOW, but the append fails. The DENY must
    # be FINAL: re-running pure evaluate() here would recompute ALLOW and emit an
    # uncommitted ALLOW (fail-open). Isolates the ledger_fault branch in Guard.decide.
    i = _intent(rig, cid="c-fault")
    a = _approve(rig, i)

    def boom(*args, **kwargs):
        raise LedgerError("simulated append failure")

    monkeypatch.setattr(rig["lg"], "append", boom)
    r = rig["g"].decide(i, a)
    assert r["verdict"] == "DENY", "ledger fault must not flip to an uncommitted ALLOW"
    assert any(x.startswith("ledger:") for x in r["reasons"])
    assert not rig["lg"].has_charge("c-fault")


def test_denial_never_flips_to_allow_on_recompute(rig, monkeypatch):
    # Force the hostile-input recompute to disagree (return ALLOW) while the first
    # decision is DENY. The elif branch must pin DENY — never emit an uncommitted
    # ALLOW. Isolates the verdict pin in Guard.decide's sanitisation branch.
    i = _intent(rig, cid="c-flip")
    a = _approve(rig, i)
    calls = {"n": 0}
    refs = {"policy_ref": "sha256:" + "0" * 64,
            "allow_ref": "sha256:" + "a" * 64, "deny_ref": "sha256:" + "d" * 64}

    def fake(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"verdict": "DENY", "reasons": ["countersign: forced"], **refs}
        return {"verdict": "ALLOW", "reasons": [], **refs}

    monkeypatch.setattr(guard, "evaluate", fake)
    r = rig["g"].decide(i, a)
    assert r["verdict"] == "DENY", "a refusal must never flip to an uncommitted ALLOW"
    assert any("refusal preserved" in x for x in r["reasons"])
    assert not rig["lg"].has_charge("c-flip")