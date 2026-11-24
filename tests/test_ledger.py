"""Hash-chained ledger: one isolating test per integrity property."""
import json

import pytest

from algovoi_agent_guard.ledger import GENESIS, Ledger, LedgerError, verify_chain

TS = "2026-11-23T08:00:00Z"


def mk(tmp_path):
    return Ledger(tmp_path / "ledger.jsonl")


def app(lg, cid, amount=100):
    return lg.append(charge_id=cid, amount=amount, asset="USDC", payee="v",
                     period="monthly", guardrail_ref="sha256:" + "ab" * 32, ts=TS)


def test_append_and_chain(tmp_path):
    lg = mk(tmp_path)
    assert lg.head() == GENESIS
    e0 = app(lg, "c-0")
    e1 = app(lg, "c-1")
    assert e0["prev"] == GENESIS and e1["prev"] != GENESIS
    ok, reasons = verify_chain(lg.entries)
    assert ok, reasons


def test_replay_refused(tmp_path):
    lg = mk(tmp_path)
    app(lg, "c-0")
    with pytest.raises(LedgerError, match="replay"):
        app(lg, "c-0")


def test_tampered_amount_breaks_chain(tmp_path):
    lg = mk(tmp_path)
    app(lg, "c-0")
    entries = lg.entries
    entries[0]["amount"] = 1  # agent shrinks its recorded spend
    ok, reasons = verify_chain(entries)
    assert not ok and any("entry_ref" in r for r in reasons)


def test_deleted_entry_breaks_chain(tmp_path):
    lg = mk(tmp_path)
    app(lg, "c-0"); app(lg, "c-1"); app(lg, "c-2")
    entries = lg.entries
    del entries[1]
    ok, reasons = verify_chain(entries)
    assert not ok and any("seq" in r or "prev" in r for r in reasons)


def test_period_totals(tmp_path):
    lg = mk(tmp_path)
    app(lg, "c-0", 100)
    lg.append(charge_id="c-1", amount=50, asset="USDC", payee="v", period="monthly",
              guardrail_ref="sha256:" + "ab" * 32, ts="2026-12-01T00:00:00Z")
    assert lg.period_total("2026-11") == 100
    assert lg.period_total("2026-12") == 50


def test_corrupt_file_fails_closed(tmp_path):
    p = tmp_path / "ledger.jsonl"
    p.write_text('{"seq":0,"prev":"' + GENESIS + '","charge_id":"x"}' + chr(10), encoding="utf-8")
    with pytest.raises(LedgerError, match="corrupt"):
        Ledger(p)


def test_reload_preserves_chain(tmp_path):
    lg = mk(tmp_path)
    app(lg, "c-0"); app(lg, "c-1")
    lg2 = Ledger(lg.path)
    assert lg2.head() == lg.head()
    ok, reasons = verify_chain(lg2.snapshot()["entries"])
    assert ok, reasons
