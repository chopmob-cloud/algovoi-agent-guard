"""Append-only, hash-chained spend ledger. Single writer, atomic appends.

Each entry carries seq, the sha256 of the previous entry's JCS (genesis = 64
zeros), the charge facts and entry_ref = sha256(JCS(entry without entry_ref)).
Rewriting or deleting any entry breaks the chain, and verify_chain() detects it
offline from public material alone. The ledger lives OUTSIDE the agent's
workspace; an agent that can rewrite the file still cannot produce a chain that
verifies against a head it does not control (the head is published with every
receipt). Duplicate charge_id is a replay and is refused.
"""
from __future__ import annotations

import copy
import json
import os
from datetime import datetime, timezone

from .jcs import canonicalise, ref, sha256_hex

GENESIS = "0" * 64
LEDGER_TYPE = "algovoi_spend_ledger"
LEDGER_VERSION = "1"


class LedgerError(ValueError):
    """Ledger is corrupt, locked, or the append is invalid."""


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def period_key(period: str, ts: str) -> str:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if period == "monthly":
        return dt.strftime("%Y-%m")
    if period == "daily":
        return dt.strftime("%Y-%m-%d")
    if period == "yearly":
        return dt.strftime("%Y")
    if period == "weekly":
        iso = dt.isocalendar()
        return f"{iso[0]}-W{iso[1]:02d}"
    return "all"  # 'once' / unknown periods: one lifetime budget


def entry_ref(entry: dict) -> str:
    return ref({k: v for k, v in entry.items() if k != "entry_ref"})


def verify_chain(entries) -> tuple:
    """Offline: (ok, reasons). Recomputes every entry_ref and prev link."""
    reasons = []
    if not isinstance(entries, list):
        return False, ["schema: entries must be a list"]
    prev = GENESIS
    seen = set()
    for n, e in enumerate(entries):
        if not isinstance(e, dict):
            return False, [f"chain: entry {n} not an object"]
        if e.get("seq") != n:
            reasons.append(f"chain: entry {n} seq mismatch")
        if e.get("prev") != prev:
            reasons.append(f"chain: entry {n} prev link broken")
        if "entry_ref" not in e or e["entry_ref"] != entry_ref(e):
            reasons.append(f"chain: entry {n} entry_ref does not recompute")
        cid = e.get("charge_id")
        if cid in seen:
            reasons.append(f"replay: charge_id {cid!r} appears twice")
        seen.add(cid)
        prev = sha256_hex(canonicalise(e))
    return (not reasons), reasons


class Ledger:
    def __init__(self, path):
        self.path = str(path)
        self._entries = []
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    self._entries = [json.loads(line) for line in fh if line.strip()]
            except (OSError, json.JSONDecodeError) as exc:
                raise LedgerError(f"ledger unreadable: {exc}") from exc
            ok, reasons = verify_chain(self._entries)
            if not ok:
                raise LedgerError(f"ledger chain corrupt, refusing to operate: {reasons}")

    @property
    def entries(self):
        return list(self._entries)

    def head(self) -> str:
        if not self._entries:
            return GENESIS
        return sha256_hex(canonicalise(self._entries[-1]))

    def has_charge(self, charge_id: str) -> bool:
        return any(e.get("charge_id") == charge_id for e in self._entries)

    def period_total(self, key: str) -> int:
        return sum(e["amount"] for e in self._entries if e.get("period_key") == key)

    def append(self, *, charge_id: str, amount: int, asset: str, payee: str,
               period: str, guardrail_ref: str, ts: str) -> dict:
        if self.has_charge(charge_id):
            raise LedgerError(f"replay: charge_id {charge_id!r} already committed")
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            raise LedgerError("amount must be a positive integer")
        entry = {
            "seq": len(self._entries),
            "prev": self.head(),
            "charge_id": charge_id,
            "amount": amount,
            "asset": asset,
            "payee": payee,
            "period_key": period_key(period, ts),
            "guardrail_ref": guardrail_ref,
            "ts": ts,
        }
        entry["entry_ref"] = entry_ref(entry)
        ok, reasons = verify_chain(self._entries + [entry])
        if not ok:
            raise LedgerError(f"append would break chain: {reasons}")
        lock = self.path + ".lock"
        fd = None
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            tmp = self.path + ".tmp"
            # atomic append = write the FULL new history to tmp, then replace
            with open(tmp, "w", encoding="utf-8") as fh:
                for e in self._entries + [entry]:
                    fh.write(json.dumps(e, separators=(",", ":"), ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except FileExistsError as exc:
            raise LedgerError("another writer holds the ledger lock") from exc
        finally:
            if fd is not None:
                os.close(fd)
                try:
                    os.unlink(lock)
                except OSError:
                    pass
        self._entries.append(entry)
        return entry

    def snapshot(self) -> dict:
        return {
            "type": LEDGER_TYPE,
            "version": LEDGER_VERSION,
            "entries": copy.deepcopy(self._entries),
            "head": self.head(),
        }
