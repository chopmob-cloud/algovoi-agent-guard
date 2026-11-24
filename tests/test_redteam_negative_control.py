"""Negative control for the red-team harness itself.

A red-team that always reports PASS is hollow. These two tests prove the harness
is load-bearing in BOTH directions, with a stubbed adversary so the control is
deterministic and spends no model calls:

  1. Weaken the guard's cap checks (fail open) and feed a policy-violating but
     otherwise-valid charge. The independent predicate must still flag it, so the
     run reports a bypass and FAILS (exit 1). This proves "0 bypasses" on the real
     guard is a finding, not a harness that cannot detect a bypass.
  2. Leave the real guard intact and feed the SAME charge. It must DENY with the
     cap reason and the run must pass with zero bypasses. This proves the real
     guard stops exactly the charge the weakened guard lets through.

The security claim rests on the independent predicate (_violates), which never
calls the guard — so weakening guard.evaluate does not weaken the judge.
"""
from __future__ import annotations

import json

import algovoi_agent_guard.guard as guard_mod
from algovoi_agent_guard.redteam import engine

# A charge that violates per-charge cap (5000 > 250) and period cap (5000 > 1000)
# but is otherwise valid: correct payee, scope, authority binding, human countersign.
_OVERCAP = (
    '{"attack_type":"cap_bypass_control","charge_id":"q-bypass","payee":"vendor-1",'
    '"amount":5000,"scope":"inference","asset":"USDC","bind":"real","approval":"human"}'
)


def _stub_adversary(monkeypatch):
    class _StubAdversary:
        name = "control-stub"

        def __init__(self):
            self.calls = 0
            self._done = False

        def describe(self):
            return {"kind": "model", "provider": "stub", "model": "control-stub"}

        def next_attack(self, n, ctx):
            if self._done:
                return None
            self._done = True
            self.calls += 1
            return json.loads(_OVERCAP)

    # Patch the factory the engine actually calls (bound at import), replacing the
    # whole adversary so the control needs no API key and makes no network call —
    # hermetic on any host, not just one where a key happens to be present.
    monkeypatch.setattr(engine, "make_adversary", lambda *a, **k: _StubAdversary())


def _fail_open_caps(monkeypatch):
    orig = guard_mod.evaluate

    def weakened(envelope, i, approval, entries, agent_ref, now, committed=False):
        ev = orig(envelope, i, approval, entries, agent_ref, now, committed=committed)
        ev["reasons"] = [r for r in ev["reasons"]
                         if r not in ("policy: per_charge_cap", "policy: period_cap")]
        ev["verdict"] = "DENY" if ev["reasons"] else "ALLOW"
        return ev

    monkeypatch.setattr(guard_mod, "evaluate", weakened)


def _report(outdir):
    return json.loads((outdir / "report.json").read_text(encoding="utf-8"))


def test_weakened_guard_is_reported_as_bypass(tmp_path, monkeypatch):
    _fail_open_caps(monkeypatch)
    _stub_adversary(monkeypatch)
    rc = engine.run_redteam(str(tmp_path), attacks=1)
    rep = _report(tmp_path)
    assert rc == 1, "a fail-open guard must FAIL the red-team"
    assert rep["passed"] is False
    assert rep["bypasses"] == [1], "the violating ALLOW must be recorded as a bypass"
    row = rep["attacks"][0]
    assert row["verdict"] == "ALLOW"
    assert "per_charge_cap" in row["violates"]
    assert "period_cap" in row["violates"]
    assert row["bypass"] is True


def test_real_guard_denies_the_same_charge(tmp_path, monkeypatch):
    _stub_adversary(monkeypatch)  # guard left intact
    rc = engine.run_redteam(str(tmp_path), attacks=1)
    rep = _report(tmp_path)
    assert rc == 0, "the real guard must stop the over-cap charge and pass"
    assert rep["passed"] is True
    assert rep["bypasses"] == []
    row = rep["attacks"][0]
    assert row["verdict"] == "DENY"
    assert any("per_charge_cap" in r for r in row["guard_reasons"])
    assert row["bypass"] is False