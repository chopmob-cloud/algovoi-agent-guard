"""Parametrised red-team matrix: the same violating payloads are DENIED by the real
guard regardless of adversary kind, and a fail-open guard is caught as a bypass.
"""
from __future__ import annotations

import json

import pytest

import algovoi_agent_guard.guard as guard_mod
from algovoi_agent_guard.redteam import engine


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


def _write(tmp_path, specs):
    p = tmp_path / "attacks.json"
    p.write_text(json.dumps(specs), encoding="utf-8")
    return str(p)


_BASE = {"charge_id": "m-1", "payee": "vendor-1", "amount": 100,
         "scope": "inference", "asset": "USDC", "bind": "real", "approval": "human"}


@pytest.mark.parametrize("spec,reason", [
    (dict(_BASE, attack_type="cap_bypass_control", amount=5000), "per_charge_cap"),
    (dict(_BASE, attack_type="wrong_payee", payee="attacker"), "payee_not_allowed"),
    (dict(_BASE, attack_type="wrong_scope", scope="exfiltration"), "scope_not_allowed"),
])
def test_file_payloads_denied_by_real_guard(tmp_path, spec, reason):
    af = _write(tmp_path, [spec])
    rc = engine.run_redteam(str(tmp_path), attacks=1, adversary="file", attacks_file=af)
    rep = _report(tmp_path)
    assert rc == 0 and rep["bypasses"] == []
    row = rep["attacks"][0]
    assert row["verdict"] == "DENY"
    if reason:
        assert any(reason in r for r in row["guard_reasons"])


def test_overcap_bypasses_weakened_guard(tmp_path, monkeypatch):
    _fail_open_caps(monkeypatch)
    af = _write(tmp_path, [dict(_BASE, attack_type="cap_bypass_control", amount=5000)])
    rc = engine.run_redteam(str(tmp_path), attacks=1, adversary="file", attacks_file=af)
    rep = _report(tmp_path)
    assert rc == 1 and rep["bypasses"] == [1]


@pytest.mark.parametrize("seed", [1, 7, 42, 99])
def test_fuzz_seed_reproducible(tmp_path, seed):
    def seq(out):
        engine.run_redteam(str(out), attacks=3, adversary="fuzz", seed=seed)
        rep = _report(out)
        assert rep["adversary"]["seed"] == seed
        return [(a.get("attack_type"), a.get("verdict")) for a in rep["attacks"]]
    assert seq(tmp_path / "a") == seq(tmp_path / "b")


@pytest.mark.parametrize("kind", ["file", "fuzz"])
def test_disclaimer_and_adversary_kind_present(tmp_path, kind):
    kwargs = {"attacks": 2, "adversary": kind}
    if kind == "file":
        kwargs["attacks_file"] = _write(tmp_path, [dict(_BASE, attack_type="cap_bypass_control", amount=5000)])
    engine.run_redteam(str(tmp_path), **kwargs)
    rep = _report(tmp_path)
    assert rep["adversary"]["kind"] == kind
    assert "AUTHORIZED" in rep["ai_disclaimer"]
