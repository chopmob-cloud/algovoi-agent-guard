"""The adversary is pluggable: AI, human, file or fuzzer are judged identically.

These tests prove the security claim does not depend on the attack source. The same
policy-violating charge fed through a *file* adversary (a human's authored payload)
is DENIED by the real guard and reported as a bypass by a weakened guard — exactly
as the model-driven negative control does. Human and fuzz lanes are exercised
hermetically (injected input / seeded RNG), and the provider client's parsing and
key resolution are unit-tested without any network call.
"""
from __future__ import annotations

import json

import pytest

import algovoi_agent_guard.guard as guard_mod
from algovoi_agent_guard.redteam import engine
from algovoi_agent_guard.redteam.adversary import make_adversary
from algovoi_agent_guard.redteam.client import (PRESETS, _content_text,
                                                  client_for, extract_json,
                                                  resolve_key)

_OVERCAP = {"attack_type": "cap_bypass_control", "charge_id": "h-bypass",
            "payee": "vendor-1", "amount": 5000, "scope": "inference",
            "asset": "USDC", "bind": "real", "approval": "human"}


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


def _write_attacks(tmp_path, specs):
    p = tmp_path / "attacks.json"
    p.write_text(json.dumps(specs), encoding="utf-8")
    return str(p)


def test_file_adversary_real_guard_denies(tmp_path):
    af = _write_attacks(tmp_path, [_OVERCAP])
    rc = engine.run_redteam(str(tmp_path), attacks=1, adversary="file", attacks_file=af)
    rep = _report(tmp_path)
    assert rc == 0
    assert rep["bypasses"] == []
    assert rep["adversary"]["kind"] == "file"
    row = rep["attacks"][0]
    assert row["verdict"] == "DENY"
    assert any("per_charge_cap" in r for r in row["guard_reasons"])


def test_file_adversary_weakened_guard_is_bypass(tmp_path, monkeypatch):
    _fail_open_caps(monkeypatch)
    af = _write_attacks(tmp_path, [_OVERCAP])
    rc = engine.run_redteam(str(tmp_path), attacks=1, adversary="file", attacks_file=af)
    rep = _report(tmp_path)
    assert rc == 1, "a human-authored violating charge must bypass a fail-open guard"
    assert rep["bypasses"] == [1]
    assert rep["attacks"][0]["bypass"] is True


def test_human_adversary_payload_denied(tmp_path):
    lines = iter([json.dumps(_OVERCAP), ""])
    rc = engine.run_redteam(str(tmp_path), attacks=3, adversary="human",
                            input_fn=lambda prompt: next(lines))
    rep = _report(tmp_path)
    assert rc == 0
    assert rep["adversary"]["kind"] == "human"
    assert rep["attacks"][0]["verdict"] == "DENY"
    assert rep["bypasses"] == []


def test_human_adversary_empty_stops(tmp_path):
    rc = engine.run_redteam(str(tmp_path), attacks=5, adversary="human",
                            input_fn=lambda prompt: "")
    rep = _report(tmp_path)
    # Hardened semantics: stopping with zero executed attacks is INCONCLUSIVE,
    # not a silent pass — the deterministic battery alone is not adversary coverage.
    assert rc == 1
    assert rep["attacks"] == []
    assert rep["executed"] == 0
    assert any("no attacks executed" in f for f in rep["failures"])
    assert all(d["pass"] for d in rep["deterministic"])


def test_fuzz_adversary_is_reproducible(tmp_path):
    def seq(out):
        engine.run_redteam(str(out), attacks=4, adversary="fuzz", seed=7)
        rep = _report(out)
        assert rep["adversary"]["seed"] == 7
        return [(a.get("attack_type"), a.get("intent", {}).get("charge_id"),
                 a.get("verdict")) for a in rep["attacks"]]

    a = seq(tmp_path / "r1")
    b = seq(tmp_path / "r2")
    assert a == b, "the same seed must yield the same attack sequence"
    assert len(a) == 4


def test_schema_denied_intent_renders_in_report(tmp_path):
    bad = dict(_OVERCAP, charge_id="bad", amount=-5)  # make_intent rejects negative
    af = _write_attacks(tmp_path, [bad])
    rc = engine.run_redteam(str(tmp_path), attacks=1, adversary="file", attacks_file=af)
    rep = _report(tmp_path)
    # A schema-DENY-only run never exercised the guard: inconclusive, not a pass.
    assert rc == 1
    assert rep["executed"] == 0
    row = rep["attacks"][0]
    assert row["verdict"] == "DENY"
    assert "schema" in row["violates"]
    assert "intent" not in row
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "schema" in md  # report writer must not KeyError on a schema row


def test_ai_disclaimer_present_in_report(tmp_path):
    af = _write_attacks(tmp_path, [_OVERCAP])
    engine.run_redteam(str(tmp_path), attacks=1, adversary="file", attacks_file=af)
    rep = _report(tmp_path)
    assert "AUTHORIZED" in rep["ai_disclaimer"]
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "AI disclaimer" in md


def test_make_adversary_rejects_unknown_and_missing_file():
    with pytest.raises(ValueError):
        make_adversary("bogus")
    with pytest.raises(ValueError):
        make_adversary("file")


def test_extract_json_balanced_and_fenced():
    assert extract_json('prefix {"a": {"b": 1}} suffix') == {"a": {"b": 1}}
    assert extract_json('```json\n{"x": 2}\n```') == {"x": 2}
    with pytest.raises(ValueError):
        extract_json("no object here")
    with pytest.raises(ValueError):
        extract_json('{"unbalanced": ')


def test_content_text_handles_block_list():
    blocks = [{"type": "thinking", "text": "ignore"},
              {"type": "text", "text": '{"ok": 1}'}]
    assert _content_text(blocks) == '{"ok": 1}'
    assert _content_text("plain") == "plain"
    assert _content_text(None) == ""


def test_resolve_key_and_local_dummy(monkeypatch):
    from algovoi_agent_guard.redteam import client as client_mod
    # Hermetic: ignore the real $HERMES_HOME/.env so the test does not depend on
    # which keys happen to be present on the host.
    monkeypatch.setattr(client_mod, "_hermes_env_key", lambda name: "")
    assert resolve_key(["MISTRAL_API_KEY"], env={"MISTRAL_API_KEY": "k"}) == "k"
    assert resolve_key(["NOPE_KEY"], env={}) == ""
    local = client_for("local", env={})
    assert local.key == "not-needed"
    assert local.provider == "local"
    with pytest.raises(RuntimeError):
        client_for("mistral", env={})


def test_presets_cover_named_providers():
    for name in ("qwen", "mistral", "nim", "openai", "local"):
        assert name in PRESETS
        assert PRESETS[name]["base"].startswith("http")
    assert PRESETS["qwen"]["enable_thinking"] is False
