

import pytest


# ---- hardening fixes from the Claude VM2 second-opinion review -------------

def _file_run(tmp_path, specs, attacks):
    import json as _json
    from algovoi_agent_guard.redteam.engine import run_redteam
    f = tmp_path / "specs.json"
    f.write_text(_json.dumps(specs), encoding="utf-8")
    out = str(tmp_path / "out")
    rc = run_redteam(out, attacks=attacks, adversary="file", attacks_file=str(f))
    import json
    rep = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    return rc, rep


def test_all_refused_is_inconclusive_not_pass(tmp_path):
    rc, rep = _file_run(tmp_path, [{"refusal": True, "reason": "no"}] * 3, 3)
    assert rc == 1
    assert rep["executed"] == 0 and rep["refused"] == 3
    assert any("no attacks executed" in f for f in rep["failures"])


def test_non_dict_spec_recorded_as_failure(tmp_path):
    rc, rep = _file_run(tmp_path, ["oops", 42], 2)
    assert rc == 1
    assert rep["errored"] == 2 and rep["executed"] == 0
    assert any("invalid spec" in f for f in rep["failures"])


def test_unhashable_approval_does_not_crash(tmp_path):
    spec = {"charge_id": "u1", "payee": "vendor-1", "amount": 100,
            "scope": "inference", "bind": "real", "approval": ["x"]}
    rc, rep = _file_run(tmp_path, [spec], 1)
    assert rep["executed"] == 1            # handled, not a crash
    assert rep["attacks"][0]["verdict"] == "DENY"


def test_infinite_amount_is_schema_deny_not_coverage(tmp_path):
    spec = {"charge_id": "i1", "payee": "vendor-1", "amount": float("inf"),
            "scope": "inference", "bind": "real", "approval": "none"}
    rc, rep = _file_run(tmp_path, [spec], 1)
    assert rep["attacks"][0]["violates"] == ["schema"]
    assert rep["attacks"][0]["verdict"] == "DENY"
    # A malformed spec never reached the guard: it is not coverage, and a run
    # of only malformed specs is inconclusive, not a silent pass.
    assert rep["executed"] == 0
    assert rc == 1
    assert any("no attacks executed" in f for f in rep["failures"])


def test_resolve_key_no_ambient_leak_when_env_injected(monkeypatch):
    from algovoi_agent_guard.redteam import client as c
    monkeypatch.setattr(c, "_hermes_env_key", lambda name: "AMBIENT-SECRET")
    assert c.resolve_key(["X"], env={}) == ""        # injected env must not leak
    assert c.resolve_key(["X"], env={"X": "explicit"}) == "explicit"


def test_unknown_provider_raises_not_silent_qwen():
    from algovoi_agent_guard.redteam.client import client_for
    with pytest.raises(RuntimeError):
        client_for("qewn", env={})


def test_non_https_key_endpoint_refused():
    from algovoi_agent_guard.redteam.client import OpenAICompatClient
    cl = OpenAICompatClient("http://evil.example/v1", "k", "m")
    with pytest.raises(RuntimeError):
        cl.chat([{"role": "user", "content": "x"}])


def test_cli_redteam_surfaces_disclaimer(tmp_path, capsys):
    from algovoi_agent_guard import cli
    rc = cli.main(["redteam", "--adversary", "fuzz", "--attacks", "2",
                   "--seed", "5", "--outdir", str(tmp_path / "o")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "AI disclaimer:" in out
    assert "not a proof of security" in out


def test_cli_redteam_help_has_disclaimer_epilog(capsys):
    from algovoi_agent_guard import cli
    with pytest.raises(SystemExit) as ei:
        cli.main(["redteam", "--help"])
    assert ei.value.code == 0
    assert "AI DISCLAIMER:" in capsys.readouterr().out


def test_cli_unknown_provider_clean_error(tmp_path, capsys):
    from algovoi_agent_guard import cli
    rc = cli.main(["redteam", "--adversary", "model", "--provider", "bogus",
                   "--outdir", str(tmp_path / "o")])
    assert rc == 2
    assert "unknown provider" in capsys.readouterr().err


def test_cli_epilog_uses_engine_disclaimer_constant(capsys):
    from algovoi_agent_guard import cli
    from algovoi_agent_guard.redteam.engine import AI_DISCLAIMER
    with pytest.raises(SystemExit):
        cli.main(["redteam", "--help"])
    out = capsys.readouterr().out
    # single source of truth: the help epilog must embed the exact constant
    assert AI_DISCLAIMER in out


def test_zero_or_negative_attacks_rejected(tmp_path):
    from algovoi_agent_guard.redteam.engine import run_redteam
    for n in (0, -1):
        with pytest.raises(ValueError):
            run_redteam(str(tmp_path / f"z{n}"), attacks=n, adversary="fuzz")


def test_partial_coverage_is_labelled(tmp_path, capsys):
    spec = {"charge_id": "p1", "payee": "vendor-1", "amount": 100,
            "scope": "inference", "bind": "real", "approval": "none"}
    rc, rep = _file_run(tmp_path, [spec], 2)   # one spec, two requested
    out = capsys.readouterr().out
    assert rc == 0
    assert rep["coverage"] == {"executed": 1, "requested": 2}
    assert "PARTIAL COVERAGE (1/2 executed)" in out


def test_preset_key_not_sent_to_custom_host():
    from algovoi_agent_guard.redteam.client import client_for
    # openai preset key must NOT ride to an arbitrary --base-url host
    with pytest.raises(RuntimeError):
        client_for("openai", base_url="https://other.example/v1",
                   env={"OPENAI_API_KEY": "***"})
    # explicit api_key_env is honoured for the custom host
    cl = client_for("openai", base_url="https://other.example/v1",
                    api_key_env="CUSTOM", env={"CUSTOM": "ck"})
    assert cl.key == "ck" and cl.base == "https://other.example/v1"
    # default preset host still uses its own (explicit) key
    cl2 = client_for("openai", api_key_env="CUSTOM", env={"CUSTOM": "ck"})
    assert cl2.key == "ck"


def test_non_https_error_redacts_userinfo():
    from algovoi_agent_guard.redteam.client import OpenAICompatClient
    cl = OpenAICompatClient("http://user:pass@evil.example/v1", "k", "m")
    with pytest.raises(RuntimeError) as ei:
        cl.chat([{"role": "user", "content": "x"}])
    msg = str(ei.value)
    assert "evil.example" in msg
    assert "user:pass" not in msg
