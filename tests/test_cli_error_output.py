"""The output mode must survive an argument error.

argparse raises before it knows what -o was set to, so a caller that asked for JSON
used to get a usage message and nothing machine-readable. These four cases pin the
recovery: three spellings of the flag must be honoured, and one shape must not be.
"""
import json

import pytest

from algovoi_agent_guard.cli import main


def _run(tmp_path, tail):
    return main(["keygen", "--out", str(tmp_path / "k"), *tail])


@pytest.mark.parametrize(
    "tail",
    [
        ["--bogus", "-o", "json"],
        ["--bogus", "-ojson"],
        ["--bogus", "--output=json"],
    ],
    ids=["separate", "attached", "long-with-equals"],
)
def test_json_output_survives_an_argument_error(tmp_path, capsys, tail):
    rc = _run(tmp_path, tail)
    out = capsys.readouterr().out
    assert rc == 2
    assert json.loads(out) == {"error": "invalid arguments", "exit_code": 2}


def test_flag_after_double_dash_is_positional(tmp_path, capsys):
    """`--` ends flag parsing, so this did not ask for JSON and must not get it."""
    rc = _run(tmp_path, ["--bogus", "--", "-o", "json"])
    out = capsys.readouterr().out
    assert rc == 2
    assert out.strip() == ""