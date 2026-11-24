"""JCS correctness: RFC 8785 §3.2.3 example + float-free schema guards."""
import pytest

from algovoi_agent_guard import JcsError, canonicalise, ref


def test_rfc8785_canonicalisation_example():
    # RFC 8785 §3.2.3: key order is UTF-16 code units, so the emoji (U+1F600,
    # surrogates D83D DE00) sorts BEFORE U+FB33; U+0080 is emitted literally.
    obj = {
        "\u20ac": "Euro Sign",
        "\r": "Carriage Return",
        "\ufb33": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001f600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "\u00f6": "Latin Small Letter O With Diaeresis",
    }
    expected = (
        '{"\\r":"Carriage Return","1":"One","\u0080":"Control",'
        '"\u00f6":"Latin Small Letter O With Diaeresis","\u20ac":"Euro Sign",'
        '"\U0001f600":"Emoji: Grinning Face",'
        '"\ufb33":"Hebrew Letter Dalet With Dagesh"}'
    ).encode("utf-8")
    assert canonicalise(obj) == expected


def test_key_sort_and_no_whitespace():
    assert canonicalise({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_nested_and_arrays():
    assert canonicalise({"z": [3, 1, {"y": 2, "x": 1}], "a": None}) == \
        b'{"a":null,"z":[3,1,{"x":1,"y":2}]}'


def test_bool_is_not_int():
    assert canonicalise({"flag": True, "n": 1}) == b'{"flag":true,"n":1}'


def test_float_rejected():
    with pytest.raises(JcsError):
        canonicalise({"amount": 1.5})


def test_non_string_key_rejected():
    with pytest.raises(JcsError):
        canonicalise({1: "x"})


def test_lone_surrogate_rejected():
    with pytest.raises(JcsError):
        canonicalise("\ud800")


def test_ref_form():
    r = ref({"a": 1})
    assert r.startswith("sha256:") and len(r) == 71
