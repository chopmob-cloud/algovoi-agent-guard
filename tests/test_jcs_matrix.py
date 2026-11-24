"""Parametrised JCS (RFC 8785) vector matrix: ordering, types, rejections."""
import pytest

from algovoi_agent_guard import JcsError, canonicalise, ref


@pytest.mark.parametrize("obj,expected", [
    ({"b": 1, "a": 2}, b'{"a":2,"b":1}'),
    ({"z": 0, "a": 0}, b'{"a":0,"z":0}'),
    ({"flag": True, "n": 1}, b'{"flag":true,"n":1}'),
    ({"flag": False}, b'{"flag":false}'),
    ({"a": None}, b'{"a":null}'),
    ({"arr": [3, 1, 2]}, b'{"arr":[3,1,2]}'),
    ({"z": [3, 1, {"y": 2, "x": 1}], "a": None}, b'{"a":null,"z":[3,1,{"x":1,"y":2}]}'),
    ({"n": -7}, b'{"n":-7}'),
    ({"n": 0}, b'{"n":0}'),
    ({"s": "a\"b"}, b'{"s":"a\\"b"}'),
    ({"s": "line\nbreak"}, b'{"s":"line\\nbreak"}'),
    ({"ö": 1, "a": 2}, b'{"a":2,"\xc3\xb6":1}'),
    ({}, b'{}'),
    ({"empty": []}, b'{"empty":[]}'),
])
def test_canonical_vectors(obj, expected):
    assert canonicalise(obj) == expected


@pytest.mark.parametrize("bad", [
    {"amount": 1.5}, {"x": 0.1}, {1: "x"}, {None: "x"},
    "\ud800", {"nested": {"f": 2.5}}, {"arr": [1, 2.0]},
])
def test_rejection_vectors(bad):
    with pytest.raises(JcsError):
        canonicalise(bad)


@pytest.mark.parametrize("obj", [{"a": 1}, {"b": [1, 2], "a": "x"}, {"k": "\u20ac"}])
def test_ref_is_stable_sha256(obj):
    r1, r2 = ref(obj), ref(obj)
    assert r1 == r2 and r1.startswith("sha256:") and len(r1) == 71


def test_key_order_independent_of_insertion():
    a = canonicalise({"x": 1, "y": 2, "z": 3})
    b = canonicalise({"z": 3, "y": 2, "x": 1})
    assert a == b
