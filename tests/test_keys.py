"""One isolating test per key operation; malformed material must never raise."""
import pytest

from algovoi_agent_guard import keys


def test_roundtrip():
    priv, pub = keys.generate_keypair()
    sig = keys.sign(priv, b"pay 100 USDC to vendor")
    assert keys.verify(pub, b"pay 100 USDC to vendor", sig) is True


def test_kid_stable_16_hex():
    _, pub = keys.generate_keypair()
    kid = keys.kid_for(pub)
    assert len(kid) == 16 and all(c in "0123456789abcdef" for c in kid)
    assert keys.kid_for(pub) == kid


def test_pub_from_priv_matches():
    priv, pub = keys.generate_keypair()
    assert keys.pub_from_priv(priv) == pub


def test_wrong_key_rejects():
    priv, _ = keys.generate_keypair()
    _, other_pub = keys.generate_keypair()
    sig = keys.sign(priv, b"data")
    assert keys.verify(other_pub, b"data", sig) is False


def test_tampered_data_rejects():
    priv, pub = keys.generate_keypair()
    sig = keys.sign(priv, b"pay 100")
    assert keys.verify(pub, b"pay 900", sig) is False


@pytest.mark.parametrize("pub,sig", [
    ("not-base64!!", "AAAA"),
    ("AAAA", "not-base64!!"),
    ("", ""),
    (None, None),
])
def test_malformed_verify_is_false_not_raise(pub, sig):
    assert keys.verify(pub, b"data", sig) is False


def test_sign_bad_priv_raises_keyformat():
    with pytest.raises(keys.KeyFormatError):
        keys.sign("AAAA", b"data")
