"""X25519 and Ed25519 KATs and cross-consistency tests."""

import pytest

from secsci.primitives import ed25519 as ed
from secsci.primitives import x25519 as x


def test_rfc7748_alice_public():
    assert x.x25519_base(x.ALICE_PRIVATE) == x.ALICE_PUBLIC


def test_rfc7748_bob_public():
    assert x.x25519_base(x.BOB_PRIVATE) == x.BOB_PUBLIC


def test_rfc7748_shared_secret_both_directions():
    assert x.x25519(x.ALICE_PRIVATE, x.BOB_PUBLIC) == x.SHARED
    assert x.x25519(x.BOB_PRIVATE, x.ALICE_PUBLIC) == x.SHARED


def test_rfc7748_iterated_ladder():
    k = bytes.fromhex("0900000000000000000000000000000000000000000000000000000000000000")
    u = bytes.fromhex("0900000000000000000000000000000000000000000000000000000000000000")
    for _ in range(1):
        k, u = x.x25519(k, u), k
    assert k.hex() == "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"


def test_x25519_rejects_bad_lengths():
    with pytest.raises(ValueError):
        x.x25519(b"short", b"u" * 32)
    with pytest.raises(ValueError):
        x.x25519(b"k" * 32, b"u" * 31)


@pytest.mark.parametrize("vector", ed.VECTORS)
def test_rfc8032_public_key(vector):
    assert ed.public_key(bytes.fromhex(vector["seed"])).hex() == vector["public"]


@pytest.mark.parametrize("vector", ed.VECTORS)
def test_rfc8032_sign(vector):
    sig = ed.sign(bytes.fromhex(vector["seed"]), bytes.fromhex(vector["message"]))
    assert sig.hex() == vector["signature"]


@pytest.mark.parametrize("vector", ed.VECTORS)
def test_rfc8032_verify(vector):
    assert ed.verify(
        bytes.fromhex(vector["public"]),
        bytes.fromhex(vector["message"]),
        bytes.fromhex(vector["signature"]),
    )


def test_verify_rejects_tampering():
    v = ed.VECTORS[2]
    pub = bytes.fromhex(v["public"])
    msg = bytes.fromhex(v["message"])
    sig = bytes.fromhex(v["signature"])
    assert not ed.verify(pub, msg + b"x", sig)
    for i in range(0, 64, 7):
        bad = bytearray(sig)
        bad[i] ^= 1
        assert not ed.verify(pub, msg, bytes(bad))
    bad_pub = bytearray(pub)
    bad_pub[0] ^= 1
    assert not ed.verify(bytes(bad_pub), msg, sig)
    # S >= L must be rejected.
    s_high = int.from_bytes(sig[32:], "little") + ed.L
    bad_s = sig[:32] + (s_high & ((1 << 256) - 1)).to_bytes(32, "little")
    assert not ed.verify(pub, msg, bad_s)


def test_base_point_matches_rfc_encoding():
    assert ed._encode(ed.BASE).hex() == (
        "5866666666666666666666666666666666666666666666666666666666666666"
    )


def test_ed25519_to_x25519_birational_map():
    # For an Ed25519 key pair, converting the public key and deriving
    # X25519 public from the converted private key must agree.
    for v in ed.VECTORS:
        seed = bytes.fromhex(v["seed"])
        pub = bytes.fromhex(v["public"])
        x_priv = ed.seed_to_x25519_private(seed)
        assert x.x25519_base(x_priv) == ed.to_montgomery(pub)


def test_dh_between_ed25519_identities_agrees():
    a_seed = bytes.fromhex(ed.VECTORS[0]["seed"])
    b_seed = bytes.fromhex(ed.VECTORS[1]["seed"])
    a_pub, b_pub = ed.public_key(a_seed), ed.public_key(b_seed)
    a_priv = ed.seed_to_x25519_private(a_seed)
    b_priv = ed.seed_to_x25519_private(b_seed)
    shared_a = x.x25519(a_priv, ed.to_montgomery(b_pub))
    shared_b = x.x25519(b_priv, ed.to_montgomery(a_pub))
    assert shared_a == shared_b
