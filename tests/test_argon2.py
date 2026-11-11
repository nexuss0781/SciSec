"""Argon2 KATs from RFC 9106 section 5, plus API behaviour tests."""

import pytest

from secsci.primitives.argon2 import (
    _initial_hash,
    argon2,
    argon2d,
    argon2i,
    argon2id,
    h_prime,
)

PASSWORD = b"\x01" * 32
SALT = b"\x02" * 16
SECRET = b"\x03" * 8
AD = b"\x04" * 12

VECTORS = {
    "d": "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
    "i": "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
    "id": "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
}

PREHASH = {
    "d": "b8819791a0359660bb7709c85fa48f04d5d82c05c5f215ccdb885491717cf757"
         "082c28b951be381410b5fc2eb7274033b9fdc7ae672bcaac5d179097a4af3109",
    "i": "c46065815276a0b3e731731c902f1fd80cf776907fbb7b6a5ca72e7b56011fee"
         "ca446c86dd75b9469a5e6879dec4b72d0863fb939b982e5f397cc7d164fddaa9",
    "id": "2889de487eb42ae500c0007ed9252f1069eadec40d5765b485de6dc2437a67b8"
          "546a2f0acc1a0882db8fcf74714b472e94df421a5da1112ffa11434370a1e997",
}


@pytest.mark.parametrize("variant", ["d", "i", "id"])
def test_rfc9106_tag(variant):
    tag = argon2(
        PASSWORD,
        SALT,
        time_cost=3,
        memory_cost=32,
        parallelism=4,
        tag_length=32,
        secret=SECRET,
        associated_data=AD,
        variant=variant,
    )
    assert tag.hex() == VECTORS[variant]


@pytest.mark.parametrize("variant", ["d", "i", "id"])
def test_rfc9106_prehashing_digest(variant):
    h0 = _initial_hash(
        PASSWORD, SALT, SECRET, AD, 32, 3, 4, 32, {"d": 0, "i": 1, "id": 2}[variant]
    )
    assert h0.hex() == PREHASH[variant]


def test_convenience_wrappers_match():
    kw = dict(
        time_cost=3,
        memory_cost=32,
        parallelism=4,
        tag_length=32,
        secret=SECRET,
        associated_data=AD,
    )
    assert argon2d(PASSWORD, SALT, **kw).hex() == VECTORS["d"]
    assert argon2i(PASSWORD, SALT, **kw).hex() == VECTORS["i"]
    assert argon2id(PASSWORD, SALT, **kw).hex() == VECTORS["id"]


def test_h_prime_short_and_long():
    # For outlen <= 64, H' is just BLAKE2b(LE32(outlen) || data).
    from secsci.primitives.blake2b import blake2b

    assert h_prime(b"abc", 32) == blake2b((32).to_bytes(4, "little") + b"abc", 32)
    long = h_prime(b"abc", 100)
    assert len(long) == 100
    assert long == h_prime(b"abc", 100)


def test_deterministic_and_salt_sensitive():
    kw = dict(time_cost=2, memory_cost=32, parallelism=2, tag_length=32)
    a = argon2id(PASSWORD, SALT, **kw)
    b = argon2id(PASSWORD, SALT, **kw)
    c = argon2id(PASSWORD, SALT + b"x", **kw)
    assert a == b
    assert a != c


def test_parameter_validation():
    with pytest.raises(ValueError):
        argon2(PASSWORD, SALT, variant="x")
    with pytest.raises(ValueError):
        argon2(PASSWORD, SALT, time_cost=0)
    with pytest.raises(ValueError):
        argon2(PASSWORD, SALT, parallelism=0)
    with pytest.raises(ValueError):
        argon2(PASSWORD, SALT, memory_cost=8, parallelism=4)
    with pytest.raises(ValueError):
        argon2(PASSWORD, SALT, tag_length=3)


@pytest.mark.slow
def test_production_parameters_64mib():
    # The component spec's production Argon2id settings.  Kept behind
    # the ``slow`` marker because pure-Python memory filling at 64 MiB
    # takes a while.
    tag = argon2id(
        b"correct horse battery staple",
        b"secsci-argon2-salt",
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        tag_length=32,
    )
    assert len(tag) == 32
