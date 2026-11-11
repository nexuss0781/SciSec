"""KATs for SHA-2, HMAC and HKDF (RFC 6234, RFC 4231, RFC 5869).

The constants are *derived* from prime roots in ``secsci.primitives.hash``;
here we assert they match the published FIPS / RFC tables exactly, then
run the published test vectors for the algorithms built on top.
"""

import pytest

from secsci.primitives import hash as h


# ---------------------------------------------------------------------------
# Derived constants vs. published tables (FIPS 180-4 / RFC 6234)
# ---------------------------------------------------------------------------

def test_sha256_iv_and_k_are_derived_correctly():
    assert h.IV256 == (
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    )
    assert h.K256[0] == 0x428A2F98
    assert h.K256[1] == 0x71374491
    assert h.K256[63] == 0xC67178F2
    assert h.K256[10] == 0x243185BE  # spot check deep in the table


def test_sha512_iv_and_k_are_derived_correctly():
    assert h.IV512 == (
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1, 0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
    )
    assert h.K512[0] == 0x428A2F98D728AE22
    assert h.K512[79] == 0x6C44198C4A475817


def test_sha384_iv_uses_primes_9_through_16():
    assert h.IV384[0] == 0xCBBB9D5DC1059ED8
    assert h.IV384[7] == 0x47B5481DBEFA4FA4


# ---------------------------------------------------------------------------
# FIPS 180-2 / RFC 6234 digest vectors
# ---------------------------------------------------------------------------

ABC = b"abc"
BLOCK448 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
BLOCK896 = (
    b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
    b"ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
)

SHA256_KATS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (ABC, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (BLOCK448, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
]

SHA512_KATS = [
    (
        b"",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    ),
    (
        ABC,
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ),
    (
        BLOCK896,
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
        "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
    ),
]

SHA384_KATS = [
    (
        ABC,
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
        "8086072ba1e7cc2358baeca134c825a7",
    ),
    (
        BLOCK896,
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
        "fcc7c71a557e2db966c3e9fa91746039",
    ),
]


@pytest.mark.parametrize("msg,expected", SHA256_KATS)
def test_sha256_kat(msg, expected):
    assert h.sha256(msg).hex() == expected


@pytest.mark.parametrize("msg,expected", SHA512_KATS)
def test_sha512_kat(msg, expected):
    assert h.sha512(msg).hex() == expected


@pytest.mark.parametrize("msg,expected", SHA384_KATS)
def test_sha384_kat(msg, expected):
    assert h.sha384(msg).hex() == expected


@pytest.mark.slow
def test_sha256_million_a():
    digest = h.SHA256()
    chunk = b"a" * 1000
    for _ in range(1000):
        digest.update(chunk)
    assert digest.hexdigest() == (
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    )


@pytest.mark.slow
def test_sha512_million_a():
    digest = h.SHA512()
    chunk = b"a" * 1000
    for _ in range(1000):
        digest.update(chunk)
    assert digest.hexdigest() == (
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
        "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
    )


def test_incremental_updates_match_one_shot():
    data = bytes(range(256)) * 7
    for fn, cls in ((h.sha256, h.SHA256), (h.sha384, h.SHA384), (h.sha512, h.SHA512)):
        one = fn(data)
        inc = cls()
        for i in range(0, len(data), 37):
            inc.update(data[i : i + 37])
        assert inc.digest() == one


# ---------------------------------------------------------------------------
# RFC 4231 HMAC-SHA-256 / HMAC-SHA-512 vectors
# ---------------------------------------------------------------------------

HMAC_CASES = [
    (
        bytes([0x0B]) * 20,
        b"Hi There",
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
        "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    ),
    (
        b"Jefe",
        b"what do ya want for nothing?",
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
        "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
    ),
    (
        bytes([0xAA]) * 20,
        bytes([0xDD]) * 50,
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39"
        "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
    ),
    (
        bytes(range(1, 26)),
        bytes([0xCD]) * 50,
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db"
        "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
    ),
    (
        bytes([0xAA]) * 131,
        b"Test Using Larger Than Block-Size Key - Hash Key First",
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
        "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
    ),
    (
        bytes([0xAA]) * 131,
        b"This is a test using a larger than block-size key and a larger "
        b"than block-size data. The key needs to be hashed before being used"
        b" by the HMAC algorithm.",
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944"
        "b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
    ),
]


@pytest.mark.parametrize("key,msg,exp256,exp512", HMAC_CASES)
def test_hmac_sha256_rfc4231(key, msg, exp256, exp512):
    assert h.hmac_sha256(key, msg).hex() == exp256


@pytest.mark.parametrize("key,msg,exp256,exp512", HMAC_CASES)
def test_hmac_sha512_rfc4231(key, msg, exp256, exp512):
    assert h.hmac_sha512(key, msg).hex() == exp512


def test_hmac_long_key_is_hashed():
    key = b"k" * 200
    assert h.hmac_sha256(key, b"x") == h.hmac_sha256(h.sha256(key), b"x")


# ---------------------------------------------------------------------------
# RFC 5869 HKDF vectors
# ---------------------------------------------------------------------------

HKDF_CASES = [
    dict(
        ikm=bytes([0x0B]) * 22,
        salt=bytes.fromhex("000102030405060708090a0b0c"),
        info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        length=42,
        prk="077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        okm="3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865",
    ),
    dict(
        ikm=bytes(range(0x00, 0x50)),
        salt=bytes(range(0x60, 0xB0)),
        info=bytes(range(0xB0, 0x100)),
        length=82,
        prk="06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
        okm="b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f1d87",
    ),
    dict(
        ikm=bytes([0x0B]) * 22,
        salt=b"",
        info=b"",
        length=42,
        prk="19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
        okm="8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8",
    ),
]


@pytest.mark.parametrize("case", HKDF_CASES)
def test_hkdf_sha256_rfc5869(case):
    prk = h.hkdf_extract("sha256", case["salt"], case["ikm"])
    assert prk.hex() == case["prk"]
    okm = h.hkdf_expand("sha256", prk, case["info"], case["length"])
    assert okm.hex() == case["okm"]
    assert h.hkdf_sha256(case["ikm"], case["salt"], case["info"], case["length"]) == okm


def test_hkdf_rejects_overlong_output():
    with pytest.raises(ValueError):
        h.hkdf_sha256(b"x", b"", b"", 255 * 32 + 1)
