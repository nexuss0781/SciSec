"""AES Key Wrap KATs from RFC 3394 sections 4.1-4.6."""

import pytest

from secsci.primitives.aeskw import unwrap, wrap

DATA128 = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
DATA192 = DATA128 + bytes.fromhex("0001020304050607")
DATA256 = DATA128 + bytes.fromhex("000102030405060708090A0B0C0D0E0F")

VECTORS = [
    (
        "000102030405060708090A0B0C0D0E0F",
        DATA128,
        "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
    ),
    (
        "000102030405060708090A0B0C0D0E0F1011121314151617",
        DATA128,
        "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
    ),
    (
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        DATA128,
        "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
    ),
    (
        "000102030405060708090A0B0C0D0E0F1011121314151617",
        DATA192,
        "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
    ),
    (
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        DATA192,
        "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
    ),
    (
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        DATA256,
        "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43B"
        "FB988B9B7A02DD21",
    ),
]


@pytest.mark.parametrize("kek,data,ct", VECTORS)
def test_rfc3394_wrap_unwrap(kek, data, ct):
    kek, data, ct = bytes.fromhex(kek), data, bytes.fromhex(ct)
    assert wrap(kek, data).hex().upper() == ct.hex().upper()
    assert unwrap(kek, ct) == data


def test_corrupt_ciphertext_is_rejected():
    kek = bytes(range(32))
    ct = wrap(kek, bytes(range(16)))
    for i in range(len(ct)):
        bad = bytearray(ct)
        bad[i] ^= 1
        with pytest.raises(ValueError):
            unwrap(kek, bytes(bad))


def test_wrong_kek_is_rejected():
    ct = wrap(b"a" * 32, bytes(range(16)))
    with pytest.raises(ValueError):
        unwrap(b"b" * 32, ct)


def test_parameter_validation():
    with pytest.raises(ValueError):
        wrap(b"k" * 32, b"short")
    with pytest.raises(ValueError):
        wrap(b"k" * 32, b"x" * 15)
    with pytest.raises(ValueError):
        unwrap(b"k" * 32, b"x" * 16)
    with pytest.raises(ValueError):
        wrap(b"k" * 32, b"x" * 16, b"badiv")
