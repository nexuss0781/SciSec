"""AES block cipher and CTR KATs (FIPS 197, SP 800-38A)."""

import pytest

from secsci.primitives.aes import AES, INV_SBOX, SBOX, ctr_xor

# FIPS 197 Appendix C, plaintext 00112233...eeff
PT = bytes.fromhex("00112233445566778899aabbccddeeff")

AES_VECTORS = [
    ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "8ea2b7ca516745bfeafc49904b496089",
    ),
]


@pytest.mark.parametrize("key,ct", AES_VECTORS)
def test_fips197_encrypt_decrypt(key, ct):
    cipher = AES(bytes.fromhex(key))
    ciphertext = cipher.encrypt_block(PT)
    assert ciphertext.hex() == ct
    assert cipher.decrypt_block(ciphertext) == PT


def test_sbox_is_derived_correctly():
    # Spot checks from FIPS 197 Figure 7 and the inverse table.
    assert SBOX[0x00] == 0x63
    assert SBOX[0x01] == 0x7C
    assert SBOX[0x53] == 0xED
    assert SBOX[0xFF] == 0x16
    assert INV_SBOX[0x63] == 0x00
    for i in range(256):
        assert INV_SBOX[SBOX[i]] == i


def test_sp800_38a_ctr_aes128():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    counter = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plaintext = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
    )
    expected = bytes.fromhex(
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
    )
    assert ctr_xor(key, counter, plaintext) == expected


def test_key_size_validation():
    with pytest.raises(ValueError):
        AES(b"short")
    with pytest.raises(ValueError):
        AES(b"k" * 15)
    with pytest.raises(ValueError):
        AES(b"k" * 33)
    with pytest.raises(ValueError):
        AES(b"k" * 16).encrypt_block(b"x")
