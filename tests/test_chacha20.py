"""ChaCha20, Poly1305 and ChaCha20-Poly1305 KATs (RFC 8439)."""

import pytest

from secsci.primitives.chacha20 import block, chacha20
from secsci.primitives.chacha20poly1305 import (
    chacha20poly1305_decrypt,
    chacha20poly1305_encrypt,
)
from secsci.primitives.poly1305 import poly1305

KEY = bytes(range(32))
SUNSCREEN = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you "
    b"only one tip for the future, sunscreen would be it."
)


def test_block_function_vector():
    out = block(KEY, 1, bytes.fromhex("000000090000004a00000000"))
    assert out.hex() == (
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )


def test_chacha20_encryption_vector():
    nonce = bytes.fromhex("000000000000004a00000000")
    expected = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d"
    )
    assert chacha20(KEY, nonce, SUNSCREEN, counter=1) == expected
    assert chacha20(KEY, nonce, expected, counter=1) == SUNSCREEN


def test_poly1305_vector():
    key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    )
    assert poly1305(key, b"Cryptographic Forum Research Group").hex() == (
        "a8061dc1305136c6c22b8baf0c0127a9"
    )


def test_aead_vector():
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    expected_ct = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116"
    )
    ct, tag = chacha20poly1305_encrypt(key, nonce, SUNSCREEN, aad)
    assert ct == expected_ct
    assert tag.hex() == "1ae10b594f09e26a7e902ecbd0600691"
    assert chacha20poly1305_decrypt(key, nonce, ct, tag, aad) == SUNSCREEN


def test_aead_tamper_detection():
    key, nonce = b"k" * 32, b"n" * 12
    ct, tag = chacha20poly1305_encrypt(key, nonce, b"hello", b"ad")
    for i in range(len(ct)):
        bad = bytearray(ct)
        bad[i] ^= 1
        with pytest.raises(ValueError):
            chacha20poly1305_decrypt(key, nonce, bytes(bad), tag, b"ad")
    with pytest.raises(ValueError):
        chacha20poly1305_decrypt(key, nonce, ct, bytes(16), b"ad")
    with pytest.raises(ValueError):
        chacha20poly1305_decrypt(key, nonce, ct, tag, b"ad!")


def test_parameter_validation():
    with pytest.raises(ValueError):
        block(b"short", 0, b"n" * 12)
    with pytest.raises(ValueError):
        block(KEY, 0, b"n" * 8)
    with pytest.raises(ValueError):
        block(KEY, -1, b"n" * 12)
    with pytest.raises(ValueError):
        poly1305(b"short", b"x")
    with pytest.raises(ValueError):
        chacha20poly1305_encrypt(KEY, b"short", b"x")
