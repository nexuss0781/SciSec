"""Cross-validation of the C++ core engine against the Python reference.

These tests are marked ``binding`` and skip cleanly when the shared
library has not been built.  Build it with::

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --config Release

The randomized cases exercise every exported operation, not just the
known-answer vectors.
"""

import hashlib
import os
import random

import pytest

from secsci import binding
from secsci.components.c1_drbg import HMACDRBG
from secsci.components.c12_sharing import (
    P as GF_P,
    add as gf_add,
    encode_field,
    inv as gf_inv,
    mul as gf_mul,
    sub as gf_sub,
)
from secsci.primitives import chacha20poly1305 as py_chacha
from secsci.primitives import gcm as py_gcm
from secsci.primitives import hash as py_hash
from secsci.primitives import x25519 as py_x25519

pytestmark = pytest.mark.binding

RNG = random.Random(0x5EC5C1)


@pytest.fixture(scope="module")
def core():
    try:
        return binding.default_core()
    except binding.LibraryNotFound as exc:
        pytest.skip(str(exc))


def random_bytes(length: int) -> bytes:
    return bytes(RNG.getrandbits(8) for _ in range(length))


def test_abi_version_and_selftest(core):
    assert core.api.abi_version == binding.ABI_VERSION
    assert "secsci" in core.version
    assert core.selftest() is True
    assert core.path is not None and core.path.is_file()


def test_sha_matches_python_and_hashlib(core):
    lengths = [0, 1, 3, 55, 56, 57, 63, 64, 65, 127, 128, 129, 1000]
    for length in lengths:
        data = random_bytes(length)
        assert core.sha256(data) == py_hash.sha256(data)
        assert core.sha256(data) == hashlib.sha256(data).digest()
        assert core.sha512(data) == py_hash.sha512(data)
        assert core.sha512(data) == hashlib.sha512(data).digest()


def test_hmac_matches_python(core):
    key_lengths = [0, 1, 16, 32, 63, 64, 65, 128, 129, 200]
    for key_length in key_lengths:
        key = random_bytes(key_length)
        for message_length in (0, 1, 32, 100, 300):
            message = random_bytes(message_length)
            assert core.hmac_sha256(key, message) == py_hash.hmac_sha256(
                key, message
            )
            assert core.hmac_sha512(key, message) == py_hash.hmac_sha512(
                key, message
            )


def test_hkdf_matches_python(core):
    for _ in range(20):
        ikm = random_bytes(RNG.randrange(1, 100))
        salt = random_bytes(RNG.randrange(0, 80))
        info = random_bytes(RNG.randrange(0, 80))
        length = RNG.randrange(1, 250)
        assert core.hkdf_sha256(ikm, salt, info, length) == py_hash.hkdf_sha256(
            ikm, salt, info, length
        )
        assert core.hkdf_sha512(ikm, salt, info, length) == py_hash.hkdf_sha512(
            ikm, salt, info, length
        )
    # A missing salt is the all-zero salt of the hash length.
    assert core.hkdf_sha256(b"ikm", None, b"info", 42) == py_hash.hkdf_sha256(
        b"ikm", None, b"info", 42
    )


def test_aes_gcm_known_answer_and_fuzz(core):
    key = bytes(32)
    nonce = bytes(12)
    ciphertext, tag = core.aes256_gcm_encrypt(key, nonce, b"")
    assert ciphertext == b""
    assert tag.hex() == "530f8afbc74536b9a963b4f1c4cb738b"

    for _ in range(30):
        key = random_bytes(32)
        nonce = random_bytes(12)
        aad = random_bytes(RNG.randrange(0, 40))
        plaintext = random_bytes(RNG.randrange(0, 200))
        ciphertext, tag = core.aes256_gcm_encrypt(key, nonce, plaintext, aad)
        expected_ciphertext, expected_tag = py_gcm.gcm_encrypt(
            key, nonce, plaintext, aad
        )
        assert ciphertext == expected_ciphertext
        assert tag == expected_tag
        assert core.aes256_gcm_decrypt(
            key, nonce, ciphertext, tag, aad
        ) == plaintext

    key = random_bytes(32)
    nonce = random_bytes(12)
    ciphertext, tag = core.aes256_gcm_encrypt(key, nonce, b"tamper me")
    bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
    with pytest.raises(binding.AuthenticationError):
        core.aes256_gcm_decrypt(key, nonce, ciphertext, bad_tag)
    with pytest.raises(binding.AuthenticationError):
        core.aes256_gcm_decrypt(key, nonce, ciphertext, tag, b"wrong aad")


def test_chacha20poly1305_known_answer_and_fuzz(core):
    key = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    )
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    ciphertext, tag = core.chacha20poly1305_encrypt(
        key, nonce, plaintext, aad
    )
    expected_ciphertext, expected_tag = py_chacha.chacha20poly1305_encrypt(
        key, nonce, plaintext, aad
    )
    assert ciphertext == expected_ciphertext
    assert tag == expected_tag
    assert tag.hex() == "1ae10b594f09e26a7e902ecbd0600691"

    for _ in range(30):
        key = random_bytes(32)
        nonce = random_bytes(12)
        aad = random_bytes(RNG.randrange(0, 40))
        plaintext = random_bytes(RNG.randrange(0, 200))
        ciphertext, tag = core.chacha20poly1305_encrypt(
            key, nonce, plaintext, aad
        )
        expected_ciphertext, expected_tag = (
            py_chacha.chacha20poly1305_encrypt(key, nonce, plaintext, aad)
        )
        assert ciphertext == expected_ciphertext
        assert tag == expected_tag
        assert core.chacha20poly1305_decrypt(
            key, nonce, ciphertext, tag, aad
        ) == plaintext

    key = random_bytes(32)
    nonce = random_bytes(12)
    ciphertext, tag = core.chacha20poly1305_encrypt(key, nonce, b"tamper me")
    with pytest.raises(binding.AuthenticationError):
        core.chacha20poly1305_decrypt(
            key, nonce, ciphertext, bytes([tag[0] ^ 1]) + tag[1:]
        )


def test_x25519_known_answers(core):
    scalar = bytes.fromhex(
        "a546e36bf0527c9d3b16154b82465edd"
        "62144c0ac1fc5a18506a2244ba449ac4"
    )
    point = bytes.fromhex(
        "e6db6867583030db3594c1a424b15f7c"
        "726624ec26b3353b10a903a6d0ab1c4c"
    )
    assert core.x25519(scalar, point).hex() == (
        "c3da55379de9c6908e94ea4df28d084f"
        "32eccf03491c71f754b4075577a28552"
    )

    alice = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645"
        "df4c2f87ebc0992ab177fba51db92c2a"
    )
    bob = bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee6"
        "6f3bb1292618b6fd1c2f8b27ff88e0eb"
    )
    alice_public = core.x25519_base(alice)
    bob_public = core.x25519_base(bob)
    assert alice_public.hex() == (
        "8520f0098930a754748b7ddcb43ef75a"
        "0dbf3a0d26381af4eba4a98eaa9b4e6a"
    )
    assert bob_public.hex() == (
        "de9edb7d7b7dc1b4d35b61c2ece43537"
        "3f8343c85b78674dadfc7e146f882b4f"
    )
    shared = core.x25519(alice, bob_public)
    assert shared == core.x25519(bob, alice_public)
    assert shared.hex() == (
        "4a5d9d5ba4ce2de1728e3bf480350f25"
        "e07e21c947d19e3376f09b3c1e161742"
    )


def test_x25519_randomized_agreement(core):
    for _ in range(15):
        alice = random_bytes(32)
        bob = random_bytes(32)
        alice_public = core.x25519_base(alice)
        bob_public = core.x25519_base(bob)
        assert alice_public == py_x25519.x25519_base(alice)
        assert bob_public == py_x25519.x25519_base(bob)
        assert core.x25519(alice, bob_public) == py_x25519.x25519(
            alice, bob_public
        )
        assert core.x25519(alice, bob_public) == core.x25519(
            bob, alice_public
        )
    # The all-zero point maps to zero.
    assert core.x25519(random_bytes(32), bytes(32)) == bytes(32)


def test_drbg_matches_python(core):
    entropy = bytes(range(32))
    nonce = bytes(range(16))
    personalization = b"Sec-Sci binding test"
    python_drbg = HMACDRBG(entropy, nonce, personalization)
    with core.drbg(entropy, nonce, personalization) as cpp_drbg:
        for length, additional in [
            (1, b""),
            (32, b""),
            (33, b"additional input"),
            (64, b""),
            (100, bytes(range(10))),
        ]:
            assert cpp_drbg.generate(length, additional) == (
                python_drbg.generate(length, additional)
            )
        new_entropy = bytes(range(32, 64))
        cpp_drbg.reseed(new_entropy, b"reseed context")
        python_drbg.reseed(new_entropy, b"reseed context")
        assert cpp_drbg.generate(48) == python_drbg.generate(48)


def test_drbg_rejects_short_seed(core):
    with pytest.raises(ValueError):
        core.drbg(bytes(31), bytes(16))
    with pytest.raises(ValueError):
        core.drbg(bytes(32), bytes(15))


def test_drbg_handle_is_single_use(core):
    drbg = core.drbg(bytes(32), bytes(16))
    drbg.generate(16)
    drbg.close()
    with pytest.raises(ValueError):
        drbg.generate(16)


def test_gf521_matches_python(core):
    values = [0, 1, 2, 3, GF_P - 1, GF_P - 2]
    values += [RNG.randrange(GF_P) for _ in range(20)]
    for a in values:
        encoded_a = encode_field(a)
        if a == 0:
            # Zero has no inverse; both implementations must reject it.
            with pytest.raises(ZeroDivisionError):
                gf_inv(a)
            with pytest.raises(ValueError):
                core.gf521_inv(encoded_a)
        else:
            assert core.gf521_inv(encoded_a) == encode_field(gf_inv(a))
        for b in values[:10]:
            encoded_b = encode_field(b)
            assert core.gf521_add(encoded_a, encoded_b) == encode_field(
                gf_add(a, b)
            )
            assert core.gf521_sub(encoded_a, encoded_b) == encode_field(
                gf_sub(a, b)
            )
            assert core.gf521_mul(encoded_a, encoded_b) == encode_field(
                gf_mul(a, b)
            )


def test_gf521_rejects_out_of_range(core):
    modulus = GF_P.to_bytes(66, "big")
    with pytest.raises(ValueError):
        core.gf521_add(modulus, bytes(66))
    with pytest.raises(ValueError):
        core.gf521_mul(bytes(66), modulus)
    with pytest.raises(ValueError):
        core.gf521_inv(bytes(66))


def test_ed25519_is_reported_unsupported(core):
    with pytest.raises(binding.NotSupportedError):
        core.ed25519_public_key(bytes(32))
    with pytest.raises(binding.NotSupportedError):
        core.ed25519_sign(bytes(32), b"message")
    with pytest.raises(binding.NotSupportedError):
        core.ed25519_verify(bytes(32), b"message", bytes(64))


def test_argument_validation_happens_before_the_c_call(core):
    with pytest.raises(ValueError):
        core.aes256_gcm_encrypt(bytes(31), bytes(12), b"data")
    with pytest.raises(ValueError):
        core.aes256_gcm_encrypt(bytes(32), bytes(11), b"data")
    with pytest.raises(ValueError):
        core.chacha20poly1305_decrypt(
            bytes(32), bytes(12), b"data", bytes(15)
        )
    with pytest.raises(ValueError):
        core.x25519(bytes(31), bytes(32))
    with pytest.raises(ValueError):
        core.gf521_add(bytes(65), bytes(66))
    with pytest.raises(ValueError):
        core.hkdf_sha256(b"ikm", b"salt", b"info", -1)


def test_find_library_honours_environment(monkeypatch, core):
    if core.path is None:
        pytest.skip("core has no path")
    monkeypatch.setenv("SECSCI_LIBRARY", str(core.path))
    assert binding.find_library() == core.path
    assert binding.library_available() is True


def test_library_not_found_message(monkeypatch):
    monkeypatch.setenv("SECSCI_LIBRARY", str(os.devnull))
    monkeypatch.setattr(binding, "_candidate_paths", lambda: iter(()))
    with pytest.raises(binding.LibraryNotFound):
        binding.load_library()
