"""C7 tests: padding buckets, AEAD envelopes, tamper resistance."""

import pytest

from secsci.components.c7_envelope import (
    Envelope,
    EnvelopeError,
    open_envelope,
    pad,
    padded_size,
    seal,
    unpad,
)

KEY = bytes(range(32))


def test_padded_sizes_are_powers_of_two():
    assert padded_size(0) == 256
    assert padded_size(1) == 256
    assert padded_size(248) == 256  # 248 + 8 == 256
    assert padded_size(249) == 512
    assert padded_size(504) == 512
    assert padded_size(505) == 1024
    for n in (0, 1, 100, 247, 248, 249, 1000, 4096):
        size = padded_size(n)
        assert size >= n + 8
        assert size & (size - 1) == 0


def test_pad_unpad_roundtrip_and_zero_fill():
    for n in (0, 1, 7, 100, 248, 249, 1000):
        data = bytes(range(256)) * (n // 256) + bytes(range(n % 256))
        assert len(data) == n
        padded = pad(data)
        assert len(padded) == padded_size(n)
        assert unpad(padded) == data
        assert padded[8 + n :] == b"\x00" * (len(padded) - 8 - n)


def test_unpad_rejects_malformed():
    with pytest.raises(EnvelopeError):
        unpad(b"\x00" * 100)
    with pytest.raises(EnvelopeError):
        unpad(b"\xff" * 8 + b"\x00" * 248)
    bad = bytearray(pad(b"data"))
    bad[-1] = 1
    with pytest.raises(EnvelopeError):
        unpad(bytes(bad))


def test_envelope_roundtrip_both_suites():
    for suite in ("aes-gcm", "chacha20-poly1305"):
        env = seal(KEY, b"secret text", suite=suite, aad=b"context")
        assert env.ciphertext
        parsed = Envelope.from_bytes(env.to_bytes())
        assert parsed == env
        assert open_envelope(KEY, env, aad=b"context") == b"secret text"
        assert open_envelope(KEY, parsed, aad=b"context") == b"secret text"


def test_ciphertext_length_hides_plaintext_length():
    a = seal(KEY, b"x" * 10, nonce=b"n" * 12)
    b = seal(KEY, b"x" * 200, nonce=b"n" * 12)
    assert len(a.ciphertext) == len(b.ciphertext) == 256
    c = seal(KEY, b"x" * 240, nonce=b"n" * 12)
    assert len(c.ciphertext) == 256


def test_wrong_aad_or_key_fails():
    env = seal(KEY, b"payload", aad=b"right")
    with pytest.raises(EnvelopeError):
        open_envelope(KEY, env, aad=b"wrong")
    with pytest.raises(EnvelopeError):
        open_envelope(b"k" * 32, env, aad=b"right")


def test_tampering_fails_uniformly():
    env = seal(KEY, b"tamper me", aad=b"ad")
    raw = bytearray(env.to_bytes())
    # Flip a byte in the nonce, ciphertext and tag regions.
    for pos in (6, 20, len(raw) - 1):
        bad = bytearray(raw)
        bad[pos] ^= 0x40
        with pytest.raises(EnvelopeError) as exc:
            open_envelope(KEY, bytes(bad), aad=b"ad")
        assert "authentication" in str(exc.value) or "padding" in str(exc.value)


def test_truncated_and_bad_magic_rejected():
    env = seal(KEY, b"x")
    raw = env.to_bytes()
    with pytest.raises(EnvelopeError):
        Envelope.from_bytes(raw[:20])
    with pytest.raises(EnvelopeError):
        Envelope.from_bytes(b"XXXX" + raw[4:])
    with pytest.raises(EnvelopeError):
        Envelope.from_bytes(raw[:4] + b"\x7f" + raw[5:])


def test_nonce_validation_and_unknown_suite():
    with pytest.raises(ValueError):
        seal(KEY, b"x", nonce=b"short")
    with pytest.raises(ValueError):
        seal(KEY, b"x", suite="rot13")
    with pytest.raises(EnvelopeError):
        pad(b"x" * (1 << 24))
