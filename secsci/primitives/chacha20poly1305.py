"""AEAD_CHACHA20_POLY1305 (RFC 8439 section 2.8)."""

from __future__ import annotations

from .chacha20 import chacha20, block
from .poly1305 import poly1305


def _pad16(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 16)


def _mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    return (
        _pad16(aad)
        + _pad16(ciphertext)
        + len(aad).to_bytes(8, "little")
        + len(ciphertext).to_bytes(8, "little")
    )


def chacha20poly1305_encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b""
) -> tuple[bytes, bytes]:
    if len(nonce) != 12:
        raise ValueError("ChaCha20-Poly1305 nonce must be 12 bytes")
    otk = block(key, 0, nonce)[:32]
    ciphertext = chacha20(key, nonce, plaintext, counter=1)
    tag = poly1305(otk, _mac_data(aad, ciphertext))
    return ciphertext, tag


def chacha20poly1305_decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b""
) -> bytes:
    if len(tag) != 16:
        raise ValueError("ChaCha20-Poly1305 tag must be 16 bytes")
    otk = block(key, 0, nonce)[:32]
    expected = poly1305(otk, _mac_data(aad, ciphertext))
    diff = 0
    for x, y in zip(expected, tag):
        diff |= x ^ y
    if diff:
        raise ValueError("ChaCha20-Poly1305 authentication failed")
    return chacha20(key, nonce, ciphertext, counter=1)
