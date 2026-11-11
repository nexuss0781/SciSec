"""AES-GCM (NIST SP 800-38D) with a from-scratch GHASH.

GHASH multiplies in GF(2^128) modulo x^128 + x^7 + x^2 + x + 1 using the
bit-serial algorithm: each step shifts right, reducing with
R = 0xE1000...0 when the shifted-out bit was 1.

The AES block cipher itself lives in :mod:`secsci.primitives.aes`.
"""

from __future__ import annotations

from .aes import AES

_BLOCK = 16
_R = 0xE1 << 120


def _gf128_mul(x: int, y: int) -> int:
    """Multiplication in GF(2^128) with the GCM reduction polynomial."""
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


def _ghash(h: int, data: bytes) -> int:
    if len(data) % _BLOCK:
        raise ValueError("GHASH input must be a multiple of 16 bytes")
    y = 0
    for i in range(0, len(data), _BLOCK):
        y = _gf128_mul(y ^ int.from_bytes(data[i : i + _BLOCK], "big"), h)
    return y


def _pad16(data: bytes) -> bytes:
    if len(data) % _BLOCK == 0:
        return data
    return data + b"\x00" * (_BLOCK - len(data) % _BLOCK)


def _inc32(block: bytes) -> bytes:
    return block[:12] + ((int.from_bytes(block[12:], "big") + 1) & 0xFFFFFFFF).to_bytes(4, "big")


def _gctr(aes: AES, initial_counter: bytes, data: bytes) -> bytes:
    out = bytearray()
    counter = initial_counter
    for i in range(0, len(data), _BLOCK):
        keystream = aes.encrypt_block(counter)
        chunk = data[i : i + _BLOCK]
        out.extend(x ^ y for x, y in zip(chunk, keystream))
        counter = _inc32(counter)
    return bytes(out)


def _gcm_tag(h: int, j0: bytes, aad: bytes, ciphertext: bytes, aes: AES) -> bytes:
    lengths = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    s = _ghash(h, _pad16(aad) + _pad16(ciphertext) + lengths)
    mask = int.from_bytes(aes.encrypt_block(j0), "big")
    return (s ^ mask).to_bytes(16, "big")


def _j0(h: int, iv: bytes) -> bytes:
    if len(iv) == 12:
        return iv + b"\x00\x00\x00\x01"
    if not iv:
        raise ValueError("GCM IV must not be empty")
    return _ghash(h, _pad16(iv) + b"\x00" * 8 + (len(iv) * 8).to_bytes(8, "big")).to_bytes(
        16, "big"
    )


def gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    aes = AES(key)
    h = int.from_bytes(aes.encrypt_block(b"\x00" * 16), "big")
    j0 = _j0(h, iv)
    ciphertext = _gctr(aes, _inc32(j0), plaintext)
    tag = _gcm_tag(h, j0, aad, ciphertext, aes)
    return ciphertext, tag


def gcm_decrypt(
    key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b""
) -> bytes:
    if len(tag) != 16:
        raise ValueError("GCM tag must be 16 bytes")
    aes = AES(key)
    h = int.from_bytes(aes.encrypt_block(b"\x00" * 16), "big")
    j0 = _j0(h, iv)
    expected = _gcm_tag(h, j0, aad, ciphertext, aes)
    diff = 0
    for x, y in zip(expected, tag):
        diff |= x ^ y
    if diff:
        raise ValueError("GCM authentication failed")
    return _gctr(aes, _inc32(j0), ciphertext)
