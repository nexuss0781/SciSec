"""ChaCha20 stream cipher (RFC 8439)."""

from __future__ import annotations

import struct

MASK32 = 0xFFFFFFFF
CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)  # "expand 32-byte k"


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & MASK32


def _qr(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & MASK32
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK32
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK32
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK32
    s[b] = _rotl(s[b] ^ s[c], 7)


def block(key: bytes, counter: int, nonce: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes")
    if not 0 <= counter <= MASK32:
        raise ValueError("ChaCha20 counter must fit in 32 bits")
    state = list(CONSTANTS) + list(struct.unpack("<8I", key)) + [counter] + list(
        struct.unpack("<3I", nonce)
    )
    working = list(state)
    for _ in range(10):
        _qr(working, 0, 4, 8, 12)
        _qr(working, 1, 5, 9, 13)
        _qr(working, 2, 6, 10, 14)
        _qr(working, 3, 7, 11, 15)
        _qr(working, 0, 5, 10, 15)
        _qr(working, 1, 6, 11, 12)
        _qr(working, 2, 7, 8, 13)
        _qr(working, 3, 4, 9, 14)
    return struct.pack("<16I", *[(a + b) & MASK32 for a, b in zip(working, state)])


def chacha20(key: bytes, nonce: bytes, data: bytes, counter: int = 0) -> bytes:
    """Encrypt/decrypt ``data`` with the ChaCha20 keystream."""
    out = bytearray()
    for offset in range(0, len(data), 64):
        stream = block(key, (counter + offset // 64) & MASK32, nonce)
        chunk = data[offset : offset + 64]
        out.extend(x ^ y for x, y in zip(chunk, stream))
    return bytes(out)
