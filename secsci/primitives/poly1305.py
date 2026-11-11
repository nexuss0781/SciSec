"""Poly1305 one-time authenticator (RFC 8439 section 2.5)."""

from __future__ import annotations

P = (1 << 130) - 5


def poly1305(key: bytes, message: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")
    r = int.from_bytes(key[:16], "little")
    # Clamp per RFC 8439.
    r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    acc = 0
    for i in range(0, len(message), 16):
        chunk = message[i : i + 16]
        n = int.from_bytes(chunk + b"\x01", "little")
        acc = ((acc + n) * r) % P
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")
