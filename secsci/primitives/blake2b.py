"""BLAKE2b (RFC 7693), from scratch.

The IV is the SHA-512 IV, i.e. the first 64 bits of the fractional
parts of the square roots of the first eight primes (see
``secsci.primitives.hash``).  The SIGMA permutation is a table defined
by RFC 7693; it is not derivable from a closed formula and is included
verbatim.  The compression function uses the standard BLAKE2b G
function with 64-bit words and 12 rounds (SIGMA repeats every 10).
"""

from __future__ import annotations

import struct

from .hash import IV512

MASK64 = 0xFFFFFFFFFFFFFFFF
BLOCK_BYTES = 128

SIGMA: tuple[tuple[int, ...], ...] = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
)


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & MASK64


def _g(v: list[int], a: int, b: int, c: int, d: int, x: int, y: int) -> None:
    v[a] = (v[a] + v[b] + x) & MASK64
    v[d] = _rotr(v[d] ^ v[a], 32)
    v[c] = (v[c] + v[d]) & MASK64
    v[b] = _rotr(v[b] ^ v[c], 24)
    v[a] = (v[a] + v[b] + y) & MASK64
    v[d] = _rotr(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & MASK64
    v[b] = _rotr(v[b] ^ v[c], 63)


def _compress(h: list[int], block: bytes, t: int, last: bool) -> None:
    m = struct.unpack("<16Q", block)
    v = list(h) + list(IV512)
    v[12] ^= t & MASK64
    v[13] ^= (t >> 64) & MASK64
    if last:
        v[14] ^= MASK64
    for r in range(12):
        s = SIGMA[r % 10]
        _g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
        _g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
        _g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
        _g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
        _g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
        _g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
        _g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
        _g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
    for i in range(8):
        h[i] ^= v[i] ^ v[i + 8]


class BLAKE2b:
    """Incremental BLAKE2b with optional key (MAC) and variable digest."""

    def __init__(self, digest_size: int = 64, key: bytes = b"") -> None:
        if not 1 <= digest_size <= 64:
            raise ValueError("digest_size must be in 1..64")
        if len(key) > 64:
            raise ValueError("key must be at most 64 bytes")
        self.outlen = digest_size
        self._h = list(IV512)
        # Parameter block: digest length, key length, fanout=1, depth=1.
        self._h[0] ^= 0x01010000 ^ (len(key) << 8) ^ digest_size
        self._t = 0
        self._buf = bytearray()
        self._finalized = False
        if key:
            self._buf.extend(key + b"\x00" * (BLOCK_BYTES - len(key)))

    def update(self, data: bytes | bytearray | memoryview) -> "BLAKE2b":
        if self._finalized:
            raise ValueError("BLAKE2b already finalized")
        data = bytes(data)
        if not data:
            return self
        # A pending full block (possibly the padded key block) is only
        # compressed once more input is known to exist.
        if len(self._buf) == BLOCK_BYTES:
            _compress(self._h, bytes(self._buf), self._t + BLOCK_BYTES, False)
            self._t += BLOCK_BYTES
            self._buf.clear()
        while len(data) > BLOCK_BYTES - len(self._buf):
            take = BLOCK_BYTES - len(self._buf)
            self._buf.extend(data[:take])
            data = data[take:]
            _compress(self._h, bytes(self._buf), self._t + BLOCK_BYTES, False)
            self._t += BLOCK_BYTES
            self._buf.clear()
        self._buf.extend(data)
        return self

    def digest(self) -> bytes:
        t = self._t + len(self._buf)
        block = bytes(self._buf).ljust(BLOCK_BYTES, b"\x00")
        h = list(self._h)
        _compress(h, block, t, True)
        return b"".join(word.to_bytes(8, "little") for word in h)[: self.outlen]

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> "BLAKE2b":
        other = object.__new__(BLAKE2b)
        other.__dict__.update(self.__dict__)
        other._h = list(self._h)
        other._buf = bytearray(self._buf)
        return other


def blake2b(
    data: bytes,
    digest_size: int = 64,
    key: bytes = b"",
) -> bytes:
    return BLAKE2b(digest_size, key).update(data).digest()
