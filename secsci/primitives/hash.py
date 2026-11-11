"""SHA-2 family, HMAC and HKDF, with constants derived from primes.

FIPS 180-4 defines the SHA-2 round constants as the first bits of the
fractional parts of the *cube roots* of the first primes, and the
initial hash values as the first bits of the fractional parts of the
*square roots* of the first primes.  Instead of hard-coding the tables,
we compute them at import time with integer arithmetic only:

    frac_bits(p) = floor(p^(1/k) * 2^b) mod 2^b

which is exact because ``math.isqrt`` / integer k-th roots are exact on
integers.  The resulting tables are checked against the published
FIPS/RFC 6234 tables in ``tests/test_hash.py`` as a self-audit.

HMAC (RFC 2104) and HKDF (RFC 5869) are built on top of these hashes;
the RFC 5869 test vectors are exercised in the same test module.
"""

from __future__ import annotations

from math import isqrt

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF


def _primes(count: int) -> list[int]:
    ps: list[int] = []
    candidate = 2
    while len(ps) < count:
        is_prime = True
        for p in ps:
            if p * p > candidate:
                break
            if candidate % p == 0:
                is_prime = False
                break
        if is_prime:
            ps.append(candidate)
        candidate += 1
    return ps


def _iroot(n: int, k: int) -> int:
    """Floor of the k-th root of a non-negative integer (exact)."""
    if n < 0:
        raise ValueError("negative radicand")
    if n in (0, 1):
        return n
    # Binary search on bit length; n is at most a few thousand bits here.
    lo, hi = 1, 1 << ((n.bit_length() + k - 1) // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid**k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo


def _frac_sqrt(p: int, bits: int) -> int:
    """First ``bits`` bits of the fractional part of sqrt(p)."""
    return isqrt(p << (2 * bits)) & ((1 << bits) - 1)


def _frac_cbrt(p: int, bits: int) -> int:
    """First ``bits`` bits of the fractional part of cbrt(p)."""
    return _iroot(p << (3 * bits), 3) & ((1 << bits) - 1)


_PRIMES_80 = _primes(80)

# FIPS 180-4, section 4.2.2 / 5.3: SHA-256 constants.
K256: tuple[int, ...] = tuple(_frac_cbrt(p, 32) for p in _PRIMES_80[:64])
IV256: tuple[int, ...] = tuple(_frac_sqrt(p, 32) for p in _PRIMES_80[:8])
# SHA-224 uses the second 32 bits of the same fractional square roots.
IV224: tuple[int, ...] = tuple(_frac_sqrt(p, 64) & MASK32 for p in _PRIMES_80[8:16])

# SHA-512 constants.
K512: tuple[int, ...] = tuple(_frac_cbrt(p, 64) for p in _PRIMES_80)
IV512: tuple[int, ...] = tuple(_frac_sqrt(p, 64) for p in _PRIMES_80[:8])
# SHA-384 uses the ninth through sixteenth primes.
IV384: tuple[int, ...] = tuple(_frac_sqrt(p, 64) for p in _PRIMES_80[8:16])


def _rotr(x: int, n: int, width: int) -> int:
    mask = (1 << width) - 1
    return ((x >> n) | (x << (width - n))) & mask


class _Sha2:
    """Generic Merkle-Damgard SHA-2 core (32- or 64-bit words)."""

    word_bits: int
    block_bytes: int
    rounds: int
    state_size: int
    iv: tuple[int, ...]
    k: tuple[int, ...]
    length_bytes: int

    def __init__(self) -> None:
        self._h = list(self.iv)
        self._buf = bytearray()
        self._length = 0  # message length in bytes

    def _compress(self, block: bytes) -> None:
        w = self.word_bits
        mask = (1 << w) - 1
        n = self.block_bytes // (w // 8)
        x = int.from_bytes(block, "big")
        sched = [(x >> (w * (n - 1 - i))) & mask for i in range(n)]
        for i in range(n, self.rounds):
            s0 = _rotr(sched[i - 15], self._r1, w) ^ _rotr(sched[i - 15], self._r2, w) ^ (
                sched[i - 15] >> self._r3
            )
            s1 = _rotr(sched[i - 2], self._r4, w) ^ _rotr(sched[i - 2], self._r5, w) ^ (
                sched[i - 2] >> self._r6
            )
            sched.append((sched[i - 16] + s0 + sched[i - 7] + s1) & mask)
        a, b, c, d, e, f, g, h = self._h
        for i in range(self.rounds):
            s1 = _rotr(e, 14 if w == 64 else 6, w) ^ _rotr(e, 18 if w == 64 else 11, w) ^ _rotr(
                e, 41 if w == 64 else 25, w
            )
            ch = (e & f) ^ ((~e) & g)
            t1 = (h + s1 + ch + self.k[i] + sched[i]) & mask
            s0 = _rotr(a, 28 if w == 64 else 2, w) ^ _rotr(a, 34 if w == 64 else 13, w) ^ _rotr(
                a, 39 if w == 64 else 22, w
            )
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (s0 + maj) & mask
            h, g, f, e, d, c, b, a = g, f, e, (d + t1) & mask, c, b, a, (t1 + t2) & mask
        self._h = [(u + v) & mask for u, v in zip(self._h, (a, b, c, d, e, f, g, h))]

    # Rotation/shift amounts, set per subclass.
    _r1 = _r2 = _r3 = _r4 = _r5 = _r6 = 0

    def update(self, data: bytes | bytearray | memoryview) -> "_Sha2":
        data = bytes(data)
        self._length += len(data)
        self._buf.extend(data)
        bs = self.block_bytes
        while len(self._buf) >= bs:
            self._compress(bytes(self._buf[:bs]))
            del self._buf[:bs]
        return self

    def digest(self) -> bytes:
        bit_len = self._length * 8
        pad_len = (-(self._length + 1 + self.length_bytes)) % self.block_bytes
        tail = b"\x80" + b"\x00" * pad_len + bit_len.to_bytes(self.length_bytes, "big")
        clone = self._copy()
        clone.update(tail)
        w = self.word_bits // 8
        out = b"".join(h.to_bytes(w, "big") for h in clone._h)
        return out[: self.state_size]

    def _copy(self) -> "_Sha2":
        other = object.__new__(type(self))
        other.__dict__.update(self.__dict__)
        other._h = list(self._h)
        other._buf = bytearray(self._buf)
        return other

    def hexdigest(self) -> str:
        return self.digest().hex()


class SHA256(_Sha2):
    word_bits = 32
    block_bytes = 64
    rounds = 64
    state_size = 32
    iv = IV256
    k = K256
    length_bytes = 8
    _r1, _r2, _r3 = 7, 18, 3
    _r4, _r5, _r6 = 17, 19, 10

    def __init__(self) -> None:
        super().__init__()


class SHA224(_Sha2):
    word_bits = 32
    block_bytes = 64
    rounds = 64
    state_size = 28
    iv = IV224
    k = K256
    length_bytes = 8
    _r1, _r2, _r3 = 7, 18, 3
    _r4, _r5, _r6 = 17, 19, 10


class SHA512(_Sha2):
    word_bits = 64
    block_bytes = 128
    rounds = 80
    state_size = 64
    iv = IV512
    k = K512
    length_bytes = 16
    _r1, _r2, _r3 = 1, 8, 7
    _r4, _r5, _r6 = 19, 61, 6


class SHA384(_Sha2):
    word_bits = 64
    block_bytes = 128
    rounds = 80
    state_size = 48
    iv = IV384
    k = K512
    length_bytes = 16
    _r1, _r2, _r3 = 1, 8, 7
    _r4, _r5, _r6 = 19, 61, 6


def sha256(data: bytes) -> bytes:
    return SHA256().update(data).digest()


def sha512(data: bytes) -> bytes:
    return SHA512().update(data).digest()


def sha384(data: bytes) -> bytes:
    return SHA384().update(data).digest()


def sha224(data: bytes) -> bytes:
    return SHA224().update(data).digest()


_HASHES = {
    "sha256": (SHA256, 64),
    "sha384": (SHA384, 128),
    "sha512": (SHA512, 128),
}


def hmac(hash_name: str, key: bytes, message: bytes) -> bytes:
    """RFC 2104 HMAC over one of the SHA-2 functions above."""
    try:
        cls, block_size = _HASHES[hash_name]
    except KeyError as exc:  # pragma: no cover - defensive
        raise ValueError(f"unsupported hash {hash_name!r}") from exc
    if len(key) > block_size:
        key = cls().update(key).digest()
    key = key + b"\x00" * (block_size - len(key))
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    inner = cls().update(ipad).update(message).digest()
    return cls().update(opad).update(inner).digest()


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac("sha256", key, message)


def hmac_sha512(key: bytes, message: bytes) -> bytes:
    return hmac("sha512", key, message)


def hkdf_extract(hash_name: str, salt: bytes | None, ikm: bytes) -> bytes:
    if salt is None:
        salt = b"\x00" * (64 if hash_name.startswith("sha512") else 48 if hash_name == "sha384" else 32)
    return hmac(hash_name, salt, ikm)


def hkdf_expand(hash_name: str, prk: bytes, info: bytes, length: int) -> bytes:
    hash_len = {"sha256": 32, "sha384": 48, "sha512": 64}[hash_name]
    if length > 255 * hash_len:
        raise ValueError("HKDF output too long")
    out = bytearray()
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac(hash_name, prk, block + info + bytes([counter]))
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def hkdf(hash_name: str, ikm: bytes, salt: bytes | None, info: bytes, length: int) -> bytes:
    return hkdf_expand(hash_name, hkdf_extract(hash_name, salt, ikm), info, length)


def hkdf_sha256(ikm: bytes, salt: bytes | None, info: bytes, length: int) -> bytes:
    return hkdf("sha256", ikm, salt, info, length)


def hkdf_sha512(ikm: bytes, salt: bytes | None, info: bytes, length: int) -> bytes:
    return hkdf("sha512", ikm, salt, info, length)
