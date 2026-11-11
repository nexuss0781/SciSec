"""C1 -- HMAC-DRBG CSPRNG (NIST SP 800-90A).

Pure-Python HMAC-DRBG instantiated with SHA-256.  The only entropy
source ever consulted is ``os.urandom`` at seeding/reseed time; all
random values handed to the rest of Sec-Sci come from this DRBG.

NIST CAVP KATs (no-reseed, SHA-256) are exercised in
``tests/test_c1_drbg.py``.
"""

from __future__ import annotations

import os
import threading

from ..primitives.hash import hmac_sha256

RESEED_INTERVAL = 2**48
_HASH_LEN = 32


class HMACDRBG:
    """SP 800-90A HMAC_DRBG with SHA-256.

    ``entropy`` must be at least 32 bytes and ``nonce`` at least 16
    bytes, matching a 256-bit security strength.
    """

    def __init__(
        self,
        entropy: bytes,
        nonce: bytes,
        personalization: bytes = b"",
        seed_material: bytes | None = None,
    ) -> None:
        if seed_material is None:
            if len(entropy) < 32:
                raise ValueError("HMAC-DRBG entropy must be >= 32 bytes")
            if len(nonce) < 16:
                raise ValueError("HMAC-DRBG nonce must be >= 16 bytes")
            seed_material = entropy + nonce + personalization
        self._k = b"\x00" * _HASH_LEN
        self._v = b"\x01" * _HASH_LEN
        self._update(seed_material)
        self.reseed_counter = 1

    def _update(self, provided_data: bytes = b"") -> None:
        self._k = hmac_sha256(self._k, self._v + b"\x00" + provided_data)
        self._v = hmac_sha256(self._k, self._v)
        if provided_data:
            self._k = hmac_sha256(self._k, self._v + b"\x01" + provided_data)
            self._v = hmac_sha256(self._k, self._v)

    def reseed(self, entropy: bytes, additional_input: bytes = b"") -> None:
        if len(entropy) < 32:
            raise ValueError("HMAC-DRBG entropy must be >= 32 bytes")
        self._update(entropy + additional_input)
        self.reseed_counter = 1

    def generate(self, num_bytes: int, additional_input: bytes = b"") -> bytes:
        if num_bytes < 0:
            raise ValueError("num_bytes must be non-negative")
        if self.reseed_counter > RESEED_INTERVAL:
            raise RuntimeError("HMAC-DRBG requires a reseed")
        if additional_input:
            self._update(additional_input)
        out = bytearray()
        while len(out) < num_bytes:
            self._v = hmac_sha256(self._k, self._v)
            out.extend(self._v)
        # SP 800-90A step 6: the state update is performed even when the
        # additional input is empty.
        self._update(additional_input)
        self.reseed_counter += 1
        return bytes(out[:num_bytes])

    def random_below(self, bound: int) -> int:
        """Uniform integer in [0, bound) with rejection sampling."""
        if bound <= 0:
            raise ValueError("bound must be positive")
        if bound == 1:
            return 0
        bits = (bound - 1).bit_length()
        nbytes = (bits + 7) // 8
        mask = (1 << bits) - 1
        while True:
            candidate = int.from_bytes(self.generate(nbytes), "big") & mask
            if candidate < bound:
                return candidate

    def random_bytes(self, n: int) -> bytes:
        return self.generate(n)


_GLOBAL_LOCK = threading.RLock()
_GLOBAL_DRBG: HMACDRBG | None = None


def _system_drbg(personalization: bytes = b"SecSci-C1-v1") -> HMACDRBG:
    global _GLOBAL_DRBG
    with _GLOBAL_LOCK:
        if _GLOBAL_DRBG is None:
            _GLOBAL_DRBG = HMACDRBG(
                os.urandom(32), os.urandom(16), personalization
            )
        return _GLOBAL_DRBG


def random_bytes(n: int) -> bytes:
    """Cryptographically strong random bytes from the global DRBG."""
    with _GLOBAL_LOCK:
        return _system_drbg().generate(n)


def random_below(bound: int) -> int:
    with _GLOBAL_LOCK:
        return _system_drbg().random_below(bound)


def random_int(bits: int) -> int:
    if bits <= 0:
        return 0
    return int.from_bytes(random_bytes((bits + 7) // 8), "big") & ((1 << bits) - 1)
