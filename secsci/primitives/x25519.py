"""X25519 Diffie-Hellman (RFC 7748) over Curve25519.

The Montgomery ladder is written exactly as in RFC 7748 section 5:
the doubling step computes

    x2 = AA * BB
    z2 = E * (AA + 121665 * E)

with A = x2 + z2, AA = A^2, B = x2 - z2, BB = B^2, E = AA - BB.
(The widely-copied variant with ``121666 * E`` belongs to the historical
Curve25519 paper; the RFC-correct constant for this ladder is 121665,
because the RFC defines A24 = (486662 - 2) / 4.)  This is one of the
formula glitches corrected relative to the original specification
prompt and is documented in the README.
"""

from __future__ import annotations

P = 2**255 - 19
A24 = 121665
BITS = 255


def _clamp(k: bytes) -> int:
    if len(k) != 32:
        raise ValueError("X25519 scalar must be 32 bytes")
    n = int.from_bytes(k, "little")
    n &= ~7
    n &= ~(128 << 8 * 31)
    n |= 64 << 8 * 31
    return n


def _decode_u(u: bytes) -> int:
    if len(u) != 32:
        raise ValueError("X25519 u-coordinate must be 32 bytes")
    n = int.from_bytes(u, "little")
    n &= (1 << 255) - 1
    return n % P


def x25519(scalar: bytes, u_coordinate: bytes) -> bytes:
    k = _clamp(scalar)
    x1 = _decode_u(u_coordinate)
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    for t in range(BITS - 1, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t

        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) % P
        x3 = x3 * x3 % P
        z3 = (da - cb) % P
        z3 = x1 * (z3 * z3 % P) % P
        x2 = aa * bb % P
        z2 = e * ((aa + A24 * e) % P) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    result = x2 * pow(z2, P - 2, P) % P
    return result.to_bytes(32, "little")


def x25519_base(scalar: bytes) -> bytes:
    return x25519(scalar, (9).to_bytes(32, "little"))


# RFC 7748 section 6.1 test values.
ALICE_PRIVATE = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
)
ALICE_PUBLIC = bytes.fromhex(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
)
BOB_PRIVATE = bytes.fromhex(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
)
BOB_PUBLIC = bytes.fromhex(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
)
SHARED = bytes.fromhex(
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
)
