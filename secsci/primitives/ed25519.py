"""Ed25519 signatures (RFC 8032), from scratch.

Points live on the twisted Edwards curve

    -x^2 + y^2 = 1 + d x^2 y^2,   d = -121665 / 121666 mod p

and are represented in extended twisted Edwards coordinates
(X : Y : Z : T) with x = X/Z, y = Y/Z, T = XY/Z.  The addition and
doubling formulas are the complete Hisil-Wong-Carter-Dawson formulas
for a = -1, so the identity and arbitrary points need no special cases.

The base point is *derived*, not hard-coded: y = 4/5, x = the even
square root of (y^2 - 1)/(d y^2 + 1).
"""

from __future__ import annotations

from .hash import sha512

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENTITY = (0, 1, 1, 0)


def _inv(x: int) -> int:
    return pow(x % P, P - 2, P)


def _add(p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D % P * t2 % P
    d = z1 * 2 * z2 % P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _double(p: tuple[int, int, int, int]):
    x1, y1, z1, _ = p
    a = x1 * x1 % P
    b = y1 * y1 % P
    c = 2 * z1 * z1 % P
    d = -a % P
    e = ((x1 + y1) * (x1 + y1) - a - b) % P
    g = (d + b) % P
    f = (g - c) % P
    h = (d - b) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _neg(p: tuple[int, int, int, int]):
    x, y, z, t = p
    return ((-x) % P, y, z, (-t) % P)


def scalar_mult(k: int, point: tuple[int, int, int, int]):
    result = IDENTITY
    addend = point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _double(addend)
        k >>= 1
    return result


def _encode(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    zi = _inv(z)
    x = x * zi % P
    y = y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(data: bytes):
    if len(data) != 32:
        raise ValueError("Ed25519 point encoding must be 32 bytes")
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        raise ValueError("non-canonical Ed25519 point")
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    # p = 5 (mod 8): x = u v^3 (u v^7)^((p-5)/8), then correct.
    x = u * pow(v, 3, P) % P * pow(u * pow(v, 7, P) % P, (P - 5) // 8, P) % P
    if v * x * x % P != u:
        if v * x * x % P != (-u) % P:
            raise ValueError("point is not on the curve")
        x = x * SQRT_M1 % P
    if x == 0 and sign:
        raise ValueError("invalid sign bit for x = 0")
    if (x & 1) != sign:
        x = P - x
    return (x, y, 1, x * y % P)


def _base_point():
    y = 4 * _inv(5) % P
    return _decode(y.to_bytes(32, "little"))


BASE = _base_point()


def _clamp_scalar(h: bytes) -> int:
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


def public_key(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    a = _clamp_scalar(sha512(seed))
    return _encode(scalar_mult(a, BASE))


def sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = sha512(seed)
    a = _clamp_scalar(h)
    prefix = h[32:]
    a_pub = _encode(scalar_mult(a, BASE))
    r = int.from_bytes(sha512(prefix + message), "little") % L
    r_enc = _encode(scalar_mult(r, BASE))
    k = int.from_bytes(sha512(r_enc + a_pub + message), "little") % L
    s = (r + k * a) % L
    return r_enc + s.to_bytes(32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    try:
        a_point = _decode(public)
        r_point = _decode(signature[:32])
    except ValueError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(sha512(signature[:32] + public + message), "little") % L
    left = scalar_mult(s, BASE)
    right = _add(r_point, scalar_mult(k, a_point))
    return _encode(left) == _encode(right)


# ---------------------------------------------------------------------------
# Conversion helpers for X3DH: Ed25519 identity keys -> X25519 DH keys.
# ---------------------------------------------------------------------------

def to_montgomery(public: bytes) -> bytes:
    """Map an Ed25519 point to its X25519 u-coordinate.

    u = (1 + y) / (1 - y) is the birational map between the twisted
    Edwards curve and Curve25519 (RFC 7748 section 4.1).
    """
    point = _decode(public)
    y = point[1] * _inv(point[2]) % P
    u = (1 + y) * _inv(1 - y) % P
    return u.to_bytes(32, "little")


def seed_to_x25519_private(seed: bytes) -> bytes:
    """X25519 private key corresponding to an Ed25519 identity seed."""
    return sha512(seed)[:32]


# RFC 8032 section 7.1 test vectors.
VECTORS = [
    {
        "seed": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "public": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "message": "",
        "signature": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    {
        "seed": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "public": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "message": "72",
        "signature": "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                     "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    {
        "seed": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "public": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "message": "af82",
        "signature": "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                     "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
]
