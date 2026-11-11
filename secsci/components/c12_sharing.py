"""C12 -- Shamir secret sharing and an OPRF/SVR password variant.

Everything in this module lives in the prime field GF(p) with

    p = 2**521 - 1

the fifth Mersenne prime.  The field is represented with Python integers;
addition and multiplication use the Mersenne reduction

    x mod p = (x & p) + (x >> 521)   (repeated, then a final conditional
                                      subtraction)

which is exact for the operand ranges used here.  Inversion is Fermat's
little theorem, ``a**(p-2) mod p``.  A field element is serialised as 66
big-endian bytes; secret chunks are 65 bytes so every chunk is already a
canonical field element (``< 2**520 < p``).

Shamir secret sharing
---------------------
``split_secret`` splits a byte string into ``n`` shares with threshold
``k``.  The secret is cut into 65-byte chunks; each chunk is the constant
term of a random degree ``k-1`` polynomial over GF(p), and share ``i`` is
the tuple of polynomial evaluations at ``x = i`` (``1 <= i <= 65535``).
``combine_shares`` uses Lagrange interpolation at ``x = 0``.  Shares
carry a random 8-byte set identifier, the threshold, the original secret
length and the number of chunks, so shares from different splits cannot
be mixed silently.  The wire format is::

    "SHR1" | set_id(8) | threshold(1) | index(2) | secret_len(4) |
    chunk_count(2) | y_0(66) | ... | y_{count-1}(66)

Shares are *not* authenticated: an attacker who can modify a share can
change the recovered secret.  Distribute shares over an authenticated
channel, or wrap them in the C7 padded AEAD envelope.

OPRF / SVR
----------
The OPRF is the classic blinded-exponentiation construction in the
multiplicative group GF(p)*:

    client: h = HashToGroup(password, context);  y = h**r mod p
    server: z = y**k mod p
    client: w = z**(r**-1 mod p-1) = h**k

The client output is ``SHA-256("SecSci-C12-OPRF-output" || w)``.  A
*secret validation record* (SVR) is derived from that output with HKDF
and stored by the server; authentication succeeds when the SVRs match.

**Caveat.**  GF(p)* has order ``p-1 = 2 * (2**520 - 1)``, which is not
prime, so this group is not a prime-order group and does not provide the
security guarantees of a production OPRF (ristretto255/decaf or a
hash-to-curve group).  ``HashToGroup`` squares the hash output, which
lands in the odd-order subgroup of quadratic residues and excludes -1,
and blinding exponents are chosen coprime to ``p-1`` so that unblinding
is well defined.  This is a mathematically self-contained reference
implementation consistent with the rest of Sec-Sci, not a drop-in
replacement for an audited OPRF.
"""

from __future__ import annotations

from dataclasses import dataclass
from hmac import compare_digest
from math import gcd
from typing import Callable, Iterable, Sequence

from ..primitives.hash import hkdf_sha256, sha256, sha512
from .c1_drbg import random_bytes

P = (1 << 521) - 1
FIELD_BITS = 521
FIELD_BYTES = 66
CHUNK_BYTES = 65

SHARE_MAGIC = b"SHR1"
SET_ID_LEN = 8
MAX_SHARES = 0xFFFF
MAX_THRESHOLD = 0xFF

OPRF_LABEL = b"SecSci-C12-OPRF-v1"
OPRF_OUTPUT_LABEL = b"SecSci-C12-OPRF-output"
SVR_LABEL = b"SecSci-C12-SVR-v1"
SVR_SALT = b"SecSci-C12-SVR-salt"

Rng = Callable[[int], bytes]


class SharingError(ValueError):
    """Malformed share, inconsistent set, or bad sharing parameter."""


class OPRFError(ValueError):
    """Malformed OPRF input or invalid server key."""


# ---------------------------------------------------------------------------
# GF(2**521 - 1) arithmetic
# ---------------------------------------------------------------------------


def _check_field(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("field elements must be integers")
    if not 0 <= value < P:
        raise ValueError("field element out of range")
    return value


def reduce(value: int) -> int:
    """Reduce an integer modulo p using Mersenne folding."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("field elements must be integers")
    if value < 0:
        value %= P
    value = (value & P) + (value >> FIELD_BITS)
    value = (value & P) + (value >> FIELD_BITS)
    if value >= P:
        value -= P
    return value


def add(a: int, b: int) -> int:
    return reduce(_check_field(a) + _check_field(b))


def sub(a: int, b: int) -> int:
    return reduce(_check_field(a) + (P - _check_field(b)))


def neg(a: int) -> int:
    a = _check_field(a)
    return 0 if a == 0 else P - a


def mul(a: int, b: int) -> int:
    return reduce(_check_field(a) * _check_field(b))


def inv(a: int) -> int:
    a = _check_field(a)
    if a == 0:
        raise ZeroDivisionError("zero has no inverse in GF(2**521 - 1)")
    return pow(a, P - 2, P)


def div(a: int, b: int) -> int:
    return mul(a, inv(b))


def encode_field(value: int) -> bytes:
    return _check_field(value).to_bytes(FIELD_BYTES, "big")


def decode_field(data: bytes) -> int:
    if len(data) != FIELD_BYTES:
        raise ValueError(f"field element must be {FIELD_BYTES} bytes")
    value = int.from_bytes(data, "big")
    if value >= P:
        raise ValueError("field element out of range")
    return value


def random_scalar(rng: Rng = random_bytes) -> int:
    """A uniformly random field element.

    Draw 66 bytes, keep the low 521 bits (uniform on ``[0, 2**521)``) and
    reject the single value equal to p.  The rejection probability is
    ``2**-521``.
    """
    mask = (1 << FIELD_BITS) - 1
    while True:
        candidate = int.from_bytes(rng(FIELD_BYTES), "big") & mask
        if candidate < P:
            return candidate


def _random_nonzero(rng: Rng) -> int:
    while True:
        value = random_scalar(rng)
        if value:
            return value


def _random_unit(rng: Rng) -> int:
    """A random exponent coprime to p-1, for blinding and server keys."""
    while True:
        value = random_scalar(rng)
        if value >= 2 and value & 1 and gcd(value, P - 1) == 1:
            return value


def _evaluate_polynomial(coefficients: Sequence[int], x: int) -> int:
    """Horner evaluation in GF(p)."""
    result = 0
    for coefficient in reversed(coefficients):
        result = add(mul(result, x), coefficient)
    return result


# ---------------------------------------------------------------------------
# Shamir secret sharing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Share:
    """One share of a split secret (one field element per 65-byte chunk)."""

    set_id: bytes
    index: int
    threshold: int
    secret_len: int
    values: tuple[int, ...]

    def __post_init__(self) -> None:
        if len(self.set_id) != SET_ID_LEN:
            raise SharingError(f"set id must be {SET_ID_LEN} bytes")
        if not 1 <= self.index <= MAX_SHARES:
            raise SharingError("share index must be in 1..65535")
        if not 1 <= self.threshold <= MAX_THRESHOLD:
            raise SharingError("threshold must be in 1..255")
        if self.secret_len < 1:
            raise SharingError("secret length must be positive")
        expected = (self.secret_len + CHUNK_BYTES - 1) // CHUNK_BYTES
        if len(self.values) != expected:
            raise SharingError("share does not carry the expected number of chunks")
        for value in self.values:
            _check_field(value)

    @property
    def chunk_count(self) -> int:
        return len(self.values)

    def to_bytes(self) -> bytes:
        return (
            SHARE_MAGIC
            + self.set_id
            + bytes([self.threshold])
            + self.index.to_bytes(2, "big")
            + self.secret_len.to_bytes(4, "big")
            + len(self.values).to_bytes(2, "big")
            + b"".join(encode_field(value) for value in self.values)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "Share":
        header = len(SHARE_MAGIC) + SET_ID_LEN + 1 + 2 + 4 + 2
        if len(data) < header:
            raise SharingError("truncated share")
        if data[: len(SHARE_MAGIC)] != SHARE_MAGIC:
            raise SharingError("bad share magic")
        pos = len(SHARE_MAGIC)
        set_id = data[pos : pos + SET_ID_LEN]
        pos += SET_ID_LEN
        threshold = data[pos]
        pos += 1
        index = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2
        secret_len = int.from_bytes(data[pos : pos + 4], "big")
        pos += 4
        count = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2
        if count == 0:
            raise SharingError("share carries no chunks")
        if len(data) != pos + count * FIELD_BYTES:
            raise SharingError("invalid share length")
        try:
            values = tuple(
                decode_field(
                    data[pos + i * FIELD_BYTES : pos + (i + 1) * FIELD_BYTES]
                )
                for i in range(count)
            )
            return cls(set_id, index, threshold, secret_len, values)
        except SharingError:
            raise
        except (TypeError, ValueError) as exc:
            raise SharingError(str(exc)) from None


def split_secret(
    secret: bytes,
    threshold: int,
    shares: int,
    *,
    set_id: bytes | None = None,
    rng: Rng = random_bytes,
) -> list[Share]:
    """Split ``secret`` into ``shares`` shares with the given threshold."""
    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError("secret must be bytes")
    secret = bytes(secret)
    if not secret:
        raise SharingError("secret must not be empty")
    if not isinstance(threshold, int) or isinstance(threshold, bool):
        raise SharingError("threshold must be an integer")
    if not 1 <= threshold <= MAX_THRESHOLD:
        raise SharingError("threshold must be in 1..255")
    if not isinstance(shares, int) or isinstance(shares, bool):
        raise SharingError("share count must be an integer")
    if not threshold <= shares <= MAX_SHARES:
        raise SharingError("share count must be between threshold and 65535")
    if set_id is None:
        set_id = random_bytes(SET_ID_LEN)
    if len(set_id) != SET_ID_LEN:
        raise SharingError(f"set id must be {SET_ID_LEN} bytes")

    chunks = [
        int.from_bytes(secret[offset : offset + CHUNK_BYTES], "big")
        for offset in range(0, len(secret), CHUNK_BYTES)
    ]
    # One random polynomial per chunk, evaluated at every share index.
    polynomials: list[list[int]] = []
    for chunk in chunks:
        coefficients = [chunk]
        for _ in range(threshold - 1):
            coefficients.append(random_scalar(rng))
        if threshold > 1:
            # The leading coefficient must be nonzero, otherwise the
            # polynomial has degree < threshold-1 and the effective
            # threshold is lower than requested.
            while coefficients[-1] == 0:
                coefficients[-1] = random_scalar(rng)
        polynomials.append(coefficients)

    result: list[Share] = []
    for index in range(1, shares + 1):
        values = tuple(
            _evaluate_polynomial(coefficients, index)
            for coefficients in polynomials
        )
        result.append(
            Share(set_id, index, threshold, len(secret), values)
        )
    return result


def _check_share_set(shares: Sequence[Share]) -> None:
    if not shares:
        raise SharingError("at least one share is required")
    for share in shares:
        if not isinstance(share, Share):
            raise TypeError("shares must be Share instances")
    first = shares[0]
    seen: set[int] = set()
    for share in shares:
        if share.set_id != first.set_id:
            raise SharingError("shares come from different splits")
        if share.threshold != first.threshold:
            raise SharingError("shares have different thresholds")
        if share.secret_len != first.secret_len:
            raise SharingError("shares have different secret lengths")
        if share.chunk_count != first.chunk_count:
            raise SharingError("shares have different chunk counts")
        if share.index in seen:
            raise SharingError("duplicate share index")
        seen.add(share.index)
    if len(shares) < first.threshold:
        raise SharingError(
            f"at least {first.threshold} shares are required, got {len(shares)}"
        )


def combine_shares(shares: Iterable[Share]) -> bytes:
    """Recover the secret from at least ``threshold`` shares."""
    shares = list(shares)
    _check_share_set(shares)
    first = shares[0]
    xs = [share.index for share in shares]

    # Lagrange basis at x = 0: L_i = prod_{m != i} x_m / (x_m - x_i).
    lagrange: list[int] = []
    for i, xi in enumerate(xs):
        numerator = 1
        denominator = 1
        for m, xm in enumerate(xs):
            if m == i:
                continue
            numerator = mul(numerator, xm)
            denominator = mul(denominator, sub(xm, xi))
        lagrange.append(mul(numerator, inv(denominator)))

    chunks = []
    for chunk in range(first.chunk_count):
        value = 0
        for share, weight in zip(shares, lagrange):
            value = add(value, mul(share.values[chunk], weight))
        chunks.append(value.to_bytes(CHUNK_BYTES, "big"))
    # The final chunk only carries ``secret_len mod 65`` significant bytes;
    # big-endian encoding right-aligns the value, so keep its low bytes.
    last_len = first.secret_len - CHUNK_BYTES * (first.chunk_count - 1)
    chunks[-1] = chunks[-1][-last_len:]
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# OPRF and SVR
# ---------------------------------------------------------------------------


def _context_bytes(context: bytes | bytearray) -> bytes:
    if not isinstance(context, (bytes, bytearray)):
        raise TypeError("context must be bytes")
    if len(context) > 0xFFFF:
        raise OPRFError("context must be at most 65535 bytes")
    return bytes(context)


def hash_to_group(password: bytes, context: bytes = b"") -> int:
    """Map a password to a quadratic residue in GF(p)*.

    ``SHA-512`` output is at most 512 bits, so it is already a canonical
    field element; squaring moves it into the odd-order subgroup of
    quadratic residues.
    """
    if not isinstance(password, (bytes, bytearray)):
        raise TypeError("password must be bytes")
    context = _context_bytes(context)
    password = bytes(password)
    material = (
        OPRF_LABEL
        + len(context).to_bytes(2, "big")
        + context
        + len(password).to_bytes(4, "big")
        + password
    )
    x = int.from_bytes(sha512(material), "big")
    if x == 0:
        x = 1
    return mul(x, x)


@dataclass(frozen=True)
class BlindState:
    """Client-side state kept between blinding and finalisation."""

    r: int
    blinded: int
    group_element: int
    context: bytes

    def __post_init__(self) -> None:
        _check_field(self.r)
        _check_field(self.blinded)
        _check_field(self.group_element)
        if gcd(self.r, P - 1) != 1:
            raise OPRFError("blinding exponent must be coprime to p-1")


def blind(
    password: bytes,
    *,
    context: bytes = b"",
    rng: Rng = random_bytes,
) -> tuple[int, BlindState]:
    """Blind a password.  Returns ``(blinded_value, state)``."""
    context = _context_bytes(context)
    group_element = hash_to_group(password, context)
    r = _random_unit(rng)
    blinded = pow(group_element, r, P)
    return blinded, BlindState(r, blinded, group_element, context)


def finalize(state: BlindState, evaluated: int) -> bytes:
    """Unblind the server's evaluation and hash it to 32 bytes."""
    if not isinstance(state, BlindState):
        raise TypeError("state must be a BlindState")
    if not isinstance(evaluated, int) or isinstance(evaluated, bool):
        raise TypeError("evaluated element must be an integer")
    if not 1 <= evaluated < P:
        raise OPRFError("evaluated element out of range")
    unblinded = pow(evaluated, pow(state.r, -1, P - 1), P)
    return sha256(OPRF_OUTPUT_LABEL + encode_field(unblinded))


class OPRFServer:
    """Holds the OPRF key and evaluates blinded group elements."""

    def __init__(self, key: int | None = None, *, rng: Rng = random_bytes) -> None:
        if key is None:
            key = _random_unit(rng)
        if not isinstance(key, int) or isinstance(key, bool):
            raise TypeError("OPRF key must be an integer")
        if not 2 <= key < P:
            raise OPRFError("OPRF key out of range")
        if gcd(key, P - 1) != 1:
            raise OPRFError("OPRF key must be coprime to p-1")
        self._key = key

    def evaluate(self, blinded: int) -> int:
        if not isinstance(blinded, int) or isinstance(blinded, bool):
            raise TypeError("blinded element must be an integer")
        if not 1 <= blinded < P:
            raise OPRFError("blinded element out of range")
        return pow(blinded, self._key, P)


def derive_client_key(oprf_output: bytes, context: bytes = b"") -> bytes:
    """HKDF the OPRF output into a 32-byte SVR client key."""
    if not isinstance(oprf_output, (bytes, bytearray)):
        raise TypeError("OPRF output must be bytes")
    if len(oprf_output) != 32:
        raise OPRFError("OPRF output must be 32 bytes")
    context = _context_bytes(context)
    info = SVR_LABEL + b"-key" + len(context).to_bytes(2, "big") + context
    return hkdf_sha256(bytes(oprf_output), SVR_SALT, info, 32)


def _user_bytes(username: str | bytes) -> bytes:
    if isinstance(username, str):
        username = username.encode("utf-8")
    if not isinstance(username, (bytes, bytearray)):
        raise TypeError("username must be str or bytes")
    username = bytes(username)
    if not 1 <= len(username) <= 0xFFFF:
        raise OPRFError("username must be 1..65535 bytes")
    return username


def make_svr(client_key: bytes, username: str | bytes) -> bytes:
    """Derive the stored secret validation record."""
    if not isinstance(client_key, (bytes, bytearray)):
        raise TypeError("client key must be bytes")
    if len(client_key) != 32:
        raise OPRFError("client key must be 32 bytes")
    user = _user_bytes(username)
    return sha256(
        SVR_LABEL
        + b"-record"
        + len(user).to_bytes(2, "big")
        + user
        + bytes(client_key)
    )


class SVRServer:
    """Reference enrollment/authentication server storing only SVRs.

    The convenience methods run the client side of the OPRF locally so a
    single object can demonstrate the whole flow.  In a real deployment
    the client performs :func:`blind` and :func:`finalize` itself and the
    server only ever sees blinded group elements and the resulting SVR.
    """

    def __init__(self, key: int | None = None, *, rng: Rng = random_bytes) -> None:
        self.oprf = OPRFServer(key, rng=rng)
        self._records: dict[bytes, bytes] = {}

    def enroll(
        self,
        username: str | bytes,
        password: bytes,
        *,
        context: bytes = b"",
        rng: Rng = random_bytes,
    ) -> bytes:
        user = _user_bytes(username)
        if user in self._records:
            raise OPRFError("user is already enrolled")
        if not isinstance(password, (bytes, bytearray)):
            raise TypeError("password must be bytes")
        if not password:
            raise OPRFError("password must not be empty")
        context = _context_bytes(context)
        blinded, state = blind(
            bytes(password), context=user + b"\x00" + context, rng=rng
        )
        output = finalize(state, self.oprf.evaluate(blinded))
        client_key = derive_client_key(output, context)
        self._records[user] = make_svr(client_key, user)
        return client_key

    def authenticate(
        self,
        username: str | bytes,
        password: bytes,
        *,
        context: bytes = b"",
        rng: Rng = random_bytes,
    ) -> bool:
        user = _user_bytes(username)
        record = self._records.get(user)
        if record is None:
            return False
        if not isinstance(password, (bytes, bytearray)) or not password:
            return False
        context = _context_bytes(context)
        blinded, state = blind(
            bytes(password), context=user + b"\x00" + context, rng=rng
        )
        output = finalize(state, self.oprf.evaluate(blinded))
        candidate = make_svr(derive_client_key(output, context), user)
        return compare_digest(candidate, record)

    def verify_key(self, username: str | bytes, client_key: bytes) -> bool:
        user = _user_bytes(username)
        record = self._records.get(user)
        if record is None:
            return False
        try:
            candidate = make_svr(client_key, user)
        except OPRFError:
            return False
        return compare_digest(candidate, record)

    def record(self, username: str | bytes) -> bytes | None:
        return self._records.get(_user_bytes(username))

    def remove(self, username: str | bytes) -> None:
        self._records.pop(_user_bytes(username), None)

    def __contains__(self, username: object) -> bool:
        try:
            return _user_bytes(username) in self._records  # type: ignore[arg-type]
        except (TypeError, OPRFError):
            return False
