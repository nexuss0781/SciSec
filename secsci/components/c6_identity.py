"""C6 -- identity verification and an append-only Merkle transparency log.

Safety numbers
--------------
A Sec-Sci safety number is a deterministic 60-digit fingerprint of two
identity keys (Ed25519 encodings).  The keys are sorted so both sides
display the same value.  The digest is iterated ``iterations`` times
(5200 by default, mirroring the Signal UX) and expanded into twelve
5-digit groups.  This is a documented Sec-Sci construction, not the
Signal wire format.

Merkle log
----------
An RFC 6962-style append-only log: leaves are ``H(0x00 || data)``,
internal nodes ``H(0x01 || left || right)``, and trees are split at the
largest power of two smaller than the leaf count.  Inclusion and
consistency proofs are generated and verified with the RFC 6962
algorithms.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from ..primitives.hash import sha256

SAFETY_LABEL = b"SecSci-SafetyNumber-v1"
SAFETY_ITERATIONS = 5200
GROUPS = 12
GROUP_DIGITS = 5


def safety_number(
    identity_a: bytes, identity_b: bytes, iterations: int = SAFETY_ITERATIONS
) -> str:
    if len(identity_a) != 32 or len(identity_b) != 32:
        raise ValueError("identity keys must be 32 bytes")
    if iterations < 1:
        raise ValueError("iterations must be positive")
    a, b = sorted((identity_a, identity_b))
    h = hashlib.sha512(SAFETY_LABEL + a + b).digest()
    for i in range(iterations):
        h = hashlib.sha512(h + a + b + i.to_bytes(4, "big")).digest()
    n = int.from_bytes(h, "big")
    groups = []
    for _ in range(GROUPS):
        n, remainder = divmod(n, 100000)
        groups.append(f"{remainder:05d}")
    return " ".join(groups)


# ---------------------------------------------------------------------------
# Merkle log (RFC 6962)
# ---------------------------------------------------------------------------

EMPTY_ROOT = sha256(b"")


def leaf_hash(data: bytes) -> bytes:
    return sha256(b"\x00" + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise ValueError("Merkle node hashes must be 32 bytes")
    return sha256(b"\x01" + left + right)


def _largest_power_of_two_below(n: int) -> int:
    if n < 2:
        raise ValueError("n must be at least 2")
    return 1 << ((n - 1).bit_length() - 1)


def merkle_root(leaves: list[bytes]) -> bytes:
    """MTH over a list of raw leaf values (not leaf hashes)."""
    if not leaves:
        return EMPTY_ROOT
    hashes = [leaf_hash(item) for item in leaves]
    return _mth(hashes)


def _mth(hashes: list[bytes]) -> bytes:
    if len(hashes) == 1:
        return hashes[0]
    k = _largest_power_of_two_below(len(hashes))
    return node_hash(_mth(hashes[:k]), _mth(hashes[k:]))


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")
    return _inclusion([leaf_hash(item) for item in leaves], index)


def _inclusion(hashes: list[bytes], index: int) -> list[bytes]:
    if len(hashes) == 1:
        return []
    k = _largest_power_of_two_below(len(hashes))
    if index < k:
        return _inclusion(hashes[:k], index) + [_mth(hashes[k:])]
    return _inclusion(hashes[k:], index - k) + [_mth(hashes[:k])]


def verify_inclusion(
    root: bytes, index: int, tree_size: int, data: bytes, proof: list[bytes]
) -> bool:
    if tree_size <= 0 or not 0 <= index < tree_size:
        return False
    fn, sn = index, tree_size - 1
    r = leaf_hash(data)
    for p in proof:
        if len(p) != 32:
            return False
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def consistency_proof(leaves: list[bytes], m: int) -> list[bytes]:
    """Proof that the tree of size len(leaves) extends the first m leaves."""
    if not 0 < m <= len(leaves):
        raise ValueError("m must be in 1..tree_size")
    hashes = [leaf_hash(item) for item in leaves]
    return _subproof(m, hashes, True)


def _subproof(m: int, hashes: list[bytes], complete: bool) -> list[bytes]:
    if m == len(hashes):
        return [] if complete else [_mth(hashes)]
    k = _largest_power_of_two_below(len(hashes))
    if m <= k:
        return _subproof(m, hashes[:k], complete) + [_mth(hashes[k:])]
    return _subproof(m - k, hashes[k:], False) + [_mth(hashes[:k])]


def verify_consistency(
    old_root: bytes, new_root: bytes, m: int, n: int, proof: list[bytes]
) -> bool:
    if not (0 < m <= n):
        return False
    if m == n:
        return old_root == new_root and not proof
    if not proof or any(len(p) != 32 for p in proof):
        return False
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if fn == 0:
        fr = sr = old_root
    else:
        fr = sr = proof[0]
        proof = proof[1:]
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(p, fr)
            sr = node_hash(p, sr)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root


@dataclass
class MerkleLog:
    """Append-only log with O(log n) inclusion and consistency proofs."""

    entries: list[bytes] = field(default_factory=list)

    def append(self, data: bytes) -> int:
        self.entries.append(bytes(data))
        return len(self.entries) - 1

    @property
    def size(self) -> int:
        return len(self.entries)

    @property
    def root(self) -> bytes:
        return merkle_root(self.entries)

    def root_at(self, size: int) -> bytes:
        if not 0 <= size <= self.size:
            raise ValueError("size out of range")
        return merkle_root(self.entries[:size])

    def prove_inclusion(self, index: int) -> list[bytes]:
        return inclusion_proof(self.entries, index)

    def prove_consistency(self, old_size: int) -> list[bytes]:
        return consistency_proof(self.entries, old_size)


# ---------------------------------------------------------------------------
# Trust on first use
# ---------------------------------------------------------------------------

class IdentityChanged(Exception):
    """Raised when a peer presents a different identity key."""


@dataclass
class TrustStore:
    identities: dict[str, bytes] = field(default_factory=dict)
    verified: set[str] = field(default_factory=set)

    def check(self, user: str, identity: bytes) -> bytes:
        if len(identity) != 32:
            raise ValueError("identity key must be 32 bytes")
        seen = self.identities.get(user)
        if seen is None:
            self.identities[user] = identity
            return identity
        if seen != identity:
            raise IdentityChanged(f"identity key changed for {user}")
        return identity

    def mark_verified(self, user: str) -> None:
        if user not in self.identities:
            raise KeyError("unknown user")
        self.verified.add(user)

    def is_verified(self, user: str) -> bool:
        return user in self.verified
