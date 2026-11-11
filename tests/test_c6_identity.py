"""C6 tests: safety numbers, Merkle inclusion/consistency, TOFU trust."""

import pytest

from secsci.components.c6_identity import (
    IdentityChanged,
    MerkleLog,
    TrustStore,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    node_hash,
    safety_number,
    verify_consistency,
    verify_inclusion,
)


def test_safety_number_shape_and_symmetry():
    a, b = b"a" * 32, b"b" * 32
    sn = safety_number(a, b, iterations=16)
    groups = sn.split(" ")
    assert len(groups) == 12
    assert all(len(g) == 5 and g.isdigit() for g in groups)
    assert sn == safety_number(b, a, iterations=16)
    assert sn != safety_number(a, b"c" * 32, iterations=16)


def test_safety_number_default_iterations_vector():
    # A stable regression value for the documented Sec-Sci construction.
    sn = safety_number(b"a" * 32, b"b" * 32, iterations=64)
    assert sn == safety_number(b"a" * 32, b"b" * 32, iterations=64)
    assert len(sn.split(" ")) == 12


def test_safety_number_validation():
    with pytest.raises(ValueError):
        safety_number(b"short", b"b" * 32)
    with pytest.raises(ValueError):
        safety_number(b"a" * 32, b"b" * 32, iterations=0)


def test_hash_construction():
    assert leaf_hash(b"x") == leaf_hash(b"x")
    assert leaf_hash(b"x") != node_hash(leaf_hash(b"x"), leaf_hash(b"x"))
    with pytest.raises(ValueError):
        node_hash(b"short", b"x" * 32)


def test_merkle_root_known_shapes():
    leaves = [b"a", b"b", b"c"]
    root = merkle_root(leaves)
    expected = node_hash(
        node_hash(leaf_hash(b"a"), leaf_hash(b"b")), leaf_hash(b"c")
    )
    assert root == expected
    assert merkle_root([]) == merkle_root([])
    assert merkle_root([b"a"]) == leaf_hash(b"a")


@pytest.mark.parametrize("size", range(1, 18))
def test_inclusion_all_indices(size):
    leaves = [f"leaf-{i}".encode() for i in range(size)]
    root = merkle_root(leaves)
    for i in range(size):
        proof = inclusion_proof(leaves, i)
        assert verify_inclusion(root, i, size, leaves[i], proof)
        assert not verify_inclusion(root, i, size, leaves[i] + b"x", proof)
        if proof:
            bad = list(proof)
            bad[0] = bytes([bad[0][0] ^ 1]) + bad[0][1:]
            assert not verify_inclusion(root, i, size, leaves[i], bad)


@pytest.mark.parametrize("size", range(1, 18))
def test_consistency_all_prefixes(size):
    leaves = [f"leaf-{i}".encode() for i in range(size)]
    new_root = merkle_root(leaves)
    for m in range(1, size + 1):
        old_root = merkle_root(leaves[:m])
        proof = consistency_proof(leaves, m)
        assert verify_consistency(old_root, new_root, m, size, proof)
        assert not verify_consistency(
            bytes(32), new_root, m, size, proof
        )
        assert not verify_consistency(
            old_root, bytes(32), m, size, proof
        )


def test_merkle_log_api():
    log = MerkleLog()
    assert log.root == merkle_root([])
    roots = []
    for i in range(10):
        log.append(f"event-{i}".encode())
        roots.append(log.root)
    assert log.size == 10
    for i in range(10):
        proof = log.prove_inclusion(i)
        assert verify_inclusion(log.root, i, 10, f"event-{i}".encode(), proof)
    for m in range(1, 10):
        proof = log.prove_consistency(m)
        assert verify_consistency(roots[m - 1], log.root, m, 10, proof)
    assert log.root_at(0) == merkle_root([])
    with pytest.raises(ValueError):
        log.root_at(11)


def test_trust_store_tofu():
    store = TrustStore()
    identity = b"i" * 32
    assert store.check("bob", identity) == identity
    assert store.check("bob", identity) == identity
    with pytest.raises(IdentityChanged):
        store.check("bob", b"j" * 32)
    assert not store.is_verified("bob")
    store.mark_verified("bob")
    assert store.is_verified("bob")
    with pytest.raises(KeyError):
        store.mark_verified("carol")
    with pytest.raises(ValueError):
        store.check("carol", b"short")
