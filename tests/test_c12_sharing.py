"""C12 tests: GF(2**521-1), Shamir sharing, OPRF and SVR."""

import itertools
import math

import pytest

from secsci.components.c12_sharing import (
    CHUNK_BYTES,
    FIELD_BYTES,
    P,
    OPRFError,
    OPRFServer,
    OPRF_OUTPUT_LABEL,
    SVRServer,
    Share,
    SharingError,
    add,
    blind,
    combine_shares,
    decode_field,
    derive_client_key,
    div,
    encode_field,
    finalize,
    hash_to_group,
    inv,
    make_svr,
    mul,
    neg,
    random_scalar,
    reduce,
    split_secret,
    sub,
)
from secsci.primitives.hash import sha256


def is_probable_prime(n: int) -> bool:
    """Miller-Rabin with the first twelve prime bases."""
    if n < 2:
        return False
    bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for base in bases:
        if n % base == 0:
            return n == base
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for base in bases:
        x = pow(base, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


# ---------------------------------------------------------------------------
# Field arithmetic
# ---------------------------------------------------------------------------


def test_p_is_the_fifth_mersenne_prime():
    assert P == 2**521 - 1
    assert is_probable_prime(P)
    # p - 1 is even and therefore not prime; the group order is composite.
    assert (P - 1) % 2 == 0
    assert not is_probable_prime(P - 1)
    # 3 divides p - 1, which matters for exponent validation below.
    assert (P - 1) % 3 == 0


def test_reduction_and_basic_identities():
    assert reduce(0) == 0
    assert reduce(P) == 0
    assert reduce(P + 5) == 5
    assert reduce(P * P) == 0
    assert reduce(-1) == P - 1
    assert reduce(-P) == 0
    assert reduce(-(P + 1)) == P - 1
    assert add(P - 1, 1) == 0
    assert sub(0, 1) == P - 1
    assert neg(0) == 0 and neg(7) == P - 7
    assert mul(0, P - 1) == 0
    assert mul(P - 1, P - 1) == 1
    assert div(10, 5) == 2
    assert mul(123456789, inv(123456789)) == 1
    with pytest.raises(ZeroDivisionError):
        inv(0)
    with pytest.raises(ValueError):
        add(P, 0)
    with pytest.raises(ValueError):
        mul(0, -1)


def test_field_axioms_on_random_values():
    values = [0, 1, 2, 3, P - 1, P - 2, (1 << 520), (1 << 260) + 7]
    values += [random_scalar() for _ in range(6)]
    for a in values:
        assert add(a, 0) == a
        assert mul(a, 1) == a
        assert add(a, neg(a)) == 0
        if a:
            assert mul(a, inv(a)) == 1
        for b in values:
            assert add(a, b) == add(b, a)
            assert mul(a, b) == mul(b, a)
            assert sub(add(a, b), b) == a
            for c in values:
                assert add(add(a, b), c) == add(a, add(b, c))
                assert mul(mul(a, b), c) == mul(a, mul(b, c))
                assert mul(a, add(b, c)) == add(mul(a, b), mul(a, c))


def test_encode_decode_field():
    for value in (0, 1, 2, P - 1, P - 2, 1 << 520):
        encoded = encode_field(value)
        assert len(encoded) == FIELD_BYTES
        assert decode_field(encoded) == value
    with pytest.raises(ValueError):
        encode_field(P)
    with pytest.raises(ValueError):
        encode_field(-1)
    with pytest.raises(ValueError):
        decode_field(b"\x00" * (FIELD_BYTES - 1))
    with pytest.raises(ValueError):
        decode_field(P.to_bytes(FIELD_BYTES, "big"))


def test_random_scalar_is_in_range():
    values = {random_scalar() for _ in range(100)}
    assert all(0 <= value < P for value in values)
    assert len(values) > 90


# ---------------------------------------------------------------------------
# Shamir secret sharing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("length", [1, 2, 64, CHUNK_BYTES, CHUNK_BYTES + 1, 200, 131])
def test_split_and_combine_roundtrip(length):
    secret = bytes((i * 37 + 11) & 0xFF for i in range(length))
    shares = split_secret(secret, 3, 5)
    assert len(shares) == 5
    assert [share.index for share in shares] == [1, 2, 3, 4, 5]
    assert len({share.set_id for share in shares}) == 1
    for subset in itertools.combinations(shares, 3):
        assert combine_shares(subset) == secret
    assert combine_shares(shares) == secret
    assert combine_shares(shares[:4]) == secret


def test_any_threshold_subset_works():
    secret = b"threshold secret material"
    shares = split_secret(secret, 4, 7)
    for subset in itertools.combinations(shares, 4):
        assert combine_shares(subset) == secret
    for subset in itertools.combinations(shares, 5):
        assert combine_shares(subset) == secret


def test_fewer_than_threshold_shares_are_rejected():
    shares = split_secret(b"secret", 3, 5)
    with pytest.raises(SharingError):
        combine_shares(shares[:2])
    with pytest.raises(SharingError):
        combine_shares([])


def test_threshold_one_is_allowed():
    shares = split_secret(b"one-of-one", 1, 4)
    for share in shares:
        assert combine_shares([share]) == b"one-of-one"


def test_share_wire_roundtrip():
    shares = split_secret(b"wire format secret" * 5, 2, 4)
    for share in shares:
        raw = share.to_bytes()
        assert Share.from_bytes(raw) == share
        assert len(raw) == 4 + 8 + 1 + 2 + 4 + 2 + len(share.values) * FIELD_BYTES
    with pytest.raises(SharingError):
        Share.from_bytes(b"XXXX" + shares[0].to_bytes()[4:])
    with pytest.raises(SharingError):
        Share.from_bytes(shares[0].to_bytes()[:-1])
    with pytest.raises(SharingError):
        Share.from_bytes(shares[0].to_bytes() + b"\x00")


def test_share_wire_rejects_invalid_field_values_and_indices():
    raw = bytearray(split_secret(b"secret", 2, 3)[0].to_bytes())
    bad = bytearray(raw)
    bad[4 + 8 + 1 : 4 + 8 + 3] = (0).to_bytes(2, "big")  # index 0
    with pytest.raises(SharingError):
        Share.from_bytes(bytes(bad))
    bad = bytearray(raw)
    bad[4 + 8 + 1 + 2 + 4 + 2 : 4 + 8 + 1 + 2 + 4 + 2 + FIELD_BYTES] = P.to_bytes(
        FIELD_BYTES, "big"
    )
    with pytest.raises(SharingError):
        Share.from_bytes(bytes(bad))
    bad = bytearray(raw)
    bad[4 + 8] = 0  # threshold 0
    with pytest.raises(SharingError):
        Share.from_bytes(bytes(bad))
    bad = bytearray(raw)
    bad[4 + 8 + 1 + 2 : 4 + 8 + 1 + 2 + 4] = (0).to_bytes(4, "big")  # length 0
    with pytest.raises(SharingError):
        Share.from_bytes(bytes(bad))


def test_mixing_splits_and_duplicates_is_rejected():
    first = split_secret(b"first secret", 2, 4)
    second = split_secret(b"second secret", 2, 4)
    with pytest.raises(SharingError):
        combine_shares([first[0], second[1]])
    with pytest.raises(SharingError):
        combine_shares([first[0], first[0], first[1]])
    with pytest.raises(TypeError):
        combine_shares([first[0], "not a share"])  # type: ignore[list-item]


def test_shares_from_different_lengths_are_rejected():
    short = split_secret(b"a", 2, 3)
    long = split_secret(b"a" * 100, 2, 3)
    with pytest.raises(SharingError):
        combine_shares([short[0], long[1]])


def test_split_parameter_validation():
    with pytest.raises(SharingError):
        split_secret(b"", 2, 3)
    with pytest.raises(SharingError):
        split_secret(b"x", 0, 3)
    with pytest.raises(SharingError):
        split_secret(b"x", 4, 3)
    with pytest.raises(SharingError):
        split_secret(b"x", 2, 0)
    with pytest.raises(SharingError):
        split_secret(b"x", 2, 65536)
    with pytest.raises(SharingError):
        split_secret(b"x", 2, 3, set_id=b"short")
    with pytest.raises(TypeError):
        split_secret("text", 2, 3)  # type: ignore[arg-type]


def test_split_is_randomised_and_set_ids_differ():
    first = split_secret(b"same secret", 2, 3)
    second = split_secret(b"same secret", 2, 3)
    assert first[0].set_id != second[0].set_id
    assert [s.values for s in first] != [s.values for s in second]


def test_share_dataclass_validation():
    with pytest.raises(SharingError):
        Share(b"short", 1, 2, 1, (0,))
    with pytest.raises(SharingError):
        Share(b"12345678", 0, 2, 1, (0,))
    with pytest.raises(SharingError):
        Share(b"12345678", 1, 0, 1, (0,))
    with pytest.raises(SharingError):
        Share(b"12345678", 1, 2, 0, (0,))
    with pytest.raises(SharingError):
        Share(b"12345678", 1, 2, 1, (0, 0))
    with pytest.raises(ValueError):
        Share(b"12345678", 1, 2, 1, (P,))


# ---------------------------------------------------------------------------
# OPRF and SVR
# ---------------------------------------------------------------------------


def test_hash_to_group_lands_in_the_quadratic_residue_subgroup():
    for password, context in [
        (b"password", b""),
        (b"password", b"alice"),
        (b"", b"empty"),
        (b"\x00" * 64, b"context"),
    ]:
        element = hash_to_group(password, context)
        assert 1 <= element < P
        assert pow(element, (P - 1) // 2, P) == 1
        assert hash_to_group(password, context) == element
        assert hash_to_group(password, context + b"x") != element
    with pytest.raises(TypeError):
        hash_to_group("password")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        hash_to_group(b"password", "context")  # type: ignore[arg-type]


def test_oprf_blinding_and_finalisation_are_algebraically_consistent():
    key = 7
    assert math.gcd(key, P - 1) == 1
    server = OPRFServer(key)
    password = b"correct horse battery staple"
    context = b"alice"
    first_blinded, first_state = blind(password, context=context)
    second_blinded, second_state = blind(password, context=context)
    assert first_blinded != second_blinded
    first = finalize(first_state, server.evaluate(first_blinded))
    second = finalize(second_state, server.evaluate(second_blinded))
    assert first == second
    assert len(first) == 32
    element = hash_to_group(password, context)
    expected = sha256(OPRF_OUTPUT_LABEL + encode_field(pow(element, key, P)))
    assert first == expected
    assert finalize(first_state, server.evaluate(first_blinded)) == first


def test_oprf_context_password_and_key_separation():
    server = OPRFServer(7)
    password = b"hunter2"
    outputs = set()
    for context in (b"", b"alice", b"bob"):
        blinded, state = blind(password, context=context)
        outputs.add(finalize(state, server.evaluate(blinded)))
    assert len(outputs) == 3
    # A different password with the same context gives a different output.
    blinded, state = blind(b"hunter3")
    assert finalize(state, server.evaluate(blinded)) not in outputs
    # A different server key gives a different output for the same input.
    other = OPRFServer(13)
    blinded, state = blind(password)
    assert finalize(state, other.evaluate(blinded)) not in outputs
    assert finalize(state, server.evaluate(blinded)) in outputs


def test_oprf_rejects_bad_inputs_and_keys():
    server = OPRFServer(7)
    with pytest.raises(OPRFError):
        server.evaluate(0)
    with pytest.raises(OPRFError):
        server.evaluate(P)
    blinded, state = blind(b"password")
    with pytest.raises(OPRFError):
        finalize(state, 0)
    with pytest.raises(OPRFError):
        finalize(state, P)
    with pytest.raises(TypeError):
        finalize("state", 1)  # type: ignore[arg-type]
    for key in (0, 1, 3, P - 1, P, -1):
        with pytest.raises(OPRFError):
            OPRFServer(key)
    with pytest.raises(TypeError):
        OPRFServer(True)  # type: ignore[arg-type]


def test_oprf_server_generates_valid_keys():
    for _ in range(10):
        server = OPRFServer()
        blinded, state = blind(b"password")
        assert 1 <= server.evaluate(blinded) < P
        assert len(finalize(state, server.evaluate(blinded))) == 32


def test_svr_enrollment_and_authentication():
    server = SVRServer(7)
    client_key = server.enroll("alice", b"correct horse")
    assert len(client_key) == 32
    assert server.authenticate("alice", b"correct horse")
    assert not server.authenticate("alice", b"wrong horse")
    assert not server.authenticate("bob", b"correct horse")
    assert server.verify_key("alice", client_key)
    assert not server.verify_key("alice", bytes(32))
    assert not server.verify_key("bob", client_key)
    record = server.record("alice")
    assert record is not None and len(record) == 32
    assert b"correct horse" not in record
    assert client_key not in record
    assert "alice" in server
    server.remove("alice")
    assert "alice" not in server
    assert not server.authenticate("alice", b"correct horse")


def test_svr_context_binding():
    server = SVRServer(7)
    server.enroll("alice", b"password", context=b"device-1")
    assert server.authenticate("alice", b"password", context=b"device-1")
    assert not server.authenticate("alice", b"password", context=b"device-2")


def test_svr_validation():
    server = SVRServer(7)
    with pytest.raises(OPRFError):
        server.enroll("alice", b"")
    server.enroll("alice", b"password")
    with pytest.raises(OPRFError):
        server.enroll("alice", b"other")
    with pytest.raises(TypeError):
        server.enroll("bob", "password")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        make_svr("key", "alice")  # type: ignore[arg-type]
    with pytest.raises(OPRFError):
        make_svr(b"short", "alice")
    with pytest.raises(OPRFError):
        derive_client_key(b"short")
    with pytest.raises(TypeError):
        derive_client_key(bytes(32), "context")  # type: ignore[arg-type]
    assert not server.authenticate("alice", b"")
    assert server.verify_key("alice", b"short") is False


def test_svr_records_are_deterministic_for_the_same_key():
    first = SVRServer(7)
    second = SVRServer(7)
    first.enroll("alice", b"password")
    second.enroll("alice", b"password")
    assert first.record("alice") == second.record("alice")
    third = SVRServer(13)
    third.enroll("alice", b"password")
    assert third.record("alice") != first.record("alice")
