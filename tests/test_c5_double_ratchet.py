"""C5 Double Ratchet tests: multi-turn conversation, ordering, tampering."""

import pytest

from secsci.components.c5_double_ratchet import (
    RatchetHeader,
    RatchetMessage,
    RatchetState,
    generate_ratchet_keypair,
    kdf_ck,
    kdf_rk,
)


def session():
    sk = bytes(range(32))
    bob_priv, bob_pub = generate_ratchet_keypair()
    alice = RatchetState.initiator(sk, bob_pub)
    bob = RatchetState.responder(sk, bob_priv, bob_pub)
    return alice, bob


def test_kdf_ck_domain_separation():
    mk, ck = kdf_ck(b"c" * 32)
    assert mk != ck
    assert mk == kdf_ck(b"c" * 32)[0]


def test_kdf_rk_lengths():
    rk, ck = kdf_rk(b"r" * 32, b"d" * 32)
    assert len(rk) == 32 and len(ck) == 32 and rk != ck


def test_first_message_and_reply():
    alice, bob = session()
    msg = alice.encrypt(b"hello bob")
    assert bob.decrypt(msg) == b"hello bob"
    reply = bob.encrypt(b"hello alice")
    assert alice.decrypt(reply) == b"hello alice"


def test_multi_turn_conversation():
    alice, bob = session()
    for i in range(10):
        assert bob.decrypt(alice.encrypt(f"A->B {i}".encode())) == f"A->B {i}".encode()
        assert alice.decrypt(bob.encrypt(f"B->A {i}".encode())) == f"B->A {i}".encode()


def test_out_of_order_delivery():
    alice, bob = session()
    messages = [alice.encrypt(f"m{i}".encode()) for i in range(6)]
    for i in [3, 0, 5, 2, 1, 4]:
        assert bob.decrypt(messages[i]) == f"m{i}".encode()


def test_batched_sends_then_replies():
    alice, bob = session()
    batch = [alice.encrypt(i.to_bytes(2, "big")) for i in range(8)]
    reply_batch = []
    plaintexts = {}
    # Bob receives in an interleaved order and sends several replies.
    for i in [1, 0, 3, 2, 5, 4, 7, 6]:
        assert bob.decrypt(batch[i]) == i.to_bytes(2, "big")
        reply = bob.encrypt(b"r" + i.to_bytes(2, "big"))
        reply_batch.append(reply)
        plaintexts[reply.header.n] = b"r" + i.to_bytes(2, "big")
    for i in [2, 0, 1, 3, 5, 4, 6, 7]:
        assert alice.decrypt(reply_batch[i]) == plaintexts[reply_batch[i].header.n]


def test_duplicate_delivery_is_rejected():
    alice, bob = session()
    msg = alice.encrypt(b"once")
    assert bob.decrypt(msg) == b"once"
    with pytest.raises(ValueError):
        bob.decrypt(msg)


def test_skipped_limit():
    alice, bob = session()
    bob.max_skip = 3
    messages = [alice.encrypt(b"x" * 4) for _ in range(10)]
    with pytest.raises(ValueError):
        bob.decrypt(messages[9])


def test_tampering_is_rejected():
    alice, bob = session()
    msg = alice.encrypt(b"authentic")
    import copy

    for field_name in ("ciphertext", "tag", "nonce"):
        trial = copy.deepcopy(bob)
        bad = RatchetMessage(
            msg.header,
            msg.nonce if field_name != "nonce" else bytes([msg.nonce[0] ^ 1]) + msg.nonce[1:],
            msg.ciphertext if field_name != "ciphertext" else b"X" + msg.ciphertext[1:],
            msg.tag if field_name != "tag" else bytes([msg.tag[0] ^ 1]) + msg.tag[1:],
        )
        with pytest.raises(ValueError):
            trial.decrypt(bad)


def test_wire_roundtrip():
    alice, bob = session()
    msg = alice.encrypt(b"wire")
    parsed = RatchetMessage.from_bytes(msg.to_bytes())
    assert parsed == msg
    assert bob.decrypt(parsed) == b"wire"
    with pytest.raises(ValueError):
        RatchetMessage.from_bytes(b"bad")


def test_header_roundtrip():
    h = RatchetHeader(b"p" * 32, 7, 9)
    assert RatchetHeader.from_bytes(h.to_bytes()) == h
    with pytest.raises(ValueError):
        RatchetHeader(b"p" * 32, -1, 0).to_bytes()
