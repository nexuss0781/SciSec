"""C11 Sesame tests: fan-out, device add/remove, handshake retry."""

import pytest

from secsci.components.c11_sesame import (
    SesameDevice,
    SesameEnvelope,
    SesameError,
    SesameManager,
)


def make_device(user, index, seed_byte, **kwargs):
    return SesameDevice(user, f"{user}-{index}", bytes([seed_byte]) * 32, **kwargs)


def setup(alice_count=1, bob_count=1, carol_count=0):
    manager = SesameManager()
    alice = [make_device("alice", i, 10 + i, one_time_prekeys=8) for i in range(alice_count)]
    bob = [make_device("bob", i, 40 + i, one_time_prekeys=8) for i in range(bob_count)]
    carol = [make_device("carol", i, 70 + i, one_time_prekeys=8) for i in range(carol_count)]
    for device in alice + bob + carol:
        manager.add_local_device(device)
    manager.publish_devices("alice", alice)
    manager.publish_devices("bob", bob)
    if carol:
        manager.publish_devices("carol", carol)
    return manager, alice, bob, carol


def test_single_device_roundtrip():
    manager, alice, bob, _ = setup()
    envelopes = manager.send("alice", "alice-0", "bob", b"hello bob")
    assert set(envelopes) == {"bob-0"}
    assert manager.receive("bob", "bob-0", "alice", envelopes["bob-0"]) == b"hello bob"
    reply = manager.send("bob", "bob-0", "alice", b"hello alice")
    assert manager.receive("alice", "alice-0", "bob", reply["alice-0"]) == b"hello alice"


def test_fanout_to_multiple_devices():
    manager, alice, bob, _ = setup(alice_count=3)
    envelopes = manager.send("bob", "bob-0", "alice", b"to all devices")
    assert set(envelopes) == {"alice-0", "alice-1", "alice-2"}
    # Each envelope is independently encrypted.
    assert len({env.to_bytes() for env in envelopes.values()}) == 3
    results = manager.receive_for_all("alice", "bob", envelopes)
    assert results == {device: b"to all devices" for device in envelopes}


def test_multi_turn_and_out_of_order():
    manager, alice, bob, _ = setup()
    messages = [
        manager.send("alice", "alice-0", "bob", f"m{i}".encode())["bob-0"]
        for i in range(6)
    ]
    for i in [3, 0, 5, 2, 1, 4]:
        assert manager.receive("bob", "bob-0", "alice", messages[i]) == f"m{i}".encode()
    reply = manager.send("bob", "bob-0", "alice", b"reply")
    assert manager.receive("alice", "alice-0", "bob", reply["alice-0"]) == b"reply"


def test_device_added_later():
    manager, alice, bob, _ = setup()
    manager.send("bob", "bob-0", "alice", b"before add")
    assert manager.device_ids("alice") == ["alice-0"]
    new_device = make_device("alice", 1, 99, one_time_prekeys=8)
    manager.add_local_device(new_device)
    version = manager.add_remote_device("alice", "alice-1", new_device.bundle)
    assert version > 1
    assert manager.device_ids("alice") == ["alice-0", "alice-1"]
    envelopes = manager.send("bob", "bob-0", "alice", b"after add")
    assert set(envelopes) == {"alice-0", "alice-1"}
    assert manager.receive("alice", "alice-1", "bob", envelopes["alice-1"]) == b"after add"
    assert manager.receive("alice", "alice-0", "bob", envelopes["alice-0"]) == b"after add"


def test_device_removed():
    manager, alice, bob, _ = setup(alice_count=3)
    manager.send("bob", "bob-0", "alice", b"first")
    manager.remove_remote_device("alice", "alice-1")
    assert manager.device_ids("alice") == ["alice-0", "alice-2"]
    envelopes = manager.send("bob", "bob-0", "alice", b"second")
    assert set(envelopes) == {"alice-0", "alice-2"}
    assert manager.receive("alice", "alice-0", "bob", envelopes["alice-0"]) == b"second"
    assert manager.receive("alice", "alice-2", "bob", envelopes["alice-2"]) == b"second"


def test_handshake_is_retried_until_reply():
    manager, alice, bob, _ = setup()
    first = manager.send("alice", "alice-0", "bob", b"one")["bob-0"]
    second = manager.send("alice", "alice-0", "bob", b"two")["bob-0"]
    assert first.handshake is not None
    assert second.handshake is not None
    assert manager.receive("bob", "bob-0", "alice", first) == b"one"
    assert manager.receive("bob", "bob-0", "alice", second) == b"two"
    reply = manager.send("bob", "bob-0", "alice", b"ack")["alice-0"]
    assert manager.receive("alice", "alice-0", "bob", reply) == b"ack"
    third = manager.send("alice", "alice-0", "bob", b"three")["bob-0"]
    assert third.handshake is None
    assert manager.receive("bob", "bob-0", "alice", third) == b"three"


def test_duplicate_handshake_is_ignored_but_message_duplicate_is_rejected():
    manager, alice, bob, _ = setup()
    envelope = manager.send("alice", "alice-0", "bob", b"once")["bob-0"]
    assert manager.receive("bob", "bob-0", "alice", envelope) == b"once"
    with pytest.raises(SesameError):
        manager.receive("bob", "bob-0", "alice", envelope)


def test_wrong_recipient_device_is_rejected():
    manager, alice, bob, _ = setup(alice_count=2)
    envelopes = manager.send("bob", "bob-0", "alice", b"routed")
    with pytest.raises(SesameError):
        manager.receive("alice", "alice-1", "bob", envelopes["alice-0"])


def test_envelope_wire_roundtrip_and_tampering():
    manager, alice, bob, _ = setup()
    envelope = manager.send("alice", "alice-0", "bob", b"wire")["bob-0"]
    raw = envelope.to_bytes()
    parsed = SesameEnvelope.from_bytes(raw)
    assert parsed == envelope
    assert manager.receive("bob", "bob-0", "alice", parsed) == b"wire"
    with pytest.raises(SesameError):
        SesameEnvelope.from_bytes(raw[:-1])
    with pytest.raises(SesameError):
        SesameEnvelope.from_bytes(b"XXXX" + raw[4:])
    bad = bytearray(raw)
    bad[-1] ^= 1
    with pytest.raises(SesameError):
        manager.receive("bob", "bob-0", "alice", bytes(bad))


def test_two_senders_use_distinct_one_time_prekeys():
    manager, alice, bob, carol = setup(carol_count=1)
    from_alice = manager.send("alice", "alice-0", "bob", b"from alice")["bob-0"]
    from_carol = manager.send("carol", "carol-0", "bob", b"from carol")["bob-0"]
    assert manager.receive("bob", "bob-0", "alice", from_alice) == b"from alice"
    assert manager.receive("bob", "bob-0", "carol", from_carol) == b"from carol"
    # Both sessions are independent and can continue.
    assert manager.receive("bob", "bob-0", "alice", manager.send("alice", "alice-0", "bob", b"a2")["bob-0"]) == b"a2"
    assert manager.receive("bob", "bob-0", "carol", manager.send("carol", "carol-0", "bob", b"c2")["bob-0"]) == b"c2"


def test_unknown_devices_and_errors():
    manager, alice, bob, _ = setup()
    with pytest.raises(SesameError):
        manager.send("nobody", "nobody-0", "bob", b"x")
    with pytest.raises(SesameError):
        manager.send("alice", "alice-0", "nobody", b"x")
    with pytest.raises(SesameError):
        manager.receive("nobody", "nobody-0", "alice", b"x")
    with pytest.raises(SesameError):
        manager.remove_remote_device("alice", "missing")
    with pytest.raises(SesameError):
        manager.add_local_device(alice[0])
    with pytest.raises(SesameError):
        manager.publish_devices("bob", alice)
    with pytest.raises(ValueError):
        SesameDevice("alice", "", b"k" * 32)
    with pytest.raises(ValueError):
        SesameDevice("alice", "x" * 256, b"k" * 32)
    with pytest.raises(ValueError):
        SesameDevice("alice", "d", b"short")
    with pytest.raises(SesameError):
        alice[0].send("bob", "bob-0", b"no session")


def test_sessions_survive_unrelated_device_changes():
    manager, alice, bob, _ = setup(alice_count=2)
    manager.send("bob", "bob-0", "alice", b"hello")
    # Remove alice-1; the alice-0 session must keep working.
    manager.remove_remote_device("alice", "alice-1")
    envelopes = manager.send("bob", "bob-0", "alice", b"still here")
    assert set(envelopes) == {"alice-0"}
    assert manager.receive("alice", "alice-0", "bob", envelopes["alice-0"]) == b"still here"
