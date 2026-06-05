"""Double Ratchet tests: round-trip, DH-ratchet across turns, out-of-order
delivery, forward secrecy, post-compromise security, bounds, and forgery.

The ratchet provides the forward-secrecy + post-compromise-security remediation
for the residual "no PFS for the static leg" risk. These tests prove the state
machine round-trips, heals after a DH ratchet step (PCS), retains earlier message
keys for out-of-order delivery within bounds, and fails closed on tamper.
"""

from __future__ import annotations

import copy

import pytest

pytest.importorskip("cryptography")

from gateway.crypto import hermes_ratchet as hr  # noqa: E402


def _establish(session_id: str = "s1"):
    """Establish an Alice(initiator)/Bob(responder) pair sharing an initial
    secret (the authenticated X3DH output) and Bob's initial ratchet key."""
    shared = hr.random_root_key()
    bob_initial = hr.generate_key_pair()
    alice = hr.initiator_state(
        session_id=session_id, local_device_id="alice", remote_device_id="bob",
        shared_secret=shared, remote_initial_ratchet_public_key_base64=bob_initial.public_key_base64,
    )
    bob = hr.responder_state(
        session_id=session_id, local_device_id="bob", remote_device_id="alice",
        shared_secret=shared, local_initial_ratchet_key_pair=bob_initial,
    )
    return alice, bob


def test_round_trip_both_directions():
    alice, bob = _establish()
    e = hr.encrypt(b"hello bob", alice)
    assert hr.decrypt(e, bob) == b"hello bob"
    e2 = hr.encrypt(b"hi alice", bob)
    assert hr.decrypt(e2, alice) == b"hi alice"


def test_many_turns_dh_ratchet():
    alice, bob = _establish()
    for i in range(10):
        e = hr.encrypt(f"a{i}".encode(), alice)
        assert hr.decrypt(e, bob) == f"a{i}".encode()
        e2 = hr.encrypt(f"b{i}".encode(), bob)
        assert hr.decrypt(e2, alice) == f"b{i}".encode()
    # Each alternation advances the DH ratchet -> epoch climbs on both sides.
    assert alice.epoch >= 9 and bob.epoch >= 9


def test_consecutive_same_sender_messages():
    alice, bob = _establish()
    envs = [hr.encrypt(f"m{i}".encode(), alice) for i in range(5)]
    for i, e in enumerate(envs):
        assert hr.decrypt(e, bob) == f"m{i}".encode()


def test_out_of_order_delivery_within_bound():
    alice, bob = _establish()
    envs = [hr.encrypt(f"m{i}".encode(), alice) for i in range(5)]
    # Deliver 4,2,0,3,1 — the skipped-message-key store covers the gaps.
    for i in [4, 2, 0, 3, 1]:
        assert hr.decrypt(envs[i], bob) == f"m{i}".encode()


def test_skip_bound_is_enforced():
    alice, bob = _establish()
    bob.max_skip = 3
    envs = [hr.encrypt(f"m{i}".encode(), alice) for i in range(10)]
    # Jumping straight to message 9 skips 9 > max_skip -> fail closed (per-chain).
    with pytest.raises(hr.TooManySkippedKeysError):
        hr.decrypt(envs[9], bob)


def test_total_skipped_key_store_bound_is_enforced():
    """The TOTAL skipped-key store cap (the overload fix, separate from the
    per-chain max_skip) fails closed across multiple DH epochs."""
    alice, bob = _establish()
    bob.max_skip = 64           # generous per chain
    bob.max_skipped_keys = 50   # small TOTAL store
    with pytest.raises(hr.SkippedKeyLimitExceededError):
        for epoch in range(20):
            msgs = [hr.encrypt(f"e{epoch}m{i}".encode(), alice) for i in range(10)]
            hr.decrypt(msgs[9], bob)  # receive only the last -> store 9 keys this chain
            hr.decrypt(hr.encrypt(b"ack", bob), alice)  # round-trip advances Alice's ratchet
    # The store never exceeds the cap (the overflowing decrypt was rejected, uncommitted).
    assert len(bob.skipped_message_keys) <= bob.max_skipped_keys


def test_forged_frame_does_not_mutate_state_transactional():
    """A forged frame (attacker ratchet key + bad ciphertext) that would trigger an
    irreversible DH ratchet must leave the caller's state BYTE-IDENTICAL — the
    decrypt is transactional and only commits after the AEAD authenticates."""
    alice, bob = _establish()
    hr.decrypt(hr.encrypt(b"warmup", alice), bob)  # establish Bob's receiving chain
    before = bob.to_wire()
    forged_pub = hr.generate_key_pair().public_key_base64  # an attacker ratchet pub
    forged_header = hr.HermesRatchetHeader(
        session_id=bob.session_id, sender_device_id="alice", receiver_device_id="bob",
        ratchet_public_key_base64=forged_pub, previous_chain_length=0,
        message_number=0, epoch=bob.epoch + 1,
    )
    forged = hr.HermesRatchetEnvelope(
        header=forged_header, ciphertext_base64=hr._b64(b"\x00" * 60)
    )
    with pytest.raises(hr.HermesRatchetError):
        hr.decrypt(forged, bob)
    assert bob.to_wire() == before, "forged frame must not advance the ratchet (transactional)"


def test_forward_secrecy_message_keys_are_single_use():
    """A message key is consumed on decrypt; the advanced chain key cannot
    re-derive a past message key (chain KDF is one-way HMAC)."""
    alice, bob = _establish()
    e0 = hr.encrypt(b"secret-0", alice)
    e1 = hr.encrypt(b"secret-1", alice)
    assert hr.decrypt(e0, bob) == b"secret-0"
    assert hr.decrypt(e1, bob) == b"secret-1"
    # Re-delivering e0 now fails: its key was popped and the chain moved on.
    with pytest.raises(hr.HermesRatchetError):
        hr.decrypt(e0, bob)


def test_post_compromise_security_old_state_cannot_read_new_epoch():
    """Snapshot Bob's state, then drive several DH-ratchet steps. A message sent
    in the new epoch cannot be decrypted by the stale snapshot — the channel has
    healed past the captured state."""
    alice, bob = _establish()
    hr.decrypt(hr.encrypt(b"warmup", alice), bob)
    stale_bob = copy.deepcopy(bob)
    # Drive several full round-trips to advance the ratchet well past the snapshot.
    for i in range(4):
        hr.decrypt(hr.encrypt(f"b{i}".encode(), bob), alice)
        hr.decrypt(hr.encrypt(f"a{i}".encode(), alice), bob)
    fresh = hr.encrypt(b"post-heal secret", alice)
    # The current Bob still reads it...
    assert hr.decrypt(fresh, bob) == b"post-heal secret"
    # ...but the stale captured state (pre-heal) cannot.
    with pytest.raises(hr.HermesRatchetError):
        hr.decrypt(fresh, copy.deepcopy(stale_bob))


def test_tampered_ciphertext_fails_closed():
    import base64

    alice, bob = _establish()
    e = hr.encrypt(b"tamper me", alice)
    raw = bytearray(base64.b64decode(e.ciphertext_base64))
    raw[-1] ^= 0x01
    bad = hr.HermesRatchetEnvelope(header=e.header, ciphertext_base64=base64.b64encode(bytes(raw)).decode())
    with pytest.raises(hr.AuthenticationFailedError):
        hr.decrypt(bad, bob)


def test_tampered_header_fails_closed():
    alice, bob = _establish()
    e = hr.encrypt(b"bind the header", alice)
    before = bob.to_wire()
    # Flip a binding-only header field (epoch) that does NOT trigger the skip/ratchet
    # path -> the envelope AAD no longer matches and the tag fails, with no mutation.
    bad_header = hr.HermesRatchetHeader(
        session_id=e.header.session_id, sender_device_id=e.header.sender_device_id,
        receiver_device_id=e.header.receiver_device_id,
        ratchet_public_key_base64=e.header.ratchet_public_key_base64,
        previous_chain_length=e.header.previous_chain_length,
        message_number=e.header.message_number, epoch=e.header.epoch + 5,
    )
    bad = hr.HermesRatchetEnvelope(header=bad_header, ciphertext_base64=e.ciphertext_base64)
    with pytest.raises(hr.AuthenticationFailedError):
        hr.decrypt(bad, bob)
    assert bob.to_wire() == before  # transactional: no state change on a forged header


def test_wrong_session_rejected():
    alice, _bob = _establish("s1")
    _alice2, bob2 = _establish("s2")  # a different session id -> header binding catches it
    e = hr.encrypt(b"cross session", alice)
    with pytest.raises(hr.InvalidEnvelopeError):
        hr.decrypt(e, bob2)


def test_associated_data_is_bound():
    alice, bob = _establish()
    e = hr.encrypt(b"with ad", alice, associated_data=b"context-A")
    assert hr.decrypt(e, bob, associated_data=b"context-A") == b"with ad"
    # A different AD on receive fails the tag.
    alice2, bob2 = _establish()
    e2 = hr.encrypt(b"with ad", alice2, associated_data=b"context-A")
    with pytest.raises(hr.AuthenticationFailedError):
        hr.decrypt(e2, bob2, associated_data=b"context-B")


def test_session_state_wire_round_trip():
    alice, bob = _establish()
    e = hr.encrypt(b"persist me", alice)
    # Persist + reload Bob's state across the wire, then decrypt.
    reloaded = hr.HermesRatchetSessionState.from_wire(bob.to_wire())
    assert hr.decrypt(e, reloaded) == b"persist me"


def test_bootstrap_session_is_symmetric_and_round_trips():
    """Both sides bootstrap matching responder/initiator sessions from the PINNED
    ratchet identity keys with no handshake; the initiator sends first, then both
    alternate with forward secrecy + PCS."""
    agent_id = hr.generate_key_pair()   # agent = responder (replies)
    phone_id = hr.generate_key_pair()   # phone = initiator (sends first)
    agent = hr.bootstrap_session(
        role=hr.HermesRatchetRole.RESPONDER, uid="u", client_id="c",
        local_ratchet_key_pair=agent_id, peer_ratchet_public_key_base64=phone_id.public_key_base64,
    )
    phone = hr.bootstrap_session(
        role=hr.HermesRatchetRole.INITIATOR, uid="u", client_id="c",
        local_ratchet_key_pair=phone_id, peer_ratchet_public_key_base64=agent_id.public_key_base64,
    )
    assert agent.session_id == phone.session_id
    assert {agent.role, phone.role} == {hr.HermesRatchetRole.INITIATOR, hr.HermesRatchetRole.RESPONDER}
    for i in range(6):
        assert hr.decrypt(hr.encrypt(f"p{i}".encode(), phone), agent) == f"p{i}".encode()
        assert hr.decrypt(hr.encrypt(f"a{i}".encode(), agent), phone) == f"a{i}".encode()
    assert agent.epoch >= 5 and phone.epoch >= 5  # DH ratchet advanced


def test_bootstrap_rejects_identical_identity_keys():
    same = hr.generate_key_pair()
    with pytest.raises(hr.InvalidPublicKeyError):
        hr.bootstrap_session(
            role=hr.HermesRatchetRole.INITIATOR, uid="u", client_id="c",
            local_ratchet_key_pair=same, peer_ratchet_public_key_base64=same.public_key_base64,
        )


def test_envelope_aad_is_deterministic_and_length_prefixed():
    h = hr.HermesRatchetHeader(
        session_id="s", sender_device_id="a", receiver_device_id="b",
        ratchet_public_key_base64="cHVi", previous_chain_length=1, message_number=2, epoch=3,
    )
    aad1 = hr.envelope_aad(h, b"ad")
    aad2 = hr.envelope_aad(h, b"ad")
    assert aad1 == aad2
    assert aad1.startswith(b"OpenBurnBar-HermesRatchet-v1-AAD")
