"""v3 (RFC 9180 HPKE Auth) adapter integration tests for the BurnBar gateway.

Complements ``test_burnbar_plugin.py`` (which covers the v2 send/open surface)
with the v3-specific behaviour: the adapter emits an HPKE v3 envelope only to a
peer the AUTHENTICATED pairing grant marked v3-capable, opens a phone→agent v3
frame end-to-end, refuses downgraded / stripped / unmarked v3 frames, floors an
un-pinned or v2-only peer to v2, and honours the break-glass rollback flag. The
crypto-layer known-answer proof lives in ``test_relay_e2ee_v3.py``.
"""

from __future__ import annotations

import json

import pytest

from gateway.config import PlatformConfig
from tests.gateway._plugin_adapter_loader import load_plugin_adapter

_burnbar = load_plugin_adapter("burnbar")
BurnBarAdapter = _burnbar.BurnBarAdapter

try:
    from gateway.crypto import relay_e2ee

    RELAY_CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    relay_e2ee = None
    RELAY_CRYPTO_AVAILABLE = False

requires_relay = pytest.mark.skipif(
    not RELAY_CRYPTO_AVAILABLE, reason="cryptography / relay_e2ee unavailable"
)

_UID = "uid-v3"
_CLIENT = "client-v3"


def _no_persist(monkeypatch):
    import hermes_cli.config as _cfg

    monkeypatch.setattr(_cfg, "save_env_value", lambda *a, **k: None, raising=False)


def _paired_adapter(monkeypatch, *, peer_priv, agent_priv, peer_version: str | None):
    """Build an E2E-paired adapter with the agent identity injected (no disk writes).

    ``peer_version`` seeds the AUTHENTICATED BURNBAR_RELAY_PEER_KEY_VERSION pin
    ("3" makes the peer v3-capable; None leaves it at the v2 floor).
    """
    _no_persist(monkeypatch)
    monkeypatch.setenv("BURNBAR_RELAY_E2E", "1")
    monkeypatch.setenv("BURNBAR_RELAY_PEER_PUBLIC_KEY", peer_priv.public_key_base64())
    monkeypatch.setenv("BURNBAR_RELAY_UID", _UID)
    monkeypatch.setenv("BURNBAR_RELAY_CLIENT_ID", _CLIENT)
    monkeypatch.delenv("BURNBAR_DISABLE_GATEWAY_HPKE_V3", raising=False)
    if peer_version is None:
        monkeypatch.delenv("BURNBAR_RELAY_PEER_KEY_VERSION", raising=False)
    else:
        monkeypatch.setenv("BURNBAR_RELAY_PEER_KEY_VERSION", peer_version)
    monkeypatch.setattr(
        relay_e2ee.AgentRelayIdentity,
        "load_or_create",
        classmethod(lambda cls, **kw: relay_e2ee.AgentRelayIdentity(agent_priv)),
    )
    cfg = PlatformConfig(enabled=True, extra={"access_token": "tok", "home_channel": "burnbar:home"})
    return BurnBarAdapter(cfg)


def _phone_to_agent_v3_event(*, agent_pub_b64: str, phone_priv, event_id: str, payload: dict) -> dict:
    """Build a sealed phone→agent v3 event the way the iOS client would."""
    payload_aad = _burnbar._gateway_event_aad(_UID, _CLIENT, event_id)
    key_aad = _burnbar._gateway_event_key_aad(_UID, _CLIENT, event_id)
    sym = relay_e2ee.generate_symmetric_key()
    payload_ct = relay_e2ee.seal_to_base64(json.dumps(payload).encode("utf-8"), sym, payload_aad)
    wrap = relay_e2ee.wrap_symmetric_key_v3(sym, agent_pub_b64, key_aad, sender_private=phone_priv)
    return {
        "id": event_id,
        "destinationId": "burnbar:home",
        "relayEnvelope": {
            "payloadCiphertext": payload_ct,
            "wrappedKey": wrap.wrapped_key,
            "enc": wrap.enc,
            "relayEncryption": wrap.relay_encryption,
            "relayKeyVersion": wrap.relay_key_version,
            "eventId": event_id,
            "senderPublicKey": phone_priv.public_key_base64(),
        },
    }


# --- emission: v3 only to a v3-pinned peer, v2 floor otherwise ---------------
@requires_relay
def test_seal_message_emits_v3_to_v3_peer_and_phone_opens(monkeypatch):
    phone = relay_e2ee.generate_private_key()
    agent = relay_e2ee.generate_private_key()
    adapter = _paired_adapter(monkeypatch, peer_priv=phone, agent_priv=agent, peer_version="3")

    env = adapter._sealer.seal_message(destination_id="burnbar:home", text="hpke secret")
    assert env["relayKeyVersion"] == 3
    assert env["relayEncryption"] == relay_e2ee.HPKE_ALGORITHM
    assert env["enc"], "v3 envelope must carry the HPKE enc"
    assert "text" not in env  # plaintext gone

    # The phone opens it with the v3 HPKE opener, binding the agent as the sender.
    sym = relay_e2ee.unwrap_symmetric_key_v3(
        env["enc"], env["wrappedKey"], phone,
        _burnbar._gateway_message_key_aad(_UID, _CLIENT, env["messageId"]),
        pinned_sender_public=env["senderPublicKey"],
    )
    opened = json.loads(
        relay_e2ee.open_base64(
            env["payloadCiphertext"], sym,
            _burnbar._gateway_message_aad(_UID, _CLIENT, env["messageId"]),
        ).decode()
    )
    assert opened == {"text": "hpke secret", "destinationId": "burnbar:home"}


@requires_relay
def test_seal_message_floors_to_v2_for_unpinned_peer(monkeypatch):
    phone = relay_e2ee.generate_private_key()
    agent = relay_e2ee.generate_private_key()
    adapter = _paired_adapter(monkeypatch, peer_priv=phone, agent_priv=agent, peer_version=None)

    env = adapter._sealer.seal_message(destination_id="burnbar:home", text="legacy v2")
    assert env["relayKeyVersion"] == 2
    assert "enc" not in env  # v2 envelope is byte-identical (no HPKE enc)


@requires_relay
def test_seal_attachment_and_model_switch_emit_v3_to_v3_peer(monkeypatch, tmp_path):
    phone = relay_e2ee.generate_private_key()
    agent = relay_e2ee.generate_private_key()
    adapter = _paired_adapter(monkeypatch, peer_priv=phone, agent_priv=agent, peer_version="3")

    f = tmp_path / "report.pdf"
    f.write_bytes(b"PDF-BYTES")
    env, _body = adapter._sealer.seal_attachment(
        destination_id="burnbar:home", file_path=f, content_type="application/pdf"
    )
    assert env["relayKeyVersion"] == 3 and env["enc"]

    sw = adapter._sealer.seal_model_switch(destination_id="burnbar:home", model_id="claude-opus-4-8")
    assert sw["relayKeyVersion"] == 3 and sw["enc"]


@requires_relay
def test_open_model_switch_opens_v3_frame(monkeypatch):
    """A phone→agent v3 model_switch opens through the authenticated open path and
    yields the typed control payload (a relay cannot inject a cleartext switch)."""
    phone = relay_e2ee.generate_private_key()
    agent = relay_e2ee.generate_private_key()
    adapter = _paired_adapter(monkeypatch, peer_priv=phone, agent_priv=agent, peer_version="3")

    raw = _phone_to_agent_v3_event(
        agent_pub_b64=agent.public_key_base64(), phone_priv=phone,
        event_id="evt-switch",
        payload={"kind": "model_switch", "modelId": "claude-opus-4-8", "destinationId": "burnbar:home"},
    )
    opened = adapter._sealer.open_model_switch(raw)
    assert opened["kind"] == "model_switch"
    assert opened["modelId"] == "claude-opus-4-8"


# --- open: phone→agent v3 round trip + downgrade refusals --------------------
@requires_relay
def test_open_event_opens_v3_frame(monkeypatch):
    phone = relay_e2ee.generate_private_key()
    agent = relay_e2ee.generate_private_key()
    adapter = _paired_adapter(monkeypatch, peer_priv=phone, agent_priv=agent, peer_version="3")

    raw = _phone_to_agent_v3_event(
        agent_pub_b64=agent.public_key_base64(), phone_priv=phone,
        event_id="evt-1", payload={"text": "hi from phone"},
    )
    opened = adapter._sealer.open_event(raw)
    assert opened == {"text": "hi from phone"}


@requires_relay
def test_open_event_refuses_v3_frame_with_stripped_enc(monkeypatch):
    phone = relay_e2ee.generate_private_key()
    agent = relay_e2ee.generate_private_key()
    adapter = _paired_adapter(monkeypatch, peer_priv=phone, agent_priv=agent, peer_version="3")

    raw = _phone_to_agent_v3_event(
        agent_pub_b64=agent.public_key_base64(), phone_priv=phone,
        event_id="evt-2", payload={"text": "x"},
    )
    raw["relayEnvelope"].pop("enc")  # relay strips the encapsulated key
    with pytest.raises(_burnbar._RelayPlaintextRefused):
        adapter._sealer.open_event(raw)


@requires_relay
def test_open_event_refuses_v3_frame_without_hpke_marker(monkeypatch):
    phone = relay_e2ee.generate_private_key()
    agent = relay_e2ee.generate_private_key()
    adapter = _paired_adapter(monkeypatch, peer_priv=phone, agent_priv=agent, peer_version="3")

    raw = _phone_to_agent_v3_event(
        agent_pub_b64=agent.public_key_base64(), phone_priv=phone,
        event_id="evt-3", payload={"text": "x"},
    )
    raw["relayEnvelope"]["relayEncryption"] = "p256-hkdf-sha256-aesgcm"  # wrong marker
    with pytest.raises(_burnbar._RelayPlaintextRefused):
        adapter._sealer.open_event(raw)


@requires_relay
@pytest.mark.parametrize("bad_version", [1, 0, "1", None])
def test_open_event_refuses_downgraded_version(monkeypatch, bad_version):
    phone = relay_e2ee.generate_private_key()
    agent = relay_e2ee.generate_private_key()
    adapter = _paired_adapter(monkeypatch, peer_priv=phone, agent_priv=agent, peer_version="3")

    raw = _phone_to_agent_v3_event(
        agent_pub_b64=agent.public_key_base64(), phone_priv=phone,
        event_id="evt-4", payload={"text": "x"},
    )
    raw["relayEnvelope"]["relayKeyVersion"] = bad_version  # relay downgrades the marker
    with pytest.raises(_burnbar._RelayPlaintextRefused):
        adapter._sealer.open_event(raw)


@requires_relay
def test_open_event_refuses_v3_frame_when_no_pin(monkeypatch):
    phone = relay_e2ee.generate_private_key()
    agent = relay_e2ee.generate_private_key()
    adapter = _paired_adapter(monkeypatch, peer_priv=phone, agent_priv=agent, peer_version="3")
    # Drop the pin: an authenticated open is impossible without the pinned sender.
    adapter._peer_public_key = None
    adapter._peer_public_keys = {}

    raw = _phone_to_agent_v3_event(
        agent_pub_b64=agent.public_key_base64(), phone_priv=phone,
        event_id="evt-5", payload={"text": "x"},
    )
    with pytest.raises(_burnbar._RelayPlaintextRefused):
        adapter._sealer.open_event(raw)


@requires_relay
def test_open_event_refuses_v3_frame_from_wrong_sender(monkeypatch):
    phone = relay_e2ee.generate_private_key()
    agent = relay_e2ee.generate_private_key()
    attacker = relay_e2ee.generate_private_key()
    adapter = _paired_adapter(monkeypatch, peer_priv=phone, agent_priv=agent, peer_version="3")

    # The attacker seals a valid v3 frame to the agent but is NOT the pinned phone.
    raw = _phone_to_agent_v3_event(
        agent_pub_b64=agent.public_key_base64(), phone_priv=attacker,
        event_id="evt-6", payload={"text": "forged"},
    )
    # Narrow to InvalidTag: the forgery must be caught by the authenticated HPKE
    # AuthDecap against the pinned sender, NOT by an upstream marker/enc/pin check
    # (which would let the test pass vacuously if the AEAD auth ever regressed).
    from cryptography.exceptions import InvalidTag

    with pytest.raises(InvalidTag):
        adapter._sealer.open_event(raw)


@requires_relay
def test_open_event_refuses_v3_to_v2_relabel(monkeypatch):
    """A relay relabelling a v3 frame as v2 (to dodge the v3 enc/marker checks and
    route the 48-byte HPKE body into the v2 2-DH unwrap) must fail closed."""
    phone = relay_e2ee.generate_private_key()
    agent = relay_e2ee.generate_private_key()
    adapter = _paired_adapter(monkeypatch, peer_priv=phone, agent_priv=agent, peer_version="3")

    raw = _phone_to_agent_v3_event(
        agent_pub_b64=agent.public_key_base64(), phone_priv=phone,
        event_id="evt-relabel", payload={"text": "x"},
    )
    # Keep the HPKE enc + 48-byte HPKE wrappedKey but relabel as v2.
    raw["relayEnvelope"]["relayKeyVersion"] = 2
    raw["relayEnvelope"]["relayEncryption"] = "p256-hkdf-sha256-aesgcm"
    with pytest.raises(
        (_burnbar._RelayPlaintextRefused, relay_e2ee.InvalidCiphertextError)
    ):
        adapter._sealer.open_event(raw)


# --- negotiation: pairing grant upgrades, runtime never does ----------------
@requires_relay
def test_pairing_grant_selects_v3_runtime_does_not():
    grant = {"gatewayRelayKeyVersion": 3, "relayCapable": True}
    assert _burnbar._peer_relay_key_version_from_pairing_grant(grant, {}) == 3
    # Unknown / missing / v1 floor to v2.
    assert _burnbar._peer_relay_key_version_from_pairing_grant({}, {}) == 2
    assert _burnbar._peer_relay_key_version_from_pairing_grant({"gatewayRelayKeyVersion": 1}, {}) == 2
    assert _burnbar._peer_relay_key_version_from_pairing_grant({"gatewayRelayKeyVersion": 99}, {}) == 2
    # Encryption-marker fallback also reaches v3.
    assert _burnbar._peer_relay_key_version_from_pairing_grant(
        {"gatewayRelayEncryption": relay_e2ee.HPKE_ALGORITHM}, {}
    ) == 3


@requires_relay
def test_coerce_peer_relay_key_version_floors_unknown():
    assert _burnbar._coerce_peer_relay_key_version("3") == 3
    assert _burnbar._coerce_peer_relay_key_version(2) == 2
    assert _burnbar._coerce_peer_relay_key_version(1) == 2
    assert _burnbar._coerce_peer_relay_key_version("garbage") == 2
    assert _burnbar._coerce_peer_relay_key_version(None) == 2


# --- break-glass rollback ----------------------------------------------------
@requires_relay
def test_break_glass_disables_v3_emission(monkeypatch):
    phone = relay_e2ee.generate_private_key()
    agent = relay_e2ee.generate_private_key()
    adapter = _paired_adapter(monkeypatch, peer_priv=phone, agent_priv=agent, peer_version="3")
    monkeypatch.setenv("BURNBAR_DISABLE_GATEWAY_HPKE_V3", "1")

    # Even with the v3 pin, emission floors to v2 while the break-glass flag is set.
    assert adapter._peer_relay_key_version_for("burnbar:home") == 2
    env = adapter._sealer.seal_message(destination_id="burnbar:home", text="rolled back")
    assert env["relayKeyVersion"] == 2 and "enc" not in env


@requires_relay
def test_capability_payload_advertises_v3_by_default(monkeypatch):
    monkeypatch.delenv("BURNBAR_DISABLE_GATEWAY_HPKE_V3", raising=False)
    cap = _burnbar._gateway_relay_capability_payload()
    assert cap["supportsHpkeV3"] is True
    assert 3 in cap["supportsRelayEnvelopeVersions"]
    assert cap["preferredRelayEnvelopeVersion"] == 3


@requires_relay
def test_capability_payload_v2_only_when_disabled(monkeypatch):
    monkeypatch.setenv("BURNBAR_DISABLE_GATEWAY_HPKE_V3", "1")
    cap = _burnbar._gateway_relay_capability_payload()
    assert cap["supportsHpkeV3"] is False
    assert cap["supportsRelayEnvelopeVersions"] == [2]
    assert cap["preferredRelayEnvelopeVersion"] == 2
