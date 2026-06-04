"""Adapter-level RFC 9180 HPKE v3 gateway behaviour.

Proves the BurnBar adapter's v3 gate end-to-end at the ``_RelaySealer`` seam:

* EMITS v3 only when the peer's authenticated capability advertises it, and a
  default (v2-only) peer keeps getting a byte-stable v2 envelope.
* OPENS a phone-sealed v3 event by binding the PINNED sender (never the wire
  ``senderPublicKey``), and refuses a v3 frame forged by an unpinned sender.
* REJECTS a relay downgrade of a v3 envelope — stripped version, coerced to v1,
  coerced to v2, or missing ``enc`` — all fail closed.

Kept in a dedicated file so it does not contend with the large shared
``test_burnbar_plugin.py`` surface owned by the messaging tests.
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
except Exception:  # pragma: no cover - cryptography missing in CI slice.
    relay_e2ee = None
    RELAY_CRYPTO_AVAILABLE = False

requires_relay = pytest.mark.skipif(
    not RELAY_CRYPTO_AVAILABLE, reason="cryptography / relay_e2ee unavailable"
)

_UID = "uid-1"
_CLIENT = "client-1"
_DEST = "burnbar:home"


class _FakeResponse:
    def __init__(self, json_body=None, status_code=200, content=b"{}"):
        self._json = json_body if json_body is not None else {}
        self.status_code = status_code
        self.content = content

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._json


class _RecordingClient:
    def __init__(self, *, post_responses=None):
        self.post_responses = post_responses or {}
        self.posts = []

    async def post(self, url, headers=None, json=None):
        self.posts.append((url, json))
        for suffix, response in self.post_responses.items():
            if url.endswith(suffix):
                return response(json) if callable(response) else response
        return _FakeResponse({})


def _e2e_adapter(monkeypatch, tmp_path, *, peer_public_key=None, peer_key_version=None):
    """An adapter forced into E2E mode with an injected agent identity.

    ``peer_key_version`` sets the resolved peer wrap capability directly (the
    same value the authenticated ``BURNBAR_RELAY_PEER_KEY_VERSION`` pin would
    produce), so a test can opt a link into v3 without the env round-trip.
    """
    monkeypatch.setattr(_burnbar, "CURSOR_FILE", tmp_path / "cursor.json")
    monkeypatch.setattr(_burnbar, "REPLAY_LEDGER_FILE", tmp_path / "replay.json")
    monkeypatch.delenv("BURNBAR_RELAY_E2E", raising=False)
    monkeypatch.delenv("BURNBAR_RELAY_PEER_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("BURNBAR_RELAY_PEER_KEY_VERSION", raising=False)
    cfg = PlatformConfig(enabled=True, extra={"access_token": "tok", "home_channel": _DEST})
    adapter = BurnBarAdapter(cfg)
    agent_priv = relay_e2ee.generate_private_key()
    adapter._relay_identity = relay_e2ee.AgentRelayIdentity(agent_priv)
    adapter._relay_e2e_enabled = True
    adapter._relay_uid = _UID
    adapter._relay_client_id = _CLIENT
    adapter._relay_uid_pinned = True
    adapter._relay_client_id_pinned = True
    adapter._relay_e2e_config_error = None
    if peer_public_key:
        adapter._peer_public_key = peer_public_key
    if peer_key_version is not None:
        adapter._peer_relay_key_version_default = peer_key_version
    adapter._load_replay_ledger(reset=True)
    return adapter, agent_priv


def _sealer(adapter):
    return _burnbar._RelaySealer(adapter)


def _phone_sealed_event_v3(
    adapter, sender_priv, event_id, payload, *, relay_key_version=3, include_enc=True
):
    """Build a phone->agent v3 (HPKE Auth) sealed event document."""
    sender_pub = sender_priv.public_key_base64()
    agent_pub = adapter._relay_public_key_base64()
    body = {"destinationId": _DEST}
    body.update(payload)
    payload_aad = _burnbar._gateway_event_aad(_UID, _CLIENT, event_id)
    key_aad = _burnbar._gateway_event_key_aad(_UID, _CLIENT, event_id)
    sym = relay_e2ee.generate_symmetric_key()
    payload_ct = relay_e2ee.seal_to_base64(json.dumps(body).encode(), sym, payload_aad)
    wrap = relay_e2ee.wrap_symmetric_key_v3(sym, agent_pub, key_aad, sender_private=sender_priv)
    envelope = {
        "eventId": event_id,
        "payloadCiphertext": payload_ct,
        "wrappedKey": wrap.wrapped_key,
        "senderPublicKey": sender_pub,
        "relayEncryption": _burnbar.GATEWAY_RELAY_ENCRYPTION_V3,
        "relayKeyVersion": relay_key_version,
    }
    if include_enc:
        envelope["enc"] = wrap.enc
    return {
        "id": event_id,
        "destinationId": _DEST,
        "senderPublicKey": sender_pub,
        "relayKeyVersion": relay_key_version,
        "relayEnvelope": envelope,
    }


# --- capability resolution ---------------------------------------------------


@requires_relay
def test_coerce_peer_relay_key_version_floors_unsupported():
    coerce = _burnbar._coerce_peer_relay_key_version
    assert coerce("3") == 3
    assert coerce(3) == 3
    assert coerce("2") == 2
    assert coerce(None) == 2
    assert coerce("1") == 2  # v1 is unsupported on the gateway -> floor to v2
    assert coerce("9") == 2  # unknown future version -> floor to v2
    assert coerce("garbage") == 2


@requires_relay
def test_capability_resolver_defaults_to_v2(monkeypatch, tmp_path):
    adapter, _ = _e2e_adapter(monkeypatch, tmp_path)
    assert adapter._peer_relay_key_version_for(_DEST) == _burnbar.GATEWAY_RELAY_KEY_VERSION
    assert adapter._peer_relay_key_version_for(_DEST) == 2


@requires_relay
def test_capability_resolver_per_destination_override(monkeypatch, tmp_path):
    adapter, _ = _e2e_adapter(monkeypatch, tmp_path)
    adapter._peer_relay_key_versions[_DEST] = 3
    assert adapter._peer_relay_key_version_for(_DEST) == 3
    # A different destination still floors to the v2 default.
    assert adapter._peer_relay_key_version_for("burnbar:other") == 2


# --- send: v3 emission vs v2 fallback ----------------------------------------


@requires_relay
def test_seal_message_emits_v3_when_peer_advertises_v3(monkeypatch, tmp_path):
    phone_priv = relay_e2ee.generate_private_key()
    adapter, agent_priv = _e2e_adapter(
        monkeypatch, tmp_path, peer_public_key=phone_priv.public_key_base64(), peer_key_version=3
    )
    env = _sealer(adapter).seal_message(destination_id=_DEST, text="v3 reply")
    assert env["relayKeyVersion"] == _burnbar.GATEWAY_RELAY_KEY_VERSION_V3 == 3
    assert env["relayEncryption"] == _burnbar.GATEWAY_RELAY_ENCRYPTION_V3
    assert env["enc"]
    assert env["senderPublicKey"] == agent_priv.public_key_base64()
    # The phone opens the v3 wrap, binding the agent's pinned sender key.
    key_aad = _burnbar._gateway_message_key_aad(_UID, _CLIENT, env["messageId"])
    payload_aad = _burnbar._gateway_message_aad(_UID, _CLIENT, env["messageId"])
    sym = relay_e2ee.unwrap_symmetric_key_v3(
        env["enc"], env["wrappedKey"], phone_priv, key_aad,
        pinned_sender_public=env["senderPublicKey"],
    )
    opened = json.loads(relay_e2ee.open_base64(env["payloadCiphertext"], sym, payload_aad).decode())
    assert opened == {"text": "v3 reply", "destinationId": _DEST}


@requires_relay
@pytest.mark.asyncio
async def test_send_message_v3_mirrors_hpke_marker_in_body(monkeypatch, tmp_path):
    phone_priv = relay_e2ee.generate_private_key()
    adapter, _agent_priv = _e2e_adapter(
        monkeypatch,
        tmp_path,
        peer_public_key=phone_priv.public_key_base64(),
        peer_key_version=3,
    )
    client = _RecordingClient(
        post_responses={"/messages": _FakeResponse({"message": {"id": "m-v3"}})}
    )
    adapter._client = client

    result = await adapter.send(_DEST, "v3 body marker")

    assert result.success is True
    _, body = client.posts[-1]
    env = body["relayEnvelope"]
    assert env["relayKeyVersion"] == _burnbar.GATEWAY_RELAY_KEY_VERSION_V3
    assert env["relayEncryption"] == _burnbar.GATEWAY_RELAY_ENCRYPTION_V3
    assert body["relayEncryption"] == _burnbar.GATEWAY_RELAY_ENCRYPTION_V3
    assert "relayKeyVersion" not in body
    assert body["messageId"] == env["messageId"]


@requires_relay
def test_seal_message_falls_back_to_v2_for_default_peer(monkeypatch, tmp_path):
    phone_priv = relay_e2ee.generate_private_key()
    adapter, agent_priv = _e2e_adapter(
        monkeypatch, tmp_path, peer_public_key=phone_priv.public_key_base64()
    )
    env = _sealer(adapter).seal_message(destination_id=_DEST, text="v2 reply")
    assert env["relayKeyVersion"] == _burnbar.GATEWAY_RELAY_KEY_VERSION == 2
    assert "enc" not in env  # v2 packs the ephemeral into wrappedKey; no separate enc
    key_aad = _burnbar._gateway_message_key_aad(_UID, _CLIENT, env["messageId"])
    payload_aad = _burnbar._gateway_message_aad(_UID, _CLIENT, env["messageId"])
    sym = relay_e2ee.unwrap_symmetric_key(
        env["wrappedKey"], phone_priv, key_aad, sender_public_base64=env["senderPublicKey"]
    )
    opened = json.loads(relay_e2ee.open_base64(env["payloadCiphertext"], sym, payload_aad).decode())
    assert opened == {"text": "v2 reply", "destinationId": _DEST}


@requires_relay
def test_seal_model_switch_emits_v3_when_advertised(monkeypatch, tmp_path):
    phone_priv = relay_e2ee.generate_private_key()
    adapter, _ = _e2e_adapter(
        monkeypatch, tmp_path, peer_public_key=phone_priv.public_key_base64(), peer_key_version=3
    )
    env = _sealer(adapter).seal_model_switch(destination_id=_DEST, model_id="claude-opus-4-8")
    assert env["relayKeyVersion"] == 3 and env["enc"]
    key_aad = _burnbar._gateway_event_key_aad(_UID, _CLIENT, env["eventId"])
    payload_aad = _burnbar._gateway_event_aad(_UID, _CLIENT, env["eventId"])
    sym = relay_e2ee.unwrap_symmetric_key_v3(
        env["enc"], env["wrappedKey"], phone_priv, key_aad,
        pinned_sender_public=env["senderPublicKey"],
    )
    opened = json.loads(relay_e2ee.open_base64(env["payloadCiphertext"], sym, payload_aad).decode())
    assert opened["modelId"] == "claude-opus-4-8"


@requires_relay
def test_seal_attachment_emits_v3_when_advertised(monkeypatch, tmp_path):
    phone_priv = relay_e2ee.generate_private_key()
    adapter, _ = _e2e_adapter(
        monkeypatch, tmp_path, peer_public_key=phone_priv.public_key_base64(), peer_key_version=3
    )
    f = tmp_path / "report.txt"
    f.write_bytes(b"PDF-BYTES-1234567890")
    env, body_bytes = _sealer(adapter).seal_attachment(
        destination_id=_DEST, file_path=f, content_type="text/plain"
    )
    assert env["relayKeyVersion"] == 3 and env["enc"]
    key_aad = _burnbar._gateway_attachment_key_aad(_UID, _CLIENT, env["attachmentId"])
    manifest_aad = _burnbar._gateway_attachment_manifest_aad(_UID, _CLIENT, env["attachmentId"])
    body_aad = _burnbar._gateway_attachment_body_aad(_UID, _CLIENT, env["attachmentId"])
    body_key = relay_e2ee.unwrap_symmetric_key_v3(
        env["enc"], env["wrappedKey"], phone_priv, key_aad,
        pinned_sender_public=env["senderPublicKey"],
    )
    manifest = json.loads(
        relay_e2ee.open_base64(env["payloadCiphertext"], body_key, manifest_aad).decode()
    )
    assert manifest["fileName"] == "report.txt"
    body = relay_e2ee.open_base64(body_bytes.decode("ascii"), body_key, body_aad)
    assert body == b"PDF-BYTES-1234567890"


@requires_relay
@pytest.mark.asyncio
async def test_runtime_status_advertises_gateway_v3_capability(monkeypatch, tmp_path):
    adapter, agent_priv = _e2e_adapter(monkeypatch, tmp_path)
    adapter._client = _RecordingClient()
    monkeypatch.setattr(_burnbar, "_runtime_status_payload", lambda: {"modelOptions": []})

    await adapter._publish_runtime_status(force=True)

    _, body = adapter._client.posts[-1]
    assert body["relayPublicKey"] == agent_priv.public_key_base64()
    assert body["relayKeyVersion"] == _burnbar.RELAY_KEY_VERSION
    assert body["relayEncryption"] == _burnbar.RELAY_ENCRYPTION
    assert body["gatewayRelayKeyVersion"] == _burnbar.GATEWAY_RELAY_KEY_VERSION_V3
    assert body["gatewayRelayEncryption"] == _burnbar.GATEWAY_RELAY_ENCRYPTION_V3
    assert body["supportedGatewayRelayKeyVersions"] == list(_burnbar._SUPPORTED_GATEWAY_RELAY_VERSIONS)


# --- open: pinned-sender binding + downgrade rejection ------------------------


@requires_relay
def test_agent_opens_phone_sealed_v3_event(monkeypatch, tmp_path):
    phone_priv = relay_e2ee.generate_private_key()
    adapter, _ = _e2e_adapter(
        monkeypatch, tmp_path, peer_public_key=phone_priv.public_key_base64()
    )
    raw = _phone_sealed_event_v3(
        adapter, phone_priv, "evt_v3_1", {"text": "open me v3", "replayCounter": 1}
    )
    opened = _sealer(adapter).open_event(raw)
    assert opened["text"] == "open me v3"


@requires_relay
def test_agent_opens_flattened_phone_sealed_v3_event(monkeypatch, tmp_path):
    """Some gateway responses flatten relayEnvelope fields onto the event.

    The compatibility shim must preserve v3's separate `enc`, relayEncryption,
    relayKeyVersion, and senderPublicKey fields before dispatching to HPKE open.
    """
    phone_priv = relay_e2ee.generate_private_key()
    adapter, _ = _e2e_adapter(
        monkeypatch, tmp_path, peer_public_key=phone_priv.public_key_base64()
    )
    nested = _phone_sealed_event_v3(
        adapter, phone_priv, "evt_v3_flat", {"text": "flat v3", "replayCounter": 1}
    )
    envelope = nested.pop("relayEnvelope")
    nested.update(envelope)
    opened = _sealer(adapter).open_event(nested)
    assert opened["text"] == "flat v3"


@requires_relay
def test_agent_refuses_v3_event_from_unpinned_sender(monkeypatch, tmp_path):
    """A v3 frame forged by an unpinned sender (riding its own senderPublicKey)
    fails closed: the open binds the PINNED phone key, not the wire field."""
    from cryptography.exceptions import InvalidTag

    phone_priv = relay_e2ee.generate_private_key()
    attacker = relay_e2ee.generate_private_key()
    adapter, _ = _e2e_adapter(
        monkeypatch, tmp_path, peer_public_key=phone_priv.public_key_base64()
    )
    raw = _phone_sealed_event_v3(
        adapter, attacker, "evt_v3_forge", {"text": "forged", "replayCounter": 1}
    )
    with pytest.raises(InvalidTag):
        _sealer(adapter).open_event(raw)


@requires_relay
def test_agent_refuses_v3_event_with_stripped_version(monkeypatch, tmp_path):
    phone_priv = relay_e2ee.generate_private_key()
    adapter, _ = _e2e_adapter(
        monkeypatch, tmp_path, peer_public_key=phone_priv.public_key_base64()
    )
    raw = _phone_sealed_event_v3(
        adapter, phone_priv, "evt_v3_strip", {"text": "x", "replayCounter": 1}
    )
    raw.pop("relayKeyVersion", None)
    raw["relayEnvelope"].pop("relayKeyVersion", None)
    with pytest.raises(_burnbar._RelayPlaintextRefused):
        _sealer(adapter).open_event(raw)


@requires_relay
def test_agent_refuses_v3_event_downgraded_to_v1(monkeypatch, tmp_path):
    phone_priv = relay_e2ee.generate_private_key()
    adapter, _ = _e2e_adapter(
        monkeypatch, tmp_path, peer_public_key=phone_priv.public_key_base64()
    )
    raw = _phone_sealed_event_v3(
        adapter, phone_priv, "evt_v3_v1", {"text": "x", "replayCounter": 1}, relay_key_version=1
    )
    with pytest.raises(_burnbar._RelayPlaintextRefused):
        _sealer(adapter).open_event(raw)


@requires_relay
def test_agent_refuses_v3_event_coerced_to_v2(monkeypatch, tmp_path):
    """Relabelling a v3 envelope as v2 routes it to the v2 unwrap, where the
    48-byte HPKE ciphertext is not a valid v2 envelope -> fail closed."""
    phone_priv = relay_e2ee.generate_private_key()
    adapter, _ = _e2e_adapter(
        monkeypatch, tmp_path, peer_public_key=phone_priv.public_key_base64()
    )
    raw = _phone_sealed_event_v3(
        adapter, phone_priv, "evt_v3_v2", {"text": "x", "replayCounter": 1}, relay_key_version=2
    )
    with pytest.raises(relay_e2ee.RelayCryptoError):
        _sealer(adapter).open_event(raw)


@requires_relay
def test_agent_refuses_v3_event_missing_enc(monkeypatch, tmp_path):
    phone_priv = relay_e2ee.generate_private_key()
    adapter, _ = _e2e_adapter(
        monkeypatch, tmp_path, peer_public_key=phone_priv.public_key_base64()
    )
    raw = _phone_sealed_event_v3(
        adapter, phone_priv, "evt_v3_noenc", {"text": "x", "replayCounter": 1}, include_enc=False
    )
    with pytest.raises(_burnbar._RelayPlaintextRefused):
        _sealer(adapter).open_event(raw)


@requires_relay
def test_agent_refuses_v3_event_missing_relay_encryption_marker(monkeypatch, tmp_path):
    phone_priv = relay_e2ee.generate_private_key()
    adapter, _ = _e2e_adapter(
        monkeypatch, tmp_path, peer_public_key=phone_priv.public_key_base64()
    )
    raw = _phone_sealed_event_v3(
        adapter, phone_priv, "evt_v3_nomarker", {"text": "x", "replayCounter": 1}
    )
    raw["relayEnvelope"].pop("relayEncryption", None)
    with pytest.raises(_burnbar._RelayPlaintextRefused):
        _sealer(adapter).open_event(raw)


@requires_relay
def test_agent_still_opens_v2_event_after_v3_added(monkeypatch, tmp_path):
    """v2 receive compatibility is intact: a v2-sealed event still opens."""
    phone_priv = relay_e2ee.generate_private_key()
    adapter, _ = _e2e_adapter(
        monkeypatch, tmp_path, peer_public_key=phone_priv.public_key_base64()
    )
    event_id = "evt_v2_compat"
    payload_aad = _burnbar._gateway_event_aad(_UID, _CLIENT, event_id)
    key_aad = _burnbar._gateway_event_key_aad(_UID, _CLIENT, event_id)
    sym = relay_e2ee.generate_symmetric_key()
    payload_ct = relay_e2ee.seal_to_base64(
        json.dumps({"text": "legacy v2", "destinationId": _DEST, "replayCounter": 1}).encode(),
        sym,
        payload_aad,
    )
    wrapped = relay_e2ee.wrap_symmetric_key(
        sym, adapter._relay_public_key_base64(), key_aad, sender_private=phone_priv
    )
    raw = {
        "id": event_id,
        "destinationId": _DEST,
        "senderPublicKey": phone_priv.public_key_base64(),
        "relayKeyVersion": _burnbar.GATEWAY_RELAY_KEY_VERSION,
        "relayEnvelope": {
            "eventId": event_id,
            "payloadCiphertext": payload_ct,
            "wrappedKey": wrapped,
            "senderPublicKey": phone_priv.public_key_base64(),
            "relayEncryption": _burnbar.RELAY_ENCRYPTION,
            "relayKeyVersion": _burnbar.GATEWAY_RELAY_KEY_VERSION,
        },
    }
    opened = _sealer(adapter).open_event(raw)
    assert opened["text"] == "legacy v2"
