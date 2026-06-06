"""Attachment body-key PQ wrap upgrade (closes audit 'Finding B').

The file BODY was always AES-256-GCM sealed (PQ-safe); only the body-KEY transport
was classical (v3 HPKE) even on a v5-pinned link. These tests prove the upgraded
``seal_attachment`` carries the body key inside a v4/v5 SIGNED manifest (hybrid-KEM
wrapped at v5), is capability-negotiated so it never bricks a legacy phone, fails
closed on a v5 pin rather than silently shipping a classical body key, and is
non-forgeable. Reference-opens the agent's own output the way the phone would.

Run: pytest tests/gateway/test_v5_attachment_wrap.py -q
"""

from __future__ import annotations

import base64
import json

import pytest

from tests.gateway.test_burnbar_plugin_v5 import (
    _burnbar,
    relay_e2ee,
    v4,
    v5,
    _UID,
    _CLIENT,
    _keys,
    _paired_v5_adapter,
    RELAY_V5_AVAILABLE,
)

requires_v5 = pytest.mark.skipif(
    not RELAY_V5_AVAILABLE, reason="cryptography HPKE MLKEM768_X25519 unavailable"
)


@pytest.fixture(autouse=True)
def _isolate_state_files(monkeypatch, tmp_path):
    monkeypatch.setattr(_burnbar, "RATCHET_SESSION_FILE", tmp_path / "ratchet.json", raising=False)
    monkeypatch.setattr(_burnbar, "REPLAY_LEDGER_FILE", tmp_path / "ledger.json", raising=False)
    monkeypatch.setattr(_burnbar, "BURNBAR_E2EE_STATE_FILE", tmp_path / "e2ee.json", raising=False)
    monkeypatch.setattr(_burnbar, "CURSOR_FILE", tmp_path / "cursor.json", raising=False)
    (tmp_path / "ledger.json").write_text("{}")


def _attach_capable_v5_adapter(monkeypatch, k, *, caps="4,5"):
    monkeypatch.setenv("BURNBAR_RELAY_PEER_ATTACHMENT_WRAP_VERSIONS", caps)
    monkeypatch.delenv("BURNBAR_ALLOW_CLASSICAL_ATTACHMENTS", raising=False)
    return _paired_v5_adapter(monkeypatch, **k)


def _write_file(tmp_path, name, content: bytes):
    p = tmp_path / name
    p.write_bytes(content)
    return p


def _phone_open_attachment(envelope, body_bytes, k, *, version):
    """Open the agent's sealed attachment the way the phone would: open the signed
    manifest -> extract the body key -> open the separately-sealed body blob."""
    attachment_id = envelope["attachmentId"]
    key_aad = _burnbar._gateway_attachment_key_aad(_UID, _CLIENT, attachment_id)
    manifest_aad = _burnbar._gateway_attachment_manifest_aad(_UID, _CLIENT, attachment_id)
    body_aad = _burnbar._gateway_attachment_body_aad(_UID, _CLIENT, attachment_id)
    if version == 5:
        manifest_pt = v5.open_signed_v5(
            envelope,
            recipient_kem_private=k["phone_kem"],
            recipient_verify_key=k["phone_sig"].public_key_base64(),
            pinned_sender_verify_key=k["agent_sig"].public_key_base64(),
            key_aad=key_aad, payload_aad=manifest_aad,
        )
    else:
        manifest_pt = v4.open_signed_v4(
            envelope,
            recipient_enc_private=k["phone_enc"],
            recipient_verify_key=k["phone_sig"].public_key_base64(),
            pinned_sender_enc_public=k["agent_enc"].public_key_base64(),
            pinned_sender_verify_key=k["agent_sig"].public_key_base64(),
            key_aad=key_aad, payload_aad=manifest_aad,
        )
    manifest = json.loads(manifest_pt)
    body_key = base64.b64decode(manifest["bodyKeyBase64"], validate=True)
    plaintext = relay_e2ee.open_base64(body_bytes.decode("ascii"), body_key, body_aad)
    return manifest, plaintext


# ── Round-trip: v5 (hybrid-KEM) and v4 (classical-but-signed) attachment wraps. ─
@requires_v5
def test_attachment_v5_roundtrip_body_key_is_pq_wrapped(monkeypatch, tmp_path):
    k = _keys()
    adapter = _attach_capable_v5_adapter(monkeypatch, k, caps="4,5")
    payload = b"top secret file contents \x00\x01\x02" * 50
    f = _write_file(tmp_path, "secret.bin", payload)
    env, body = adapter._sealer.seal_attachment(
        destination_id="burnbar:home", file_path=f, content_type="application/octet-stream"
    )
    assert env["relayKeyVersion"] == 5
    assert env["relayEncryption"] == v5.RELAY_ENCRYPTION_V5
    # The body key is NOT a top-level wire field; it rides inside the v5-sealed manifest.
    assert "bodyKeyBase64" not in env
    manifest, opened = _phone_open_attachment(env, body, k, version=5)
    assert opened == payload
    assert manifest["fileName"] == "secret.bin"
    assert manifest["byteCount"] == len(payload)


@requires_v5
def test_attachment_v4_roundtrip(monkeypatch, tmp_path):
    k = _keys()
    adapter = _attach_capable_v5_adapter(monkeypatch, k, caps="4")
    # The helper pins v5; override the resolved pin/floor to v4 to exercise the v4
    # signed-attachment path (no PQ floor, so v4 is allowed).
    adapter._peer_relay_key_version_default = 4
    adapter._peer_relay_key_version_floor_default = 4
    payload = b"v4 signed attachment body" * 20
    f = _write_file(tmp_path, "v4.bin", payload)
    env, body = adapter._sealer.seal_attachment(
        destination_id="burnbar:home", file_path=f, content_type="application/octet-stream"
    )
    assert env["relayKeyVersion"] == 4
    manifest, opened = _phone_open_attachment(env, body, k, version=4)
    assert opened == payload


# ── Capability gating: a peer that never advertised attachment-open caps keeps the
# legacy v3 wrap (byte-stable) — upgrading must never brick such a peer. Use a v4
# message pin so the legacy classical wrap is allowed (no PQ floor). ──────────────
@requires_v5
def test_attachment_legacy_v3_when_peer_not_capable(monkeypatch, tmp_path):
    k = _keys()
    monkeypatch.delenv("BURNBAR_RELAY_PEER_ATTACHMENT_WRAP_VERSIONS", raising=False)
    monkeypatch.delenv("BURNBAR_ALLOW_CLASSICAL_ATTACHMENTS", raising=False)
    adapter = _paired_v5_adapter(monkeypatch, **k)
    # Drop the pin/floor to v4 so the legacy classical wrap is allowed (no PQ floor).
    adapter._peer_relay_key_version_default = 4
    adapter._peer_relay_key_version_floor_default = 4
    f = _write_file(tmp_path, "legacy.bin", b"legacy body" * 10)
    env, _body = adapter._sealer.seal_attachment(
        destination_id="burnbar:home", file_path=f, content_type="application/octet-stream"
    )
    assert env["relayKeyVersion"] == 3  # unchanged classical wrap
    assert "senderSig" not in env       # legacy lane has no Ed25519 signature


# ── Stopgap: a v5-pinned link must NOT silently ship a classical file body when the
# peer cannot open a v5 attachment wrap. Fail closed. ────────────────────────────
@requires_v5
def test_attachment_v5_pin_fails_closed_without_peer_caps(monkeypatch, tmp_path):
    k = _keys()
    monkeypatch.delenv("BURNBAR_RELAY_PEER_ATTACHMENT_WRAP_VERSIONS", raising=False)
    monkeypatch.delenv("BURNBAR_ALLOW_CLASSICAL_ATTACHMENTS", raising=False)
    adapter = _paired_v5_adapter(monkeypatch, **k)  # v5-pinned, floor v5
    assert adapter._peer_relay_key_version_floor_for("burnbar:home") == 5
    f = _write_file(tmp_path, "x.bin", b"must not leak classically")
    with pytest.raises(_burnbar._RelayPlaintextRefused):
        adapter._sealer.seal_attachment(
            destination_id="burnbar:home", file_path=f, content_type="application/octet-stream"
        )


@requires_v5
def test_attachment_v5_pin_escape_hatch_allows_classical(monkeypatch, tmp_path):
    k = _keys()
    monkeypatch.delenv("BURNBAR_RELAY_PEER_ATTACHMENT_WRAP_VERSIONS", raising=False)
    monkeypatch.setenv("BURNBAR_ALLOW_CLASSICAL_ATTACHMENTS", "1")
    adapter = _paired_v5_adapter(monkeypatch, **k)
    f = _write_file(tmp_path, "x.bin", b"operator accepted classical")
    env, _body = adapter._sealer.seal_attachment(
        destination_id="burnbar:home", file_path=f, content_type="application/octet-stream"
    )
    assert env["relayKeyVersion"] == 3  # explicit, logged classical fallback


# ── Capability advertisement: a v5-capable agent advertises attachment wrap caps. ─
@requires_v5
def test_capability_payload_advertises_attachment_wrap(monkeypatch):
    k = _keys()
    adapter = _attach_capable_v5_adapter(monkeypatch, k)
    cap = _burnbar._gateway_relay_capability_payload(
        adapter._ratchet_init_public_key_for_advertisement(),
        adapter._relay_kem_public_key_base64(),
    )
    assert cap["supportsSignedAttachmentWrap"] is True
    assert 5 in cap["supportsGatewayAttachmentWrapVersions"]
    assert 4 in cap["supportsGatewayAttachmentWrapVersions"]
    assert 2 not in cap["supportsGatewayAttachmentWrapVersions"]
    assert 3 not in cap["supportsGatewayAttachmentWrapVersions"]


# ── Adversarial: a tampered manifest signature is refused (forgery). ─────────────
@requires_v5
def test_attachment_v5_forged_signature_refused(monkeypatch, tmp_path):
    k = _keys()
    adapter = _attach_capable_v5_adapter(monkeypatch, k)
    f = _write_file(tmp_path, "x.bin", b"authentic body")
    env, body = adapter._sealer.seal_attachment(
        destination_id="burnbar:home", file_path=f, content_type="application/octet-stream"
    )
    bad = dict(env)
    sig = bytearray(base64.b64decode(bad["senderSig"]))
    sig[0] ^= 1
    bad["senderSig"] = base64.b64encode(bytes(sig)).decode("ascii")
    with pytest.raises(v5.RelayV5SignatureError):
        _phone_open_attachment(bad, body, k, version=5)


# ── Adversarial: a relay swapping the body blob fails the body AEAD (it lacks the
# body key, which is sealed inside the manifest). ───────────────────────────────
@requires_v5
def test_attachment_v5_body_swap_refused(monkeypatch, tmp_path):
    k = _keys()
    adapter = _attach_capable_v5_adapter(monkeypatch, k)
    f = _write_file(tmp_path, "x.bin", b"authentic body bytes")
    env, body = adapter._sealer.seal_attachment(
        destination_id="burnbar:home", file_path=f, content_type="application/octet-stream"
    )
    # Manifest still opens (signature valid), but the substituted body fails AEAD.
    forged_body = base64.b64encode(b"attacker-substituted blob that is not GCM-valid").decode("ascii").encode("ascii")
    with pytest.raises(Exception):
        _phone_open_attachment(env, forged_body, k, version=5)


# ── Adversarial: AAD domain separation — the body cannot be opened as the manifest
# (the signed manifest is bound to the manifest AAD; the body to the body AAD). ──
@requires_v5
def test_attachment_v5_manifest_body_aad_distinct(monkeypatch, tmp_path):
    k = _keys()
    adapter = _attach_capable_v5_adapter(monkeypatch, k)
    f = _write_file(tmp_path, "x.bin", b"body under body AAD only")
    env, body = adapter._sealer.seal_attachment(
        destination_id="burnbar:home", file_path=f, content_type="application/octet-stream"
    )
    manifest, opened = _phone_open_attachment(env, body, k, version=5)
    body_key = base64.b64decode(manifest["bodyKeyBase64"], validate=True)
    attachment_id = env["attachmentId"]
    # Opening the body under the MANIFEST aad (wrong domain) must fail the tag.
    with pytest.raises(Exception):
        relay_e2ee.open_base64(
            body.decode("ascii"),
            body_key,
            _burnbar._gateway_attachment_manifest_aad(_UID, _CLIENT, attachment_id),
        )
