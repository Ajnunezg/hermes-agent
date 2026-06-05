"""Generate the canonical BurnBar HPKE v3 cross-language vector fixture.

Run (writes ``tests/gateway/fixtures/BurnBarHpkeV3Vector.json``)::

    cd <hermes-agent checkout>
    venv/bin/python -m tests.gateway.vectors.generate_burnbar_hpke_v3_vectors

The vectors are byte-reproducible review fixtures: static recipient/sender
keypairs, per-case content keys, HPKE Auth ephemerals, and payload AES-GCM nonces
are all deterministic. Production still uses fresh random HPKE ephemerals and
payload nonces; determinism here exists only so BurnBar, Hermes, and Android can
share one exact fixture hash and reviewers can regenerate it locally.

Coordination: this is the canonical v3 fixture source. Regenerate it once, then
mirror the exact JSON bytes into BurnBar Core and Android test resources. The
remediation verifier fails if those three copies drift.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from tests.gateway.vectors import hpke_v3_reference as ref

# --- deterministic key + content-key material (mirrors the Swift fixture) ----

_AAD_PREFIX = "OpenBurnBar-HermesRelay-v1"
_UID = "u-hpke-v3"
_CLIENT_ID = "c-hpke-v3"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _deterministic_private_raw(tweak: int) -> bytes:
    """Mirror Swift ``makeDeterministicPrivateKey(tweak)``: scalar
    ``0x10 ‖ 0x42*30 ‖ tweak`` (top bit clear -> comfortably in [1, n-1])."""
    seed = bytearray([0x42] * 32)
    seed[0] = 0x10
    seed[31] = tweak
    return bytes(seed)


def _deterministic_content_key(tweak: int) -> bytes:
    """Mirror Swift ``makeDeterministicSymmetricKey(tweak)``."""
    return bytes((i * 7 + tweak) % 251 for i in range(32))


def _public_x963(private_raw: bytes) -> bytes:
    return ref.serialize_public(ref.private_from_raw(private_raw).public_key())


def _aad(*parts: str) -> str:
    return "|".join([_AAD_PREFIX, *parts])


# Agent (tweak 0x01) opens phone→agent frames; phone (tweak 0x02) opens
# agent→phone frames — identical to the v2 gateway vector roles.
_AGENT_PRIV = _deterministic_private_raw(0x01)
_PHONE_PRIV = _deterministic_private_raw(0x02)
_AGENT_PUB = _public_x963(_AGENT_PRIV)
_PHONE_PUB = _public_x963(_PHONE_PRIV)


def _wrap(
    content_key: bytes,
    recipient_pub: bytes,
    sender_priv: bytes,
    key_aad: str,
    *,
    ephemeral_tweak: int,
):
    return ref.wrap_content_key(
        content_key,
        recipient_pub,
        sender_priv,
        key_aad.encode(),
        ephemeral_private=ref.private_from_raw(_deterministic_private_raw(ephemeral_tweak)),
    )


def _payload_nonce(name: str) -> bytes:
    return hashlib.sha256(f"BurnBarHpkeV3PayloadNonce|{name}".encode("utf-8")).digest()[:12]


def _seal_payload(name: str, plaintext: str, content_key: bytes, payload_aad: str) -> str:
    return ref.seal_payload_base64(
        plaintext.encode(),
        content_key,
        payload_aad.encode(),
        nonce=_payload_nonce(name),
    )


def _positive_case(
    *,
    name: str,
    kind: str,
    direction: str,
    object_id_field: str,
    object_id: str,
    recipient_priv: bytes,
    recipient_pub: bytes,
    sender_priv: bytes,
    sender_pub: bytes,
    key_aad: str,
    payload_aad: str,
    payload_plaintext: str,
    content_key: bytes,
    enc_b64: str,
    wrapped_b64: str,
) -> dict:
    return {
        "name": name,
        "kind": kind,
        "direction": direction,
        "expected": "open",
        "uid": _UID,
        "clientId": _CLIENT_ID,
        object_id_field: object_id,
        "recipientPrivateKeyRaw": _b64(recipient_priv),
        "recipientPublicKeyX963": _b64(recipient_pub),
        # The PINNED sender static key bound at AuthDecap (the forgery defense).
        "pinnedSenderPublicKeyX963": _b64(sender_pub),
        # The wire/diagnostic copy of the sender key (== pinned here; a relay
        # could lie in this field and the open must still bind the pin).
        "senderPublicKeyX963": _b64(sender_pub),
        "keyAAD": key_aad,
        "info": ref.info_for(key_aad.encode()).decode(),
        "enc": enc_b64,
        "wrappedKey": wrapped_b64,
        "plaintextContentKey": _b64(content_key),
        "payloadAAD": payload_aad,
        "payloadCiphertext": _seal_payload(name, payload_plaintext, content_key, payload_aad),
        "payloadPlaintext": payload_plaintext,
        "relayKeyVersion": ref.RELAY_KEY_VERSION_V3,
        "relayEncryption": ref.RELAY_ENCRYPTION_V3,
    }


def _build_positive_cases() -> list[dict]:
    cases: list[dict] = []

    # 1) phone -> agent EVENT (text/chat)
    event_id = "e-hpke-v3"
    event_key = _deterministic_content_key(0x11)
    e_enc, e_wrapped = _wrap(
        event_key,
        _AGENT_PUB,
        _PHONE_PRIV,
        _aad("gatewayEventKey", _UID, _CLIENT_ID, event_id),
        ephemeral_tweak=0xE1,
    )
    cases.append(
        _positive_case(
            name="phone_event_text",
            kind="event",
            direction="phone_to_agent",
            object_id_field="eventId",
            object_id=event_id,
            recipient_priv=_AGENT_PRIV,
            recipient_pub=_AGENT_PUB,
            sender_priv=_PHONE_PRIV,
            sender_pub=_PHONE_PUB,
            key_aad=_aad("gatewayEventKey", _UID, _CLIENT_ID, event_id),
            payload_aad=_aad("gatewayEvent", _UID, _CLIENT_ID, event_id),
            payload_plaintext=(
                '{"text":"open the BurnBar gateway","kind":"chat",'
                '"destinationId":"burnbar:home","replayCounter":1}'
            ),
            content_key=event_key,
            enc_b64=e_enc,
            wrapped_b64=e_wrapped,
        )
    )

    # 2) phone -> agent EVENT (model_switch — reuses the gatewayEvent AADs)
    ms_id = "e-model-switch-v3"
    ms_key = _deterministic_content_key(0x33)
    ms_enc, ms_wrapped = _wrap(
        ms_key,
        _AGENT_PUB,
        _PHONE_PRIV,
        _aad("gatewayEventKey", _UID, _CLIENT_ID, ms_id),
        ephemeral_tweak=0xE2,
    )
    cases.append(
        _positive_case(
            name="phone_event_model_switch",
            kind="model_switch",
            direction="phone_to_agent",
            object_id_field="eventId",
            object_id=ms_id,
            recipient_priv=_AGENT_PRIV,
            recipient_pub=_AGENT_PUB,
            sender_priv=_PHONE_PRIV,
            sender_pub=_PHONE_PUB,
            key_aad=_aad("gatewayEventKey", _UID, _CLIENT_ID, ms_id),
            payload_aad=_aad("gatewayEvent", _UID, _CLIENT_ID, ms_id),
            payload_plaintext=(
                '{"kind":"model_switch","modelId":"claude-opus-4-8",'
                '"destinationId":"burnbar:home","replayCounter":2}'
            ),
            content_key=ms_key,
            enc_b64=ms_enc,
            wrapped_b64=ms_wrapped,
        )
    )

    # 3) agent -> phone MESSAGE (reply text)
    message_id = "m-hpke-v3"
    msg_key = _deterministic_content_key(0x22)
    m_enc, m_wrapped = _wrap(
        msg_key,
        _PHONE_PUB,
        _AGENT_PRIV,
        _aad("gatewayMessageKey", _UID, _CLIENT_ID, message_id),
        ephemeral_tweak=0xE3,
    )
    cases.append(
        _positive_case(
            name="agent_reply_text",
            kind="message",
            direction="agent_to_phone",
            object_id_field="messageId",
            object_id=message_id,
            recipient_priv=_PHONE_PRIV,
            recipient_pub=_PHONE_PUB,
            sender_priv=_AGENT_PRIV,
            sender_pub=_AGENT_PUB,
            key_aad=_aad("gatewayMessageKey", _UID, _CLIENT_ID, message_id),
            payload_aad=_aad("gatewayMessage", _UID, _CLIENT_ID, message_id),
            payload_plaintext=(
                '{"text":"Hermes replied over the encrypted gateway.",'
                '"destinationId":"burnbar:home"}'
            ),
            content_key=msg_key,
            enc_b64=m_enc,
            wrapped_b64=m_wrapped,
        )
    )

    # 4 + 5) agent -> phone ATTACHMENT. ONE body key (HPKE-wrapped once) seals
    # BOTH the manifest and the body under DISTINCT payload AADs — so the two
    # required cases share enc/wrappedKey/content-key and differ only in the
    # sealed payload layer.
    attachment_id = "a-hpke-v3"
    body_key = _deterministic_content_key(0x44)
    a_key_aad = _aad("gatewayAttachmentKey", _UID, _CLIENT_ID, attachment_id)
    a_enc, a_wrapped = _wrap(
        body_key,
        _PHONE_PUB,
        _AGENT_PRIV,
        a_key_aad,
        ephemeral_tweak=0xE4,
    )
    cases.append(
        _positive_case(
            name="agent_reply_attachment_manifest",
            kind="attachment_manifest",
            direction="agent_to_phone",
            object_id_field="attachmentId",
            object_id=attachment_id,
            recipient_priv=_PHONE_PRIV,
            recipient_pub=_PHONE_PUB,
            sender_priv=_AGENT_PRIV,
            sender_pub=_AGENT_PUB,
            key_aad=a_key_aad,
            payload_aad=_aad("gatewayAttachmentManifest", _UID, _CLIENT_ID, attachment_id),
            payload_plaintext=(
                '{"fileName":"quarterly-report.pdf",'
                '"contentType":"application/pdf","byteCount":20,'
                '"destinationId":"burnbar:home"}'
            ),
            content_key=body_key,
            enc_b64=a_enc,
            wrapped_b64=a_wrapped,
        )
    )
    cases.append(
        _positive_case(
            name="agent_reply_attachment_body_key",
            kind="attachment_body_key",
            direction="agent_to_phone",
            object_id_field="attachmentId",
            object_id=attachment_id,
            recipient_priv=_PHONE_PRIV,
            recipient_pub=_PHONE_PUB,
            sender_priv=_AGENT_PRIV,
            sender_pub=_AGENT_PUB,
            key_aad=a_key_aad,
            payload_aad=_aad("gatewayAttachmentBody", _UID, _CLIENT_ID, attachment_id),
            payload_plaintext="PDF-BYTES-1234567890",
            content_key=body_key,
            enc_b64=a_enc,
            wrapped_b64=a_wrapped,
        )
    )
    return cases


def _flip_b64_byte(value_b64: str, index: int) -> str:
    raw = bytearray(base64.b64decode(value_b64))
    raw[index] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


def _build_negative_cases(positives: list[dict]) -> list[dict]:
    base = next(c for c in positives if c["name"] == "phone_event_text")
    # A wrong recipient: the phone key (the base frame is sealed to the AGENT).
    wrong_recipient_priv = _b64(_PHONE_PRIV)
    # A wrong pinned sender: the agent's own recipient key (not the phone).
    wrong_sender_pub = base["recipientPublicKeyX963"]
    # A VALID but wrong ephemeral point (on-curve) -> AuthDecap derives a wrong
    # shared secret -> AEAD InvalidTag (distinct from the off-curve mutated_enc,
    # which is rejected earlier at point validation).
    swapped_enc = _b64(
        ref.serialize_public(ref.private_from_raw(_deterministic_private_raw(0xE5)).public_key())
    )

    wrong_destination_id = "e-wrong-destination-v3"
    wrong_destination_key = _deterministic_content_key(0x55)
    wrong_destination_key_aad = _aad("gatewayEventKey", _UID, _CLIENT_ID, wrong_destination_id)
    wrong_destination_payload_aad = _aad("gatewayEvent", _UID, _CLIENT_ID, wrong_destination_id)
    wrong_destination_enc, wrong_destination_wrapped = _wrap(
        wrong_destination_key,
        _AGENT_PUB,
        _PHONE_PRIV,
        wrong_destination_key_aad,
        ephemeral_tweak=0xE6,
    )

    replay_rollback_id = "e-replay-rollback-v3"
    replay_rollback_key = _deterministic_content_key(0x66)
    replay_rollback_key_aad = _aad("gatewayEventKey", _UID, _CLIENT_ID, replay_rollback_id)
    replay_rollback_payload_aad = _aad("gatewayEvent", _UID, _CLIENT_ID, replay_rollback_id)
    replay_rollback_enc, replay_rollback_wrapped = _wrap(
        replay_rollback_key,
        _AGENT_PUB,
        _PHONE_PRIV,
        replay_rollback_key_aad,
        ephemeral_tweak=0xE7,
    )

    # ``expectedError`` is the reference v3-admission path's exact exception, so the
    # verifier asserts a tight per-negative type (never a broad ValueError that a
    # base64 artifact could satisfy). The end-to-end production downgrade/strip
    # fail-closure is proven separately against the real dispatch.
    return [
        {
            "name": "wrong_pinned_sender_key",
            "derivedFrom": base["name"],
            "mutation": "pinned_sender_public_key",
            "expected": "reject",
            "expectedError": "InvalidTag",
            "detail": "AuthDecap binds the wrong sender static key -> dh2/pkSm wrong -> InvalidTag.",
            "pinnedSenderPublicKeyX963Override": wrong_sender_pub,
        },
        {
            "name": "wrong_recipient_key",
            "derivedFrom": base["name"],
            "mutation": "recipient_private_key",
            "expected": "reject",
            "expectedError": "InvalidTag",
            "detail": "Opening with a non-recipient private key -> both DH legs wrong -> InvalidTag.",
            "recipientPrivateKeyRawOverride": wrong_recipient_priv,
        },
        {
            "name": "wrong_key_aad",
            "derivedFrom": base["name"],
            "mutation": "key_aad",
            "expected": "reject",
            "expectedError": "InvalidTag",
            "detail": "A mutated key_aad changes both HPKE info and AEAD aad -> InvalidTag.",
            "keyAADOverride": base["keyAAD"] + "|tampered",
        },
        {
            "name": "mutated_enc",
            "derivedFrom": base["name"],
            "mutation": "enc",
            "expected": "reject",
            "expectedError": "HpkeError",
            "detail": (
                "A single-byte flip of a valid X9.63 point yields an off-curve point, "
                "rejected at point validation (fail-closed, before any DH)."
            ),
            "encOverride": _flip_b64_byte(base["enc"], 40),
        },
        {
            "name": "swapped_enc_valid_point",
            "derivedFrom": base["name"],
            "mutation": "enc",
            "expected": "reject",
            "expectedError": "InvalidTag",
            "detail": (
                "A DIFFERENT valid ephemeral point -> AuthDecap derives a wrong shared "
                "secret -> AEAD InvalidTag (complements the off-curve mutated_enc)."
            ),
            "encOverride": swapped_enc,
        },
        {
            "name": "mutated_wrapped_key",
            "derivedFrom": base["name"],
            "mutation": "wrapped_key",
            "expected": "reject",
            "expectedError": "InvalidTag",
            "detail": "Flipping an HPKE ciphertext/tag byte -> AEAD tag check fails -> InvalidTag.",
            "wrappedKeyOverride": _flip_b64_byte(base["wrappedKey"], 0),
        },
        {
            "name": "wrong_destination",
            "derivedFrom": base["name"],
            "kind": "event",
            "direction": "phone_to_agent",
            "mutation": "authenticated_payload_destination",
            "expected": "reject",
            "expectedError": "PayloadPolicyError",
            "policyReject": "wrong_destination",
            "detail": (
                "The HPKE wrap and payload AEAD open, but the authenticated JSON "
                "destinationId is not the expected gateway destination -> the "
                "adapter must reject before dispatch."
            ),
            "uid": _UID,
            "clientId": _CLIENT_ID,
            "eventId": wrong_destination_id,
            "recipientPrivateKeyRaw": _b64(_AGENT_PRIV),
            "recipientPublicKeyX963": _b64(_AGENT_PUB),
            "pinnedSenderPublicKeyX963": _b64(_PHONE_PUB),
            "senderPublicKeyX963": _b64(_PHONE_PUB),
            "keyAAD": wrong_destination_key_aad,
            "info": ref.info_for(wrong_destination_key_aad.encode()).decode(),
            "enc": wrong_destination_enc,
            "wrappedKey": wrong_destination_wrapped,
            "plaintextContentKey": _b64(wrong_destination_key),
            "payloadAAD": wrong_destination_payload_aad,
            "payloadCiphertext": _seal_payload(
                "wrong_destination",
                (
                    '{"text":"wrong destination","kind":"chat",'
                    '"destinationId":"burnbar:other","replayCounter":3}'
                ),
                wrong_destination_key,
                wrong_destination_payload_aad,
            ),
            "payloadPlaintext": (
                '{"text":"wrong destination","kind":"chat",'
                '"destinationId":"burnbar:other","replayCounter":3}'
            ),
            "expectedDestinationId": "burnbar:home",
            "relayKeyVersion": ref.RELAY_KEY_VERSION_V3,
            "relayEncryption": ref.RELAY_ENCRYPTION_V3,
        },
        {
            "name": "replay_counter_rollback",
            "derivedFrom": "phone_event_model_switch",
            "kind": "event",
            "direction": "phone_to_agent",
            "mutation": "authenticated_replay_counter_rollback",
            "expected": "reject",
            "expectedError": "PayloadPolicyError",
            "policyReject": "replay_rollback",
            "detail": (
                "The HPKE wrap and payload AEAD open, but authenticated replayCounter=1 "
                "is at or below the prior high-water=2 for this paired client -> reject "
                "before dispatch even with a fresh event id."
            ),
            "uid": _UID,
            "clientId": _CLIENT_ID,
            "eventId": replay_rollback_id,
            "recipientPrivateKeyRaw": _b64(_AGENT_PRIV),
            "recipientPublicKeyX963": _b64(_AGENT_PUB),
            "pinnedSenderPublicKeyX963": _b64(_PHONE_PUB),
            "senderPublicKeyX963": _b64(_PHONE_PUB),
            "keyAAD": replay_rollback_key_aad,
            "info": ref.info_for(replay_rollback_key_aad.encode()).decode(),
            "enc": replay_rollback_enc,
            "wrappedKey": replay_rollback_wrapped,
            "plaintextContentKey": _b64(replay_rollback_key),
            "payloadAAD": replay_rollback_payload_aad,
            "payloadCiphertext": _seal_payload(
                "replay_counter_rollback",
                (
                    '{"kind":"model_switch","modelId":"claude-opus-4-8",'
                    '"destinationId":"burnbar:home","replayCounter":1}'
                ),
                replay_rollback_key,
                replay_rollback_payload_aad,
            ),
            "payloadPlaintext": (
                '{"kind":"model_switch","modelId":"claude-opus-4-8",'
                '"destinationId":"burnbar:home","replayCounter":1}'
            ),
            "replayHighWater": 2,
            "relayKeyVersion": ref.RELAY_KEY_VERSION_V3,
            "relayEncryption": ref.RELAY_ENCRYPTION_V3,
        },
        {
            "name": "version_changed_to_2",
            "derivedFrom": base["name"],
            "mutation": "relay_key_version",
            "expected": "reject",
            "expectedError": "RelayV3EnvelopeError",
            "detail": (
                "A relay relabeling v3->v2 is not admitted to the v3 opener; production "
                "routes it to the v2 opener, which fails closed because the 48-byte v3 "
                "wrappedKey is shorter than the v2 minimum (enc(65)+nonce+ct+tag). The "
                "content key is never recovered (proven end-to-end against the real "
                "dispatch in test_downgrade_and_strip_fail_closed_in_production)."
            ),
            "relayKeyVersionOverride": 2,
        },
        {
            "name": "version_changed_to_1",
            "derivedFrom": base["name"],
            "mutation": "relay_key_version",
            "expected": "reject",
            "expectedError": "RelayV3EnvelopeError",
            "detail": "v1 is not an accepted gateway relay version; the open path refuses it at the version gate (no anonymous-leg fallback).",
            "relayKeyVersionOverride": 1,
        },
        {
            "name": "missing_enc",
            "derivedFrom": base["name"],
            "mutation": "missing_field",
            "expected": "reject",
            "expectedError": "RelayV3EnvelopeError",
            "detail": "A sealed v3 frame without the HPKE 'enc' field is structurally invalid -> fail closed.",
            "dropField": "enc",
        },
        {
            "name": "missing_sender_public_key",
            "derivedFrom": base["name"],
            "mutation": "missing_field",
            "expected": "reject",
            "expectedError": "RelayV3EnvelopeError",
            "detail": "A sealed v3 gateway frame without senderPublicKey violates the shared relay schema -> fail closed.",
            "dropField": "senderPublicKey",
        },
        {
            "name": "missing_relay_encryption",
            "derivedFrom": base["name"],
            "mutation": "missing_field",
            "expected": "reject",
            "expectedError": "RelayV3EnvelopeError",
            "detail": "A sealed v3 frame without the relayEncryption marker is fail-closed rejected.",
            "dropField": "relayEncryption",
        },
    ]


def build_fixture() -> dict:
    positives = _build_positive_cases()
    negatives = _build_negative_cases(positives)
    return {
        "schemaVersion": 1,
        "relayKeyVersion": ref.RELAY_KEY_VERSION_V3,
        "relayEncryption": ref.RELAY_ENCRYPTION_V3,
        "suite": {
            "mode": "auth",
            "kem": "DHKEM_P256_HKDF_SHA256",
            "kdf": "HKDF_SHA256",
            "aead": "AES_256_GCM",
            "kemId": ref.KEM_ID,
            "kdfId": ref.KDF_ID,
            "aeadId": ref.AEAD_ID,
            "modeId": ref.MODE_AUTH,
        },
        "hpke": {
            "infoPrefix": ref.INFO_PREFIX.decode(),
            "aadEqualsKeyAad": True,
            "encEncoding": "p256-x963-uncompressed-65",
            "wrappedKeyIsHpkeCiphertext": True,
            "encByteCount": 65,
            "wrappedKeyByteCount": 48,
        },
        "generator": {
            "language": "python",
            "command": "venv/bin/python -m tests.gateway.vectors.generate_burnbar_hpke_v3_vectors",
            "reference": "tests/gateway/vectors/hpke_v3_reference.py",
            "note": (
                "Python RFC 9180 reference (test-lane canonical, byte-identical to "
                "gateway/crypto/relay_e2ee.py HPKE primitives). Static keys + content "
                "keys, HPKE ephemerals, and payload nonces are deterministic so the "
                "fixture hash is stable across Hermes, BurnBar Core, and Android. "
                "Production uses fresh random ephemerals/nonces; this determinism is "
                "test-only."
            ),
        },
        "keys": {
            "agentRecipientPublicKeyX963": _b64(_AGENT_PUB),
            "agentRecipientPrivateKeyRaw": _b64(_AGENT_PRIV),
            "phoneSenderPublicKeyX963": _b64(_PHONE_PUB),
            "phoneSenderPrivateKeyRaw": _b64(_PHONE_PRIV),
        },
        "cases": positives + negatives,
    }


FIXTURE_PATH = (
    Path(__file__).resolve().parents[1] / "fixtures" / "BurnBarHpkeV3Vector.json"
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=FIXTURE_PATH,
        help="fixture output path (default: tests/gateway/fixtures/BurnBarHpkeV3Vector.json)",
    )
    parser.add_argument(
        "--stdout", action="store_true", help="print the fixture JSON to stdout instead of writing"
    )
    args = parser.parse_args()

    fixture = build_fixture()
    text = json.dumps(fixture, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.stdout:
        print(text, end="")
        return
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8")
    positives = [c["name"] for c in fixture["cases"] if c["expected"] == "open"]
    negatives = [c["name"] for c in fixture["cases"] if c["expected"] == "reject"]
    print(f"wrote {args.out}")
    print(f"  positive cases ({len(positives)}): {', '.join(positives)}")
    print(f"  negative cases ({len(negatives)}): {', '.join(negatives)}")


if __name__ == "__main__":
    main()
