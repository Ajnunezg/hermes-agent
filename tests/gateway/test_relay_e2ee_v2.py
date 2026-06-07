"""v2 authenticated key-wrap known-answer tests against the gateway wire vector.

Opens the committed ``gateway_wire_vector.json`` (``revision == "v2"``) and
checks Python unwraps each slot under the v2 2-DH scheme. Forge tests pin a wrong
sender and expect ``InvalidTag``. The vector is regenerated and byte-verified
in-tree by ``tests/gateway/vectors/generate_wire_vectors.py`` (see
``tests/gateway/test_wire_vectors_reproducible.py``).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from plugins.platforms.burnbar import relay_e2ee  # noqa: E402

_GATEWAY_FIXTURE_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "gateway_wire_vector.json"
)


@pytest.fixture(scope="module")
def gateway_vector() -> dict:
    with _GATEWAY_FIXTURE_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _aad(value: str) -> bytes:
    return value.encode("utf-8")


def _unwrap_v2(node: dict, key_aad: str) -> bytes:
    recipient = relay_e2ee.RelayPrivateKey.from_base64(node["recipientPrivateKey"])
    return relay_e2ee.unwrap_symmetric_key(
        node["wrappedKey"],
        recipient,
        _aad(key_aad),
        sender_public_base64=node["senderPublicKey"],
    )


def _wrap_v2_test_key_data(
    key_data: bytes,
    recipient: relay_e2ee.RelayPrivateKey,
    sender: relay_e2ee.RelayPrivateKey,
    aad: bytes,
) -> str:
    """Build a valid v2 envelope around arbitrary key bytes.

    ``wrap_symmetric_key`` correctly rejects non-32-byte keys, so this helper
    mirrors the v2 derivation to prove ``unwrap_symmetric_key`` also enforces
    the boundary after decrypting a syntactically valid envelope.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    recipient_public = recipient._private_key().public_key()
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    eph_x963 = ephemeral.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    )
    recipient_pub_x963 = recipient_public.public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    )
    sender_pub_x963 = sender.public_key_x963()
    dh1 = ephemeral.exchange(ec.ECDH(), recipient_public)
    dh2 = sender._private_key().exchange(ec.ECDH(), recipient_public)
    wrapping_key = relay_e2ee._hkdf_derive(
        dh1 + dh2,
        relay_e2ee.RelayNamespace().key_wrap_shared_info_v2(
            aad, eph_x963, recipient_pub_x963, sender_pub_x963
        ),
    )
    nonce = b"\x00" * 12
    sealed = AESGCM(wrapping_key).encrypt(nonce, key_data, aad)
    return base64.b64encode(eph_x963 + nonce + sealed).decode("ascii")


def test_gateway_vector_is_the_v2_contract(gateway_vector):
    assert gateway_vector["revision"] == "v2"
    assert gateway_vector["keyVersion"] == 2
    assert relay_e2ee.KEY_VERSION == gateway_vector["keyVersion"]
    assert gateway_vector["algorithm"] == relay_e2ee.ALGORITHM
    recipient = relay_e2ee.RelayPrivateKey.from_base64(
        gateway_vector["event"]["recipientPrivateKey"]
    )
    identity = relay_e2ee.AgentRelayIdentity(recipient)
    assert identity.key_version == gateway_vector["keyVersion"]
    assert identity.algorithm == gateway_vector["algorithm"]
    for slot in ("event", "message", "modelSwitch", "attachment"):
        assert gateway_vector[slot]["senderPublicKey"], f"{slot} missing senderPublicKey"


@pytest.mark.parametrize("slot", ["event", "message", "modelSwitch"])
def test_v2_unwrap_then_open_payload(gateway_vector, slot):
    node = gateway_vector[slot]
    sym = _unwrap_v2(node, node["keyAAD"])
    assert sym == base64.b64decode(node["symmetricKey"])
    plaintext = relay_e2ee.open_base64(
        node["payloadCiphertext"], sym, _aad(node["payloadAAD"])
    )
    assert plaintext == base64.b64decode(node["encodedPlaintext"])


def test_v2_attachment_unwraps_body_key_and_opens_manifest_and_body(gateway_vector):
    node = gateway_vector["attachment"]
    body_key = _unwrap_v2(node, node["keyAAD"])
    assert body_key == base64.b64decode(node["bodyKey"])
    manifest = relay_e2ee.open_base64(
        node["manifestCiphertext"], body_key, _aad(node["manifestAAD"])
    )
    assert manifest.decode("utf-8") == node["manifestPlaintext"]
    body = relay_e2ee.open_base64(
        node["bodyCiphertext"], body_key, _aad(node["bodyAAD"])
    )
    assert body.decode("utf-8") == node["bodyPlaintext"]


@pytest.mark.parametrize("slot", ["event", "message", "modelSwitch", "attachment"])
def test_v2_unwrap_with_wrong_sender_key_raises_invalid_tag(gateway_vector, slot):
    from cryptography.exceptions import InvalidTag

    node = gateway_vector[slot]
    recipient = relay_e2ee.RelayPrivateKey.from_base64(node["recipientPrivateKey"])
    with pytest.raises(InvalidTag):
        relay_e2ee.unwrap_symmetric_key(
            node["wrappedKey"],
            recipient,
            _aad(node["keyAAD"]),
            sender_public_base64=node["recipientPublicKey"],
        )


@pytest.mark.parametrize("slot", ["event", "message", "modelSwitch", "attachment"])
def test_v2_unwrap_with_wrong_recipient_key_raises_invalid_tag(gateway_vector, slot):
    from cryptography.exceptions import InvalidTag

    node = gateway_vector[slot]
    wrong_recipient = relay_e2ee.generate_private_key()
    with pytest.raises(InvalidTag):
        relay_e2ee.unwrap_symmetric_key(
            node["wrappedKey"],
            wrong_recipient,
            _aad(node["keyAAD"]),
            sender_public_base64=node["senderPublicKey"],
        )


def test_v2_unwrap_rejects_malformed_sender_public_key(gateway_vector):
    node = gateway_vector["event"]
    recipient = relay_e2ee.RelayPrivateKey.from_base64(node["recipientPrivateKey"])
    with pytest.raises(relay_e2ee.InvalidPublicKeyError):
        relay_e2ee.unwrap_symmetric_key(
            node["wrappedKey"],
            recipient,
            _aad(node["keyAAD"]),
            sender_public_base64=node["senderPublicKey"] + "!!",
        )


def test_v2_unwrap_rejects_decrypted_symmetric_key_with_wrong_length():
    recipient = relay_e2ee.generate_private_key()
    sender = relay_e2ee.generate_private_key()
    aad = relay_e2ee.key_aad("uid", "client", "request")
    wrapped = _wrap_v2_test_key_data(b"\x11" * 31, recipient, sender, aad)

    with pytest.raises(relay_e2ee.InvalidSymmetricKeyError, match="32 bytes"):
        relay_e2ee.unwrap_symmetric_key(
            wrapped,
            recipient,
            aad,
            sender_public_base64=sender.public_key_base64(),
        )


def test_relay_private_key_repr_never_prints_scalar():
    """Private relay key material must not leak through dataclass repr()."""
    raw = b"\x01" * 32
    key = relay_e2ee.RelayPrivateKey(raw)
    identity = relay_e2ee.AgentRelayIdentity(key)

    assert "raw_representation" not in repr(key)
    assert raw.hex() not in repr(key)
    assert "\\x01" not in repr(key)
    assert "private_key" not in repr(identity)
    assert "raw_representation" not in repr(identity)
    assert "\\x01" not in repr(identity)


def test_relay_private_key_malformed_inputs_raise_typed_errors():
    with pytest.raises(relay_e2ee.InvalidPrivateKeyError, match="raw 32-byte"):
        relay_e2ee.RelayPrivateKey.from_raw(b"short")
    with pytest.raises(relay_e2ee.InvalidPrivateKeyError, match="out of range"):
        relay_e2ee.RelayPrivateKey.from_raw(b"\x00" * 32)
    with pytest.raises(relay_e2ee.InvalidPrivateKeyError, match="invalid"):
        relay_e2ee.RelayPrivateKey.from_base64("not-base64!!")

    env = {
        relay_e2ee.RELAY_PRIVATE_KEY_ENV: base64.b64encode(b"\x00" * 32).decode(
            "ascii"
        )
    }
    with pytest.raises(relay_e2ee.CorruptIdentityError, match="present but invalid"):
        relay_e2ee.AgentRelayIdentity.load_or_create(environ=env)


def test_v2_wrap_is_domain_separated_from_v1_unwrap():
    from cryptography.exceptions import InvalidTag

    sender = relay_e2ee.generate_private_key()
    recipient = relay_e2ee.generate_private_key()
    symmetric_key = relay_e2ee.generate_symmetric_key()
    aad = relay_e2ee.key_aad("u", "c", "r")
    wrapped = relay_e2ee.wrap_symmetric_key(
        symmetric_key, recipient.public_key_base64(), aad, sender_private=sender
    )
    with pytest.raises(InvalidTag):
        relay_e2ee.unwrap_symmetric_key(wrapped, recipient, aad)


def test_v1_wrap_is_domain_separated_from_v2_unwrap():
    """The reverse direction: a v1 (anonymous, 1-DH) wrap must not open under the v2
    authenticated unwrap. Together with the forward test this pins both directions of
    the v1/v2 domain separation at the crypto layer.
    """
    from cryptography.exceptions import InvalidTag

    sender = relay_e2ee.generate_private_key()
    recipient = relay_e2ee.generate_private_key()
    symmetric_key = relay_e2ee.generate_symmetric_key()
    aad = relay_e2ee.key_aad("u", "c", "r")
    # v1 wrap: no sender_private -> anonymous single-DH, v1 HKDF info prefix.
    wrapped_v1 = relay_e2ee.wrap_symmetric_key(
        symmetric_key, recipient.public_key_base64(), aad
    )
    # v2 unwrap: binds the pinned sender key + the v2 HKDF info prefix -> wrong key.
    with pytest.raises(InvalidTag):
        relay_e2ee.unwrap_symmetric_key(
            wrapped_v1, recipient, aad, sender_public_base64=sender.public_key_base64()
        )


def test_crypto_backend_probe_tests_the_real_dependency():
    """``crypto_backend_available()`` must reflect the actual ``cryptography``
    backend, not mere module importability — relay_e2ee imports the backend
    lazily, so ``import relay_e2ee`` succeeds even when it is absent. The
    primitive probe relies on this distinction."""
    import importlib
    import sys

    assert relay_e2ee.crypto_backend_available() is True

    class _Blocker:
        def find_spec(self, name, path=None, target=None):
            if name == "cryptography" or name.startswith("cryptography."):
                raise ImportError("cryptography blocked for test")
            return None

    blocker = _Blocker()
    module_name = relay_e2ee.__name__
    package = sys.modules["plugins.platforms.burnbar"]
    saved_module = sys.modules.get(module_name)
    saved_package_attr = getattr(package, "relay_e2ee", None)
    saved_crypto = {
        k: v
        for k, v in sys.modules.items()
        if k == "cryptography" or k.startswith("cryptography.")
    }
    try:
        for key in list(saved_crypto):
            del sys.modules[key]
        sys.meta_path.insert(0, blocker)
        sys.modules.pop(module_name, None)
        delattr(package, "relay_e2ee")
        # Fresh relay_e2ee import still succeeds (no top-level crypto), but the
        # probe now sees the missing backend and reports False.
        blocked_module = importlib.import_module(module_name)
        assert blocked_module.crypto_backend_available() is False
    finally:
        sys.meta_path.remove(blocker)
        sys.modules.update(saved_crypto)
        if saved_module is not None:
            sys.modules[module_name] = saved_module
        if saved_package_attr is not None:
            setattr(package, "relay_e2ee", saved_package_attr)

    assert relay_e2ee.crypto_backend_available() is True
