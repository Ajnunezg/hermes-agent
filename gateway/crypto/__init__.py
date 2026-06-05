"""End-to-end relay crypto for the BurnBar Hermes gateway.

This package is the Python side of the BurnBar relay wire format, which the
BurnBar iOS (CryptoKit) and Android clients also implement. Its known-answer
vectors live under ``tests/gateway/fixtures/`` and are regenerated and
byte-verified in-tree by ``tests/gateway/vectors/generate_wire_vectors.py``;
cross-language parity with the mobile clients is maintained in those client
repositories.

The gateway adapter (``plugins/platforms/burnbar/adapter.py``) imports the
sealing primitives from :mod:`gateway.crypto.relay_e2ee` so the agent can
seal message text / attachment bodies to the paired phone's relay public key
and unwrap inbound events sealed to its own relay public key — without the
relay server ever seeing plaintext.
"""

from .relay_e2ee import (
    ALGORITHM,
    KEY_VERSION,
    HPKE_ALGORITHM,
    HPKE_KEY_VERSION,
    HERMES_NAMESPACE,
    RelayNamespace,
    RelayPrivateKey,
    RelayPublicKey,
    RelayKeyWrapV3,
    AgentRelayIdentity,
    RelayCryptoError,
    InvalidPublicKeyError,
    InvalidCiphertextError,
    InvalidSymmetricKeyError,
    CorruptIdentityError,
    generate_private_key,
    generate_symmetric_key,
    public_key_x963_from_base64,
    seal_to_base64,
    open_base64,
    wrap_symmetric_key,
    unwrap_symmetric_key,
    wrap_symmetric_key_v3,
    unwrap_symmetric_key_v3,
    request_aad,
    key_aad,
    chunk_aad,
)

__all__ = [
    "ALGORITHM",
    "KEY_VERSION",
    "HPKE_ALGORITHM",
    "HPKE_KEY_VERSION",
    "HERMES_NAMESPACE",
    "RelayNamespace",
    "RelayPrivateKey",
    "RelayPublicKey",
    "RelayKeyWrapV3",
    "AgentRelayIdentity",
    "RelayCryptoError",
    "InvalidPublicKeyError",
    "InvalidCiphertextError",
    "InvalidSymmetricKeyError",
    "CorruptIdentityError",
    "generate_private_key",
    "generate_symmetric_key",
    "public_key_x963_from_base64",
    "seal_to_base64",
    "open_base64",
    "wrap_symmetric_key",
    "unwrap_symmetric_key",
    "wrap_symmetric_key_v3",
    "unwrap_symmetric_key_v3",
    "request_aad",
    "key_aad",
    "chunk_aad",
]
