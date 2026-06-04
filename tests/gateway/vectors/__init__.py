"""Cross-language HPKE v3 vector tooling (test-only).

This package holds the *canonical* RFC 9180 HPKE Auth-mode reference and the
fixture generator for the BurnBar Hermes relay ``relayKeyVersion == 3``
content-key wrap. It is **test tooling / a conformance oracle**, never imported
by production code. The single production source of truth is
``gateway/crypto/relay_e2ee.py`` (Python) and
``OpenBurnBarCore/Sources/OpenBurnBarCore/SharedModels/HermesRelayCrypto.swift``
(Swift); this reference exists to *prove* they agree byte-for-byte.
"""
