"""Unit tests for durable BurnBar E2EE security state."""

from __future__ import annotations

import json

import pytest

from plugins.platforms.burnbar.e2ee_state_store import (
    MAX_REPLAY_COUNTER,
    BurnBarE2EEStateError,
    BurnBarE2EEStateStore,
    legacy_encryption_bucket_id,
    stable_signed_bucket_id,
    validate_replay_counter,
)


def test_validate_replay_counter_rejects_bool_and_overflow():
    with pytest.raises(ValueError):
        validate_replay_counter(True)
    with pytest.raises(ValueError):
        validate_replay_counter(-1)
    with pytest.raises(ValueError):
        validate_replay_counter(MAX_REPLAY_COUNTER + 1)
    assert validate_replay_counter(0) == 0


def test_migrate_from_legacy_ledger(tmp_path):
    legacy = legacy_encryption_bucket_id("u", "c", "enc-fp")
    bucket = stable_signed_bucket_id(
        uid="u",
        client_id="c",
        destination_id="burnbar:home",
        peer_signing_fingerprint="peer",
        local_signing_fingerprint="local",
    )
    ledger = tmp_path / "ledger.json"
    ledger.write_text(
        json.dumps({legacy: {"highWater": 7, "ids": []}, "ratchetSessions": {"sess-1": True}}),
        encoding="utf-8",
    )
    migrated = BurnBarE2EEStateStore(tmp_path / "state.json")
    assert migrated.migrate_from_replay_ledger(
        ledger, legacy_bucket_id=legacy, target_bucket_id=bucket
    )
    assert migrated.get_inbound_high_water(bucket) == 7
    assert migrated.ratchet_lineage_exists("sess-1")
    assert migrated.get_ratchet_receive_high_water("sess-1") == 1


def test_ratchet_receive_high_water_persisted(tmp_path):
    store = BurnBarE2EEStateStore(tmp_path / "state.json")
    store.record_ratchet_receive("sess-a", 3)
    reloaded = BurnBarE2EEStateStore(tmp_path / "state.json")
    reloaded.load_or_fail_closed(has_e2e_pins=False)
    assert reloaded.get_ratchet_receive_high_water("sess-a") == 3
    store.clear_ratchet_receive("sess-a")
    assert store.get_ratchet_receive_high_water("sess-a") == 0


def test_fail_closed_without_state_or_ledger(tmp_path):
    store = BurnBarE2EEStateStore(tmp_path / "state.json")
    with pytest.raises(BurnBarE2EEStateError):
        store.load_or_fail_closed(has_e2e_pins=True, ledger_path=tmp_path / "missing.json")


def test_corrupt_state_file_fails_closed_and_is_not_overwritten(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{not-json", encoding="utf-8")

    legacy = BurnBarE2EEStateStore(path)
    legacy.load_or_fail_closed(has_e2e_pins=False)
    assert legacy.is_ready
    assert path.read_text(encoding="utf-8") == "{not-json"

    with pytest.raises(BurnBarE2EEStateError):
        BurnBarE2EEStateStore(path).load_or_fail_closed(has_e2e_pins=True)
    assert path.read_text(encoding="utf-8") == "{not-json"

    with pytest.raises(BurnBarE2EEStateError):
        BurnBarE2EEStateStore(path).initialize_pairing_bucket("bucket")
    assert path.read_text(encoding="utf-8") == "{not-json"


def test_malformed_state_schema_fails_closed(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"_schema_version": 999, "signed": {}}), encoding="utf-8")

    with pytest.raises(BurnBarE2EEStateError, match="unsupported"):
        BurnBarE2EEStateStore(path).load_or_fail_closed(has_e2e_pins=True)


def test_outbound_counter_monotonic_and_persisted(tmp_path):
    path = tmp_path / "state.json"
    bucket = stable_signed_bucket_id(
        uid="u",
        client_id="c",
        destination_id="d",
        peer_signing_fingerprint="p",
        local_signing_fingerprint="l",
    )
    first = BurnBarE2EEStateStore(path)
    first.initialize_pairing_bucket(bucket)
    c1 = first.reserve_outbound_counter(bucket)
    c2 = first.reserve_outbound_counter(bucket)
    assert c1 == 1 and c2 == 2
    second = BurnBarE2EEStateStore(path)
    second.load_or_fail_closed(has_e2e_pins=True)
    assert second.reserve_outbound_counter(bucket) == 3
