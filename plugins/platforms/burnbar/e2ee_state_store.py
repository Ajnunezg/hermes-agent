"""Durable BurnBar gateway E2EE security state (replay counters + ratchet lineage).

Stores integrity-critical counters and ratchet session lineage outside the cache
directory. Does NOT store secrets (keys, chain material, etc.).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from hermes_constants import get_hermes_home
except ImportError:  # pragma: no cover - minimal test stubs

    def get_hermes_home() -> Path:
        return Path(os.getenv("HERMES_HOME", Path.home() / ".hermes")).expanduser()


MAX_REPLAY_COUNTER = 9_007_199_254_740_991  # JavaScript Number.MAX_SAFE_INTEGER
_SCHEMA_VERSION = 1
_LOCK_RETRIES = 3
_LOCK_BACKOFF_S = 0.05

DEFAULT_STATE_FILE = (
    Path(os.getenv("HERMES_BURNBAR_E2EE_STATE_FILE", "")).expanduser()
    if os.getenv("HERMES_BURNBAR_E2EE_STATE_FILE")
    else get_hermes_home() / "security" / "burnbar_e2ee_state.json"
)


class BurnBarE2EEStateError(RuntimeError):
    """Security state could not be loaded, migrated, or persisted."""


def validate_replay_counter(value: Any) -> int:
    """Return a validated replay counter or raise ValueError."""
    if isinstance(value, bool) or value is None:
        raise ValueError("replayCounter must be a non-negative integer")
    if isinstance(value, int):
        counter = value
    elif isinstance(value, str) and value.strip().isdigit():
        counter = int(value.strip())
    else:
        raise ValueError("replayCounter must be a non-negative integer")
    if counter < 0:
        raise ValueError("replayCounter must be a non-negative integer")
    if counter > MAX_REPLAY_COUNTER:
        raise ValueError(f"replayCounter exceeds safe integer maximum ({MAX_REPLAY_COUNTER})")
    return counter


def signing_key_fingerprint(signing_key_b64: str | None) -> str:
    """Fingerprint a pinned Ed25519 verification key for stable replay buckets."""
    key = (signing_key_b64 or "").strip()
    if not key:
        return "legacy"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def legacy_encryption_bucket_id(uid: str, client_id: str, peer_encryption_fingerprint: str) -> str:
    """Legacy replay-ledger bucket (encryption-key bound) used only for migration."""
    material = json.dumps([uid, client_id, peer_encryption_fingerprint], separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def stable_signed_bucket_id(
    *,
    uid: str,
    client_id: str,
    destination_id: str,
    peer_signing_fingerprint: str,
    local_signing_fingerprint: str,
) -> str:
    """Stable replay bucket keyed by pairing/signing identity (not encryption key)."""
    material = json.dumps(
        [
            uid,
            client_id,
            destination_id,
            peer_signing_fingerprint,
            local_signing_fingerprint,
        ],
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _empty_state() -> Dict[str, Any]:
    return {
        "_schema_version": _SCHEMA_VERSION,
        "signed": {},
        "ratchetLineage": {},
        # Max receiveMessageNumber ever durably committed per ratchet session id.
        # Survives session-cache loss so a silent re-bootstrap cannot reopen replay.
        "ratchetReceiveHighWater": {},
    }


def _coerce_high_water(value: Any) -> int:
    if value is None:
        return -1
    try:
        return validate_replay_counter(value)
    except ValueError:
        return -1


class BurnBarE2EEStateStore:
    """Profile-scoped durable security state with locked read-modify-write."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = (path or DEFAULT_STATE_FILE).expanduser()
        self._lock_path = self._path.with_name(f"{self._path.name}.lock")
        self._state: Dict[str, Any] = _empty_state()
        self._loaded = False
        self._ready = False

    @property
    def path(self) -> Path:
        return self._path

    @property
    def is_ready(self) -> bool:
        return self._ready

    def load_or_fail_closed(
        self,
        *,
        has_e2e_pins: bool,
        ledger_path: Path | None = None,
        legacy_bucket_id: str | None = None,
        target_bucket_id: str | None = None,
    ) -> None:
        """Load durable state; migrate from legacy ledger once if needed."""
        if self._loaded:
            return
        self._loaded = True
        if not has_e2e_pins:
            if self._path.is_file():
                try:
                    self._state = self._read_locked()
                except BurnBarE2EEStateError:
                    self._state = _empty_state()
            self._ready = True
            return
        if self._path.is_file():
            self._state = self._read_locked()
            self._ready = True
            return
        if ledger_path is not None and ledger_path.is_file():
            if self.migrate_from_replay_ledger(
                ledger_path,
                legacy_bucket_id=legacy_bucket_id,
                target_bucket_id=target_bucket_id,
            ):
                self._ready = True
                return
        raise BurnBarE2EEStateError(
            "E2E pairing pins exist but durable security state is missing; "
            "re-pair or restore security state before using this link"
        )

    def ensure_bucket(self, bucket_id: str) -> None:
        """Create a signed bucket with default counters if absent."""
        signed = self._state.setdefault("signed", {})
        if not isinstance(signed, dict):
            signed = {}
            self._state["signed"] = signed
        entry = signed.get(bucket_id)
        if not isinstance(entry, dict):
            signed[bucket_id] = {"inboundHighWater": -1, "outboundNextCounter": 1}

    def initialize_pairing_bucket(self, bucket_id: str) -> None:
        """Initialize durable counters for a freshly paired link (no overwrite)."""
        def _init(state: Dict[str, Any]) -> None:
            signed = state.setdefault("signed", {})
            if not isinstance(signed, dict):
                signed = {}
                state["signed"] = signed
            if bucket_id not in signed:
                signed[bucket_id] = {"inboundHighWater": -1, "outboundNextCounter": 1}

        self._mutate_locked(_init)

    def get_inbound_high_water(self, bucket_id: str) -> int:
        self.ensure_bucket(bucket_id)
        signed = self._state.get("signed") or {}
        entry = signed.get(bucket_id) if isinstance(signed, dict) else {}
        if not isinstance(entry, dict):
            return -1
        return _coerce_high_water(entry.get("inboundHighWater"))

    def is_replay_counter_seen(self, bucket_id: str, replay_counter: int) -> bool:
        return replay_counter <= self.get_inbound_high_water(bucket_id)

    def check_and_commit_inbound(self, bucket_id: str, replay_counter: int) -> bool:
        """Persist monotonic inbound high-water after payload validation."""
        validate_replay_counter(replay_counter)

        def _commit(state: Dict[str, Any]) -> None:
            signed = state.setdefault("signed", {})
            if not isinstance(signed, dict):
                signed = {}
                state["signed"] = signed
            entry = signed.setdefault(bucket_id, {"inboundHighWater": -1, "outboundNextCounter": 1})
            if not isinstance(entry, dict):
                entry = {"inboundHighWater": -1, "outboundNextCounter": 1}
                signed[bucket_id] = entry
            current = _coerce_high_water(entry.get("inboundHighWater"))
            if replay_counter <= current:
                raise BurnBarE2EEStateError("replay counter is not strictly greater than high-water")
            entry["inboundHighWater"] = replay_counter

        try:
            self._mutate_locked(_commit)
            return True
        except BurnBarE2EEStateError:
            return False
        except Exception as exc:
            raise BurnBarE2EEStateError(f"could not persist inbound replay high-water: {exc}") from exc

    def reserve_outbound_counter(self, bucket_id: str) -> int:
        """Reserve and persist the next outbound replay counter."""
        reserved: Dict[str, int] = {}

        def _reserve(state: Dict[str, Any]) -> None:
            signed = state.setdefault("signed", {})
            if not isinstance(signed, dict):
                signed = {}
                state["signed"] = signed
            entry = signed.setdefault(bucket_id, {"inboundHighWater": -1, "outboundNextCounter": 1})
            if not isinstance(entry, dict):
                entry = {"inboundHighWater": -1, "outboundNextCounter": 1}
                signed[bucket_id] = entry
            counter = validate_replay_counter(entry.get("outboundNextCounter", 1))
            reserved["counter"] = counter
            entry["outboundNextCounter"] = counter + 1

        self._mutate_locked(_reserve)
        return reserved["counter"]

    def ratchet_lineage_exists(self, session_id: str) -> bool:
        lineage = self._state.get("ratchetLineage")
        return isinstance(lineage, dict) and bool(lineage.get(session_id))

    def mark_ratchet_lineage(self, session_id: str) -> None:
        def _mark(state: Dict[str, Any]) -> None:
            lineage = state.setdefault("ratchetLineage", {})
            if not isinstance(lineage, dict):
                lineage = {}
                state["ratchetLineage"] = lineage
            lineage[session_id] = True

        self._mutate_locked(_mark)

    def clear_ratchet_lineage(self, session_id: str) -> None:
        def _clear(state: Dict[str, Any]) -> None:
            lineage = state.get("ratchetLineage")
            if isinstance(lineage, dict):
                lineage.pop(session_id, None)

        self._mutate_locked(_clear)

    def get_ratchet_receive_high_water(self, session_id: str) -> int:
        """Return the highest ratchet receiveMessageNumber ever committed for a session."""
        store = self._state.get("ratchetReceiveHighWater")
        if not isinstance(store, dict):
            return 0
        try:
            return max(0, int(store.get(session_id, 0)))
        except (TypeError, ValueError):
            return 0

    def record_ratchet_receive(self, session_id: str, receive_message_number: int) -> None:
        """Persist ratchet inbound progress after a successful decrypt+commit."""
        if receive_message_number < 0:
            return

        def _record(state: Dict[str, Any]) -> None:
            store = state.setdefault("ratchetReceiveHighWater", {})
            if not isinstance(store, dict):
                store = {}
                state["ratchetReceiveHighWater"] = store
            current = 0
            try:
                current = max(0, int(store.get(session_id, 0)))
            except (TypeError, ValueError):
                current = 0
            store[session_id] = max(current, int(receive_message_number))

        self._mutate_locked(_record)

    def clear_ratchet_receive(self, session_id: str) -> None:
        """Drop ratchet inbound progress for a retired session (e.g. key rotation)."""
        def _clear(state: Dict[str, Any]) -> None:
            store = state.get("ratchetReceiveHighWater")
            if isinstance(store, dict):
                store.pop(session_id, None)

        self._mutate_locked(_clear)

    def migrate_from_replay_ledger(
        self,
        ledger_path: Path,
        *,
        legacy_bucket_id: str | None = None,
        target_bucket_id: str | None = None,
    ) -> bool:
        """One-shot migration from the cache replay ledger."""
        try:
            raw = json.loads(ledger_path.read_text(encoding="utf-8"))
        except Exception:
            return False
        if not isinstance(raw, dict):
            return False

        high_water = -1
        if legacy_bucket_id:
            entry = raw.get(legacy_bucket_id)
            if isinstance(entry, dict):
                high_water = _coerce_high_water(entry.get("highWater"))
        else:
            for entry in raw.values():
                if isinstance(entry, dict) and "highWater" in entry:
                    high_water = max(high_water, _coerce_high_water(entry.get("highWater")))

        lineage: Dict[str, bool] = {}
        ratchet_receive: Dict[str, int] = {}
        established = raw.get("ratchetSessions")
        if isinstance(established, dict):
            for session_id, marker in established.items():
                if marker:
                    sid = str(session_id)
                    lineage[sid] = True
                    # Conservative: an established session must have received at least one frame.
                    ratchet_receive[sid] = 1

        def _migrate(state: Dict[str, Any]) -> None:
            state["_schema_version"] = _SCHEMA_VERSION
            signed = state.setdefault("signed", {})
            if not isinstance(signed, dict):
                signed = {}
                state["signed"] = signed
            if target_bucket_id:
                signed[target_bucket_id] = {
                    "inboundHighWater": high_water,
                    "outboundNextCounter": max(high_water + 1, 1),
                }
            state["ratchetLineage"] = lineage
            if ratchet_receive:
                state["ratchetReceiveHighWater"] = ratchet_receive
            state["migration"] = {
                "fromReplayLedger": True,
                "at": datetime.now(timezone.utc).isoformat(),
            }

        try:
            self._mutate_locked(_migrate, create=True)
            return True
        except Exception:
            return False

    def _read_locked(self) -> Dict[str, Any]:
        with self._file_lock():
            return self._read_existing_state_unlocked()

    def _mutate_locked(self, mutator, *, create: bool = False) -> None:
        with self._file_lock():
            if self._path.is_file():
                state = self._read_existing_state_unlocked()
            elif create:
                state = _empty_state()
            else:
                state = dict(self._state)
            if not isinstance(state, dict):
                raise BurnBarE2EEStateError("durable security state is not a JSON object")
            mutator(state)
            self._write_atomic(state)
            self._state = state
            self._ready = True

    def _read_existing_state_unlocked(self) -> Dict[str, Any]:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise BurnBarE2EEStateError(
                f"durable security state is unreadable: {self._path}"
            ) from exc
        if not isinstance(raw, dict):
            raise BurnBarE2EEStateError(
                f"durable security state is not a JSON object: {self._path}"
            )
        schema = raw.get("_schema_version")
        if schema != _SCHEMA_VERSION:
            raise BurnBarE2EEStateError(
                f"unsupported durable security state schema {schema!r}: {self._path}"
            )
        for section in ("signed", "ratchetLineage", "ratchetReceiveHighWater"):
            if section in raw and not isinstance(raw.get(section), dict):
                raise BurnBarE2EEStateError(
                    f"durable security state section {section!r} is malformed: {self._path}"
                )
        return raw

    def _write_atomic(self, state: Dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._path.parent, 0o700)
        except OSError:
            pass
        tmp = self._path.with_name(f"{self._path.name}.tmp")
        data = json.dumps(state, separators=(",", ":")).encode("utf-8")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self._path)
        dir_fd = os.open(self._path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def _file_lock(self):
        return _FileLock(self._lock_path)


class _FileLock:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._fd: int | None = None

    def __enter__(self):
        self._path.parent.mkdir(parents=True, exist_ok=True)
        last_exc: Exception | None = None
        for attempt in range(_LOCK_RETRIES):
            try:
                self._fd = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
                import fcntl

                fcntl.flock(self._fd, fcntl.LOCK_EX)
                return self
            except Exception as exc:
                last_exc = exc
                if self._fd is not None:
                    os.close(self._fd)
                    self._fd = None
                if attempt + 1 < _LOCK_RETRIES:
                    time.sleep(_LOCK_BACKOFF_S * (attempt + 1))
        raise BurnBarE2EEStateError(f"could not acquire security state lock: {last_exc}")

    def __exit__(self, exc_type, exc, tb):
        if self._fd is not None:
            try:
                import fcntl

                fcntl.flock(self._fd, fcntl.LOCK_UN)
            except Exception:
                pass
            os.close(self._fd)
            self._fd = None
