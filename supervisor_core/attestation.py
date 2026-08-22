from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any

from .storage import exclusive_lock


def key_path() -> Path:
    configured = os.environ.get("AGENT_SUPERVISOR_ATTESTATION_KEY_FILE")
    return Path(configured).expanduser() if configured else Path.home() / ".agent-supervisor" / ".attestation-key"


def _existing_key(path: Path) -> tuple[bool, bytes | None]:
    """Return existence separately from validity so invalid keys are immutable."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False, None
    except OSError:
        # An unreadable directory entry is not evidence that the key is absent.
        return True, None
    is_reparse = bool(
        stat.S_ISLNK(metadata.st_mode)
        or (
            hasattr(metadata, "st_file_attributes")
            and bool(
                metadata.st_file_attributes
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            )
        )
    )
    if is_reparse or not stat.S_ISREG(metadata.st_mode):
        return True, None
    try:
        value = path.read_bytes()
    except OSError:
        return True, None
    return True, value if len(value) >= 32 else None


def _create_key_exclusive(path: Path, value: bytes) -> bool:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        return False
    created_identity: tuple[int, int] | None = None
    try:
        metadata = os.fstat(descriptor)
        created_identity = (metadata.st_dev, metadata.st_ino)
        written = 0
        while written < len(value):
            count = os.write(descriptor, value[written:])
            if count <= 0:
                raise OSError("attestation key write made no progress")
            written += count
        os.fsync(descriptor)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        if created_identity is not None:
            try:
                current = path.lstat()
                is_reparse = bool(
                    stat.S_ISLNK(current.st_mode)
                    or (
                        hasattr(current, "st_file_attributes")
                        and bool(
                            current.st_file_attributes
                            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                        )
                    )
                )
                if (
                    not is_reparse
                    and stat.S_ISREG(current.st_mode)
                    and (current.st_dev, current.st_ino) == created_identity
                ):
                    path.unlink()
            except OSError:
                pass
        raise
    else:
        os.close(descriptor)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return True


def _key(create: bool) -> bytes | None:
    path = key_path()
    exists, value = _existing_key(path)
    if exists:
        return value
    if not create:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    # Recheck under a sibling lock: all concurrent first-time signers must use
    # the single key that actually won creation, not their private candidates.
    with exclusive_lock(path.with_name(f".{path.name}.lock")):
        exists, value = _existing_key(path)
        if exists:
            return value
        candidate = secrets.token_bytes(32)
        if _create_key_exclusive(path, candidate):
            return candidate
        # A non-cooperating creator may win between the locked existence check
        # and O_EXCL. Accept only its already-valid key; never replace it.
        _, value = _existing_key(path)
        return value


def canonical_payload(record: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in record.items() if key not in {"attestation", "sequence", "recorded_at"}}
    return json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_record(record: dict[str, Any]) -> str:
    key = _key(create=True)
    if key is None:
        raise RuntimeError("attestation key unavailable")
    return hmac.new(key, canonical_payload(record), hashlib.sha256).hexdigest()


def verify_record(record: dict[str, Any]) -> bool:
    signature = record.get("attestation")
    key = _key(create=False)
    if not isinstance(signature, str) or not key:
        return False
    expected = hmac.new(key, canonical_payload(record), hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)
