from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any

from .storage import atomic_write_bytes


def key_path() -> Path:
    configured = os.environ.get("AGENT_SUPERVISOR_ATTESTATION_KEY_FILE")
    return Path(configured).expanduser() if configured else Path.home() / ".agent-supervisor" / ".attestation-key"


def _key(create: bool) -> bytes | None:
    path = key_path()
    if path.exists():
        try:
            value = path.read_bytes()
            return value if len(value) >= 32 else None
        except OSError:
            return None
    if not create:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_bytes(32)
    atomic_write_bytes(path, value)
    try:
        path.chmod(0o600)
    except OSError:
        pass
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
