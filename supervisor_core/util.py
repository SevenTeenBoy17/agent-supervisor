from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import string
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SECRET_FLAG = re.compile(
    r"(?i)^(?:--?(?:api[-_]?key|access[-_]?token|auth(?:orization)?|bearer|client[-_]?secret|password|passwd|secret|token)|/(?:password|token))$"
)


def _sensitive_key(key: str) -> bool:
    normalized = key.strip().casefold().replace("-", "_")
    if normalized in {"authorization", "authorization_header", "cookie", "set_cookie", "credential", "credentials"}:
        return True
    return bool(re.search(
        r"(?:^|_)(?:secret|token|password|passwd|api_key|access_key|private_key|client_secret|credential|cookie)s?$",
        normalized,
    ))
_TEXT_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s,;]+"),
    re.compile(r"(?i)(bearer\s+)[a-z0-9._~+\-/=]+"),
    re.compile(r"(?i)((?:api[_-]?key|token|password|passwd|secret|authorization)\s*[=:]\s*)[^\s,;]+"),
    re.compile(r"(?<![A-Za-z0-9_])(?:sk-[A-Za-z0-9_-]{8,}|github_pat_[A-Za-z0-9_]{8,}|gh[pousr]_[A-Za-z0-9_]{8,})(?![A-Za-z0-9_])"),
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return sha256_text(payload)


def stable_id(prefix: str, seed: str | None = None) -> str:
    digest = sha256_text(seed)[:16] if seed is not None else secrets.token_hex(8)
    return f"{prefix}-{digest}"


def slug(value: str, *, fallback: str = "default") -> str:
    value = value.strip()
    if not value:
        return fallback
    safe = "".join(ch if ch in string.ascii_letters + string.digits + "-_." else "-" for ch in value)
    safe = re.sub(r"-+", "-", safe).strip("-.")[:64]
    return f"{safe or fallback}-{sha256_text(value)[:8]}"


def redact(value: Any, key: str = "") -> Any:
    # Contract metadata such as waiver_authorizations and
    # source_authorization_sha256 is not a credential. Substring matching on
    # "authorization" destroyed valid waiver state; redact only credential-key
    # shapes and continue applying value-level token patterns below.
    if _sensitive_key(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        result: list[Any] = []
        redact_next = False
        for item in value:
            if redact_next:
                result.append("[REDACTED]")
                redact_next = False
                continue
            if isinstance(item, str):
                option, separator, option_value = item.partition("=")
                if _SECRET_FLAG.fullmatch(option.strip()):
                    if separator:
                        result.append(f"{option}=[REDACTED]")
                    else:
                        result.append(item)
                        redact_next = True
                    continue
            result.append(redact(item))
        return result
    if isinstance(value, str):
        clean = value
        for pattern in _TEXT_SECRET_PATTERNS:
            if pattern.groups:
                clean = pattern.sub(lambda match: match.group(1) + "[REDACTED]", clean)
            else:
                clean = pattern.sub("[REDACTED]", clean)
        return clean
    return value


def json_load(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def truthy_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}
