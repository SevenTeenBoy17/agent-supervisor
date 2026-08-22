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


_SECRET_FIELD_NAME = r"(?:api[_-]?key|token|password|passwd|secret|authorization)"
_QUOTED_TEXT_SECRET_PATTERNS = (
    (
        re.compile(
            rf'''(?i)(?P<prefix>(?<![A-Za-z0-9_])(?:"{_SECRET_FIELD_NAME}"|'{_SECRET_FIELD_NAME}'|{_SECRET_FIELD_NAME})\s*[=:]\s*)"(?:\\.|[^"\\])*"'''
        ),
        '"',
    ),
    (
        re.compile(
            rf"""(?i)(?P<prefix>(?<![A-Za-z0-9_])(?:"{_SECRET_FIELD_NAME}"|'{_SECRET_FIELD_NAME}'|{_SECRET_FIELD_NAME})\s*[=:]\s*)'(?:\\.|[^'\\])*'"""
        ),
        "'",
    ),
)
_TEXT_SECRET_PATTERNS = (
    re.compile(
        r'''(?i)(authorization\s*:\s*)(?!\[REDACTED\])(?:(?:bearer|basic)\s+)?[^\s,;}\]"']+'''
    ),
    re.compile(r"(?i)(bearer\s+)[a-z0-9._~+\-/=]+"),
    re.compile(
        rf'''(?i)((?<![A-Za-z0-9_])(?:"{_SECRET_FIELD_NAME}"|'{_SECRET_FIELD_NAME}'|{_SECRET_FIELD_NAME})\s*[=:]\s*)(?!\[REDACTED\])[^\s,;}}\]"']+'''
    ),
    re.compile(r"(?<![A-Za-z0-9_])(?:sk-[A-Za-z0-9_-]{8,}|github_pat_[A-Za-z0-9_]{8,}|gh[pousr]_[A-Za-z0-9_]{8,})(?![A-Za-z0-9_])"),
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    # Older state may contain ISO timestamps without an explicit offset. Treat
    # those as UTC (the supervisor's only clock domain), then normalize all
    # aware values so comparisons never mix naive and aware datetimes.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


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
        for pattern, quote in _QUOTED_TEXT_SECRET_PATTERNS:
            clean = pattern.sub(
                lambda match, delimiter=quote: f"{match.group('prefix')}{delimiter}[REDACTED]{delimiter}",
                clean,
            )
        for pattern in _TEXT_SECRET_PATTERNS:
            if pattern.groups:
                clean = pattern.sub(lambda match: match.group(1) + "[REDACTED]", clean)
            else:
                clean = pattern.sub("[REDACTED]", clean)
        return clean
    return value


def redact_for_persistence(value: Any) -> Any:
    """Redact unbound data while refusing to corrupt integrity-bound records.

    Supervisor state contains local signatures and hashes that are validated on
    every finalize.  Silently redacting one of their inputs would protect the
    secret but leave an authoritative record that can never validate.  Reject
    that write instead; callers can record a bounded degraded/invalid-state
    error without persisting either the secret or a forged replacement hash.
    """
    clean = redact(value)

    def reject_changed_bindings(original: Any, sanitized: Any) -> None:
        if isinstance(original, dict) and isinstance(sanitized, dict):
            if "attestation" in original and original != sanitized:
                raise ValueError("redaction would mutate an attested record")
            for key, original_hash in original.items():
                if not isinstance(key, str) or not key.endswith("_sha256"):
                    continue
                bound_key = key[:-7]
                if bound_key in original and sanitized.get(bound_key) != original.get(bound_key):
                    raise ValueError(f"redaction would mutate hash-bound field: {bound_key}")
                if sanitized.get(key) != original_hash:
                    raise ValueError(f"redaction would mutate integrity hash: {key}")
            for key, child in original.items():
                reject_changed_bindings(child, sanitized.get(str(key)))
        elif isinstance(original, (list, tuple)) and isinstance(sanitized, list):
            for child, clean_child in zip(original, sanitized, strict=False):
                reject_changed_bindings(child, clean_child)

    reject_changed_bindings(value, clean)
    if isinstance(value, dict) and isinstance(clean, dict) and isinstance(value.get("request_manifest"), dict):
        # RequestManifest binds the complete GoalContract and the atomic intent
        # text hashes.  Do not let state-level redaction invalidate that signed
        # manifest after it has been constructed.
        for field in ("goal", "intents", "intent_manifest", "request_manifest"):
            if field in value and clean.get(field) != value.get(field):
                raise ValueError(f"redaction would mutate request-manifest-bound field: {field}")
    return clean


def json_load(path: Path, default: Any = None) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return default


def truthy_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}
