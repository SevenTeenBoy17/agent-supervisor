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


class SensitivePersistenceError(ValueError):
    """Stable fail-closed error for integrity-bound sensitive mutations."""

    error_code = "sensitive-integrity-bound-record"

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(self.error_code)

_SECRET_OPTION_NAME = (
    r"(?:(?:[a-z0-9]+[-_])*(?:api[-_]?key|x[-_]?api[-_]?key|"
    r"access[-_]?(?:key|key[-_]?id|token)|secret[-_]?access[-_]?key|account[-_]?key|"
    r"subscription[-_]?key|client[-_]?(?:id|secret)|database[-_]?url|db[-_]?url|"
    r"connection[-_]?string|dsn|private[-_]?key)|"
    r"auth(?:orization)?|proxy[-_]?authorization|bearer|"
    r"password|passwd|secret|token|cookie|set[-_]?cookie)"
)
_SECRET_FLAG = re.compile(
    rf"(?i)^(?:--?{_SECRET_OPTION_NAME}|/(?:password|token|secret))$"
)


def _sensitive_key(key: str) -> bool:
    normalized = key.strip().casefold().replace("-", "_")
    # These are integrity/waiver metadata, not HTTP credential fields.  Their
    # string values still pass through value-level credential detection.
    if normalized in {
        "waiver_authorizations",
        "t3_action_authorizations",
        "source_authorization",
        "source_authorization_sha256",
        "granting_request_sha256",
    }:
        return False
    if normalized in {
        "authorization",
        "authorization_header",
        "proxy_authorization",
        "http_authorization",
        "auth_header",
        "cookie",
        "cookie_header",
        "request_cookie",
        "response_cookie",
        "set_cookie",
        "credential",
        "credentials",
        "database_url",
        "db_url",
        "connection_string",
        "connection_uri",
        "dsn",
        "client_id",
        "client_secret",
        "aws_access_key_id",
        "aws_secret_access_key",
        "secret_access_key",
        "account_key",
        "subscription_key",
        "private_key",
        "private_key_data",
    }:
        return True
    return bool(re.search(
        r"(?:^|_)(?:secret|token|password|passwd|api_key|access_key|access_key_id|"
        r"account_key|subscription_key|private_key|client_id|client_secret|credential|cookie|"
        r"database_url|db_url|connection_string|connection_uri|dsn)s?$",
        normalized,
    ))


_SECRET_FIELD_NAME = (
    r"(?:(?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|x[_-]?api[_-]?key|"
    r"access[_-]?(?:key|key[_-]?id|token)|secret[_-]?access[_-]?key|account[_-]?key|"
    r"subscription[_-]?key|client[_-]?(?:id|secret)|database[_-]?url|db[_-]?url|"
    r"connection[_-]?(?:string|uri)|dsn|private[_-]?key)|"
    r"token|password|passwd|secret|authorization|proxy[_-]?authorization|"
    r"cookie|set[_-]?cookie)"
)
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
    (
        re.compile(
            rf'''(?i)(?P<prefix>(?<!\S)(?:--?{_SECRET_OPTION_NAME}|/(?:password|token|secret))\s*(?:=\s*|\s+))"(?:\\.|[^"\\])*"'''
        ),
        '"',
    ),
    (
        re.compile(
            rf"""(?i)(?P<prefix>(?<!\S)(?:--?{_SECRET_OPTION_NAME}|/(?:password|token|secret))\s*(?:=\s*|\s+))'(?:\\.|[^'\\])*'"""
        ),
        "'",
    ),
)
_TEXT_SECRET_PATTERNS = (
    re.compile(
        r'''(?i)((?:authorization|proxy-authorization|x-api-key|x-auth-token)\s*:\s*)(?!\s*\[REDACTED\])(?:(?:bearer|basic)\s+)?[^\s,;}\]"']+'''
    ),
    re.compile(
        r'''(?i)((?:cookie|set-cookie)\s*:\s*)(?!\s*\[REDACTED\])[^\r\n,}\]"']+'''
    ),
    re.compile(r"(?i)(bearer\s+)[a-z0-9._~+\-/=]+"),
    re.compile(
        rf'''(?i)((?<![A-Za-z0-9_])(?:"{_SECRET_FIELD_NAME}"|'{_SECRET_FIELD_NAME}'|{_SECRET_FIELD_NAME})\s*[=:]\s*)(?!\s*\[REDACTED\])[^\s,;}}\]"']+'''
    ),
    re.compile(
        rf'''(?i)((?<!\S)(?:--?{_SECRET_OPTION_NAME}|/(?:password|token|secret))\s*(?:=\s*|\s+))(?!\s*\[REDACTED\])[^\s,;}}\]"']+'''
    ),
)

_URI_USERINFO = re.compile(
    r"(?i)\b(?P<scheme>https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|amqps?)://(?P<userinfo>[^/@\s]+)@"
)
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)
_COMMON_CREDENTIAL_VALUES = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    r"sk-[A-Za-z0-9_-]{8,}|"
    r"github_pat_[A-Za-z0-9_]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|"
    r"(?:AKIA|ASIA)[A-Z0-9]{16}|"
    r"AIza[0-9A-Za-z_-]{35}|"
    r"(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{12,}|whsec_[0-9A-Za-z]{12,}|"
    r"xox[baprs]-[0-9A-Za-z-]{10,}|ya29\.[0-9A-Za-z_-]{10,}|"
    r"glpat-[0-9A-Za-z_-]{12,}|npm_[0-9A-Za-z]{12,}|"
    r"(?:sq0atp|sq0csp)-[0-9A-Za-z_-]{12,}|shp(?:at|ca|pa|ss)_[0-9A-Za-z]{12,}|"
    r"GOCSPX-[0-9A-Za-z_-]{12,}|SG\.[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}|"
    r"hf_[0-9A-Za-z_-]{12,}|lin_api_[0-9A-Za-z_-]{12,}|sntrys_[0-9A-Za-z_-]{12,}"
    r")(?![A-Za-z0-9_])"
)
_SIGNED_URL_QUERY_VALUE = re.compile(
    r"(?i)(?P<prefix>(?:[?&]|&amp;)(?:"
    r"sig|(?:x-[a-z0-9-]+-)?signature|"
    r"(?:x-[a-z0-9-]+-)?credential|"
    r"sas(?:[-_]?token)?|sharedaccesssignature"
    r")=)(?!\[REDACTED\])[^&#\s\"'<>]+"
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
        clean = _SIGNED_URL_QUERY_VALUE.sub(
            lambda match: f"{match.group('prefix')}[REDACTED]",
            clean,
        )
        clean = _URI_USERINFO.sub(
            lambda match: f"{match.group('scheme')}://[REDACTED]@",
            clean,
        )
        clean = _JWT.sub("[REDACTED]", clean)
        clean = _COMMON_CREDENTIAL_VALUES.sub("[REDACTED]", clean)
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
                raise SensitivePersistenceError("attested-record-mutation")
            for key, original_hash in original.items():
                if not isinstance(key, str) or not key.endswith("_sha256"):
                    continue
                bound_key = key[:-7]
                if bound_key in original and sanitized.get(bound_key) != original.get(bound_key):
                    raise SensitivePersistenceError("hash-bound-field-mutation")
                if sanitized.get(key) != original_hash:
                    raise SensitivePersistenceError("integrity-hash-mutation")
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
                raise SensitivePersistenceError("request-manifest-bound-mutation")
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
