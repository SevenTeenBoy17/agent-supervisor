from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

import supervisor_core.discovery as discovery
from supervisor_core.discovery import RootSpec, scan_skills


class _ChangedStat:
    def __init__(self, original: os.stat_result, **changes: object) -> None:
        self._original = original
        self._changes = changes

    def __getattr__(self, name: str):
        if name in self._changes:
            return self._changes[name]
        return getattr(self._original, name)


def _write_skill(path: Path, raw: bytes) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    skill = path / "SKILL.md"
    skill.write_bytes(raw)
    return skill


def _row(inventory: dict) -> dict:
    assert len(inventory["skills"]) == 1
    return inventory["skills"][0]


def _assert_unavailable_without_leak(
    inventory: dict, *, error: str, secret: str = ""
) -> None:
    row = _row(inventory)
    assert row["availability"] == "unavailable"
    assert row["health"] == "unavailable"
    assert row["active"] is False
    assert row["automatic"] is False
    assert row["user_invocable"] is False
    assert row["error"] == error
    if secret:
        assert secret not in json.dumps(inventory, ensure_ascii=False)


def test_one_stable_snapshot_binds_metadata_body_and_hash_and_reads_content_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "skills"
    long_name = "plugin:complete:skill:name:well:beyond:thirty:characters"
    raw = (
        "---\n"
        f"name: {long_name}\n"
        "description: stable snapshot description\n"
        "disable-model-invocation: true\n"
        "dependencies: [alpha, beta]\n"
        "---\n"
        "# Stable body\n"
    ).encode("utf-8")
    skill = _write_skill(root / "stable", raw)
    expected_hash = hashlib.sha256(raw).hexdigest()
    real_open = os.open
    opens = 0

    def counted_open(path, *args, **kwargs):
        nonlocal opens
        if Path(path) == skill:
            opens += 1
        return real_open(path, *args, **kwargs)

    real_read_text = Path.read_text
    real_read_bytes = Path.read_bytes

    def forbid_text_reread(path: Path, *args, **kwargs):
        if path == skill:
            raise AssertionError("SKILL.md content was read through Path.read_text")
        return real_read_text(path, *args, **kwargs)

    def forbid_bytes_reread(path: Path, *args, **kwargs):
        if path == skill:
            raise AssertionError("SKILL.md content was read through Path.read_bytes")
        return real_read_bytes(path, *args, **kwargs)

    monkeypatch.setattr(discovery.os, "open", counted_open)
    monkeypatch.setattr(Path, "read_text", forbid_text_reread)
    monkeypatch.setattr(Path, "read_bytes", forbid_bytes_reread)

    inventory = scan_skills([RootSpec(root, "test")])
    row = _row(inventory)

    assert opens == 1
    assert row["name"] == long_name
    assert row["description"] == "stable snapshot description"
    assert row["sha256"] == expected_hash
    assert row["dependencies"] == ["alpha", "beta"]
    assert row["manual_only"] is True
    assert row["automatic"] is False
    assert row["availability"] == "enabled"
    assert row["health"] == "healthy"
    assert inventory["counts"]["long_names_active_gt_30"] == 1


def test_crlf_parser_normalization_preserves_raw_byte_hash(tmp_path: Path) -> None:
    raw = (
        b"---\r\n"
        b"name: crlf-skill\r\n"
        b"description: crlf metadata\r\n"
        b"---\r\n"
        b"# CRLF body\r\n"
        b"second line\r\n"
    )
    skill = _write_skill(tmp_path / "crlf", raw)

    metadata, body, digest = discovery._read_stable_skill(skill)

    assert digest == hashlib.sha256(raw).hexdigest()
    assert metadata == {"name": "crlf-skill", "description": "crlf metadata"}
    assert body == "# CRLF body\nsecond line\n"
    assert "\r" not in body


@pytest.mark.parametrize(
    ("field", "change"),
    [
        ("st_size", lambda value: value + 1),
        ("st_mtime_ns", lambda value: value + 1),
        ("st_ino", lambda value: value + 1),
    ],
    ids=["size", "mtime", "inode"],
)
def test_descriptor_change_during_read_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    change,
) -> None:
    root = tmp_path / "skills"
    skill = _write_skill(
        root / "changing",
        b"---\nname: changing-skill\ndescription: stable\n---\n# Body\n",
    )
    real_fstat = os.fstat
    calls = 0

    def changed_fstat(fd: int):
        nonlocal calls
        result = real_fstat(fd)
        calls += 1
        if calls >= 2:
            return _ChangedStat(result, **{field: change(getattr(result, field))})
        return result

    monkeypatch.setattr(discovery.os, "fstat", changed_fstat)

    inventory = scan_skills([RootSpec(root, "test")])

    assert calls >= 2
    _assert_unavailable_without_leak(
        inventory, error="skill-read-file-changed"
    )
    assert _row(inventory)["sha256"] == ""
    assert Path(_row(inventory)["path"]) == skill


def test_path_identity_replacement_during_read_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "skills"
    skill = _write_skill(
        root / "path-race",
        b"---\nname: path-race\ndescription: stable\n---\n# Body\n",
    )
    real_lstat = Path.lstat
    calls = 0

    def changed_lstat(path: Path):
        nonlocal calls
        result = real_lstat(path)
        if path == skill:
            calls += 1
            if calls >= 2:
                return _ChangedStat(result, st_ino=result.st_ino + 1)
        return result

    monkeypatch.setattr(Path, "lstat", changed_lstat)

    inventory = scan_skills([RootSpec(root, "test")])

    assert calls >= 2
    _assert_unavailable_without_leak(
        inventory, error="skill-read-file-changed"
    )


def test_symlink_replacement_during_read_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "skills"
    skill = _write_skill(
        root / "link-race",
        b"---\nname: link-race\ndescription: stable\n---\n# Body\n",
    )
    real_lstat = Path.lstat
    calls = 0

    def linked_lstat(path: Path):
        nonlocal calls
        result = real_lstat(path)
        if path == skill:
            calls += 1
            if calls >= 2:
                return _ChangedStat(
                    result,
                    st_mode=stat.S_IFLNK | stat.S_IRUSR,
                )
        return result

    monkeypatch.setattr(Path, "lstat", linked_lstat)

    inventory = scan_skills([RootSpec(root, "test")])

    assert calls >= 2
    _assert_unavailable_without_leak(
        inventory, error="skill-read-link-or-reparse"
    )


def test_reparse_reclassification_during_read_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "skills"
    skill = _write_skill(
        root / "reparse-race",
        b"---\nname: reparse-race\ndescription: stable\n---\n# Body\n",
    )
    real_check = discovery._is_link_or_reparse
    calls = 0

    def changed_classification(path: Path, metadata=None) -> bool:
        nonlocal calls
        if path == skill:
            calls += 1
            if calls >= 2:
                return True
        return real_check(path, metadata)

    monkeypatch.setattr(discovery, "_is_link_or_reparse", changed_classification)

    inventory = scan_skills([RootSpec(root, "test")])

    assert calls >= 2
    _assert_unavailable_without_leak(
        inventory, error="skill-read-link-or-reparse"
    )


def test_invalid_utf8_is_stably_unavailable_without_content_leak(tmp_path: Path) -> None:
    root = tmp_path / "skills"
    secret = "PRIVATE_UTF8_SENTINEL"
    _write_skill(
        root / "invalid-utf8",
        b"---\nname: invalid-utf8\ndescription: "
        + secret.encode("ascii")
        + b"\xff\n---\n# Body\n",
    )

    inventory = scan_skills([RootSpec(root, "test")])

    _assert_unavailable_without_leak(
        inventory,
        error="skill-read-utf8-invalid",
        secret=secret,
    )


def test_invalid_yaml_is_stably_unavailable_without_content_leak(tmp_path: Path) -> None:
    root = tmp_path / "skills"
    secret = "PRIVATE_YAML_SENTINEL"
    _write_skill(
        root / "invalid-yaml",
        (
            "---\n"
            "name: [unterminated\n"
            f"description: {secret}\n"
            "---\n"
            "# Body\n"
        ).encode("utf-8"),
    )

    inventory = scan_skills([RootSpec(root, "test")])

    _assert_unavailable_without_leak(
        inventory,
        error="skill-read-yaml-invalid",
        secret=secret,
    )
