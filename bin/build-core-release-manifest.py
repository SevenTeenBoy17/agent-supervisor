from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from supervisor_core.runtime_bundle import (
    RuntimeBundleError,
    build_runtime_bundle,
    inspect_runtime_bundle,
    release_identity,
)


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _is_link_or_reparse(path: Path) -> bool:
    details = path.lstat()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(details, "st_file_attributes", 0)
    return stat.S_ISLNK(details.st_mode) or bool(reparse_flag and attributes & reparse_flag)


def _reject_existing_indirection(path: Path) -> None:
    lexical = Path(os.path.abspath(os.fspath(Path(path).expanduser())))
    anchor = Path(lexical.anchor)
    current = anchor
    for part in lexical.relative_to(anchor).parts:
        current /= part
        if not current.exists() and not current.is_symlink():
            continue
        try:
            if _is_link_or_reparse(current):
                raise ValueError(
                    "output path is outside release root or contains a symlink or reparse point"
                )
        except OSError as exc:
            raise ValueError("output path component is unavailable") from exc


def _contained_output(root: Path, candidate: Path) -> Path:
    """Resolve one output beneath the physical release root."""
    root_lexical = Path(os.path.abspath(os.fspath(Path(root).expanduser())))
    _reject_existing_indirection(root_lexical)
    release_root = root_lexical.resolve(strict=True)
    requested = Path(candidate).expanduser()
    if not requested.is_absolute():
        requested = release_root / requested
    lexical = Path(os.path.abspath(os.fspath(requested)))
    try:
        lexical_relative = lexical.relative_to(release_root)
        if not lexical_relative.parts:
            raise ValueError("output path must name a file within release root")
        _reject_existing_indirection(lexical)
        resolved = lexical.resolve(strict=False)
        relative = resolved.relative_to(release_root)
    except (OSError, RuntimeError, ValueError) as exc:
        if isinstance(exc, ValueError) and "output path" in str(exc):
            raise
        raise ValueError("output path is outside release root") from exc
    if not relative.parts:
        raise ValueError("output path must name a file within release root")
    if resolved.exists() and not resolved.is_file():
        raise ValueError("output path must name a regular file")
    return resolved


def _same_output(first: Path, second: Path) -> bool:
    if os.path.normcase(str(first)) == os.path.normcase(str(second)):
        return True
    try:
        return first.exists() and second.exists() and os.path.samefile(first, second)
    except OSError:
        return False


def _validate_distinct_outputs(output: Path, identity_output: Path) -> None:
    if (
        _same_output(output, identity_output)
        or output in identity_output.parents
        or identity_output in output.parents
    ):
        raise ValueError("bundle and identity output paths must be distinct files")


def _stage_bytes(path: Path, content: bytes) -> Path:
    """Durably stage bytes beside their destination without publishing them."""
    _reject_existing_indirection(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_existing_indirection(path.parent)
    descriptor, temporary = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".stage",
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return Path(temporary)


def _read_staged_bytes(path: Path) -> bytes:
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeBundleError("staged-artifact-invalid")
    with path.open("rb") as handle:
        content = handle.read()
    after = path.stat(follow_symlinks=False)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or len(content) != before.st_size:
        raise RuntimeBundleError("staged-artifact-changed")
    return content


def _discard_stage(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _atomic_write(path: Path, content: bytes) -> None:
    _reject_existing_indirection(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_existing_indirection(path.parent)
    if path.exists() or path.is_symlink():
        _reject_existing_indirection(path)
    descriptor, temporary = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _reject_existing_indirection(path.parent)
        if path.exists() or path.is_symlink():
            _reject_existing_indirection(path)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--identity-output", type=Path)
    args = parser.parse_args()

    root_lexical = Path(os.path.abspath(os.fspath(args.root.expanduser())))
    _reject_existing_indirection(root_lexical)
    root = root_lexical.resolve(strict=True)
    output = _contained_output(root, args.output)
    identity_output = (
        _contained_output(root, args.identity_output)
        if args.identity_output is not None
        else None
    )
    if identity_output is not None:
        _validate_distinct_outputs(output, identity_output)

    bundle = build_runtime_bundle(root, args.version)
    identity = release_identity(
        root,
        args.version,
        output.relative_to(root).as_posix(),
        bundle,
    )
    identity_bytes = _canonical_json_bytes(identity)

    staged_bundle: Path | None = None
    staged_identity: Path | None = None
    try:
        staged_bundle = _stage_bytes(output, bundle)
        if identity_output is not None:
            staged_identity = _stage_bytes(identity_output, identity_bytes)

        verified_bundle = _read_staged_bytes(staged_bundle)
        verified_identity_bytes = (
            _read_staged_bytes(staged_identity)
            if staged_identity is not None
            else identity_bytes
        )
        if verified_identity_bytes != identity_bytes:
            raise RuntimeBundleError("staged-identity-mismatch")
        try:
            verified_identity = json.loads(verified_identity_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeBundleError("staged-identity-invalid") from exc
        if (
            not isinstance(verified_identity, dict)
            or verified_identity_bytes != _canonical_json_bytes(verified_identity)
        ):
            raise RuntimeBundleError("staged-identity-invalid")
        inspect_runtime_bundle(
            verified_bundle,
            expected_identity=verified_identity,
        )
    finally:
        _discard_stage(staged_identity)
        _discard_stage(staged_bundle)

    # Re-resolve immediately before publication so a changed parent cannot
    # redirect either atomic replacement outside the release root.
    if _contained_output(root, output) != output:
        raise ValueError("bundle output path changed before publication")
    if identity_output is not None:
        if _contained_output(root, identity_output) != identity_output:
            raise ValueError("identity output path changed before publication")
        _validate_distinct_outputs(output, identity_output)

    # The identity is the discovery marker.  Publish the validated payload
    # first, then publish the identity last so a consumer can never discover an
    # identity for a missing or only partially written bundle.
    _atomic_write(output, bundle)
    if identity_output is not None:
        if _contained_output(root, identity_output) != identity_output:
            raise ValueError("identity output path changed before publication")
        _validate_distinct_outputs(output, identity_output)
        _atomic_write(identity_output, identity_bytes)
    print(identity_bytes.decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
