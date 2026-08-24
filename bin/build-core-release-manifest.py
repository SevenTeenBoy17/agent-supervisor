from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from supervisor_core.runtime_bundle import build_runtime_bundle, release_identity


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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

    root = args.root.expanduser().resolve(strict=True)
    output = args.output.expanduser()
    if not output.is_absolute():
        output = root / output
    output = Path(os.path.abspath(os.fspath(output)))
    bundle = build_runtime_bundle(root, args.version)
    _atomic_write(output, bundle)
    identity = release_identity(
        root,
        args.version,
        output.relative_to(root).as_posix(),
        bundle,
    )
    if args.identity_output is not None:
        identity_output = args.identity_output.expanduser()
        if not identity_output.is_absolute():
            identity_output = root / identity_output
        _atomic_write(
            Path(os.path.abspath(os.fspath(identity_output))),
            json.dumps(
                identity,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
        )
    print(json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
