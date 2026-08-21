from __future__ import annotations

import sys
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
pointer_path = Path(os.environ.get("AGENT_SUPERVISOR_ACTIVE_POINTER", ROOT / "active-version.json"))
try:
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    active = Path(str(pointer.get("active", {}).get("path", "")))
    if (active / "supervisor_core").is_dir():
        ROOT = active
except (OSError, ValueError, TypeError):
    pass
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from supervisor_core.cli import main

raise SystemExit(main())
