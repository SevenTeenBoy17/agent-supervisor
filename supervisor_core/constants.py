from __future__ import annotations

EXIT_COMPLETE = 0
EXIT_INCOMPLETE = 2
EXIT_BLOCKED = 3
EXIT_DEGRADED = 4
EXIT_INVALID = 64

TERMINAL_STATES = {"complete", "incomplete", "blocked", "user-waived"}
CHANGE_MODES = {"continue", "extend", "replace"}
EXECUTION_MODES = {"observe", "warn", "enforce"}
INTENT_STATES = {"covered", "skipped", "deferred", "unavailable", "failed"}
REVIEW_VERDICTS = {"APPROVE", "REQUEST_CHANGES", "NEEDS_DISCUSSION"}

DEFAULT_STATE_ROOT = ".agent-supervisor/state"
DEFAULT_MAX_EVENT_BYTES = 5 * 1024 * 1024
DEFAULT_ROTATIONS = 5
DEFAULT_RETENTION_DAYS = 30
