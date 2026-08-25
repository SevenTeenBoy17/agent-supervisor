# Supervisor v8 archive notice

The following files are retained only for forensic replay and rollback. Claude's active
hook configuration and the v3 Skill do not reference them:

- `scripts/sup-log.py`
- `scripts/sup-discover.py` (retained only for import-safety regression coverage)
- `scripts/sup-plan.py`
- `scripts/sup-query.py`
- `scripts/sup-report.py`
- `scripts/sup-log.v*.backup.py`
- `scripts/sup-plan.v*.backup.py`
- `tests/test_dispatch_ledger.py`
- `tests/test_precision.py`
- `tests/test_retrieval.py`
- `tests/test_verifier.py`

The legacy test files are process-level harnesses that execute at import and call
`sys.exit`; `tests/conftest.py` excludes them from pytest collection. Supervisor v3 uses
`tests/test_v3_adapter.py` plus the shared core's complete selftest suite.

Do not route new work through these files. Restore them only as part of an explicit,
audited rollback using the pre-v3 hash manifest.
