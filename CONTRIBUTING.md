# Contributing

Thank you for improving Agent Supervisor.

## Development setup

```powershell
git clone https://github.com/SevenTeenBoy17/agent-supervisor.git
Set-Location agent-supervisor
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\python -m pytest -q
```

Use Python 3.11 or newer. On macOS/Linux, invoke `.venv/bin/python` instead.

## Change requirements

- Preserve unrelated user work and keep each change narrowly scoped.
- Add a focused regression test before fixing a security or correctness defect.
- Do not delete tests, add unexplained skips, weaken assertions, or relax thresholds to
  obtain a green run.
- Keep runtime, adapters, schemas, version fields, and release manifests aligned.
- Never commit credentials, `trusted-executables.json`, active pointers, attestations,
  raw prompts, logs, state, or workstation-specific paths.
- Security-sensitive changes need an independent implementation review and a separate
  test-integrity review when tests change.

## Pull requests

Describe the goal, affected contracts, risk tier, rollback, exact validation commands,
and any degraded platform coverage. By submitting a contribution, you agree that it is
licensed under Apache-2.0.

