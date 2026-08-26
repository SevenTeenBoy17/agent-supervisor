# Installation

The installer performs no network calls and is a dry run unless `--apply` is present.
It builds a deterministic runtime bundle, validates it, installs the release beside any
previous version, backs up changed managed files, copies the thin adapters, and publishes
`ActiveVersionPointer/v4` last.

## 1. Clone and inspect

```powershell
git clone https://github.com/SevenTeenBoy17/agent-supervisor.git
Set-Location agent-supervisor
git checkout v3.1.6
python -m pip install .
python bin/install-agent-supervisor.py
```

Linux and macOS:

```bash
git clone https://github.com/SevenTeenBoy17/agent-supervisor.git
cd agent-supervisor
git checkout v3.1.6
python3 -m pip install .
python3 bin/install-agent-supervisor.py
```

The package install supplies the declared PyYAML and jsonschema dependencies used by
the isolated runtime. Review the JSON plan. Then apply it:

```powershell
python bin/install-agent-supervisor.py --apply
python "$HOME/.agent-supervisor/bin/agent-supervisor.py" --version
```

Use `python3` for those two commands on Linux and macOS. The published wheel installs
the Python core and console entry point only; it does not install the Codex or Claude
adapters. For a full adapter installation, use the tagged source tree or extract the
runtime ZIP and run its installer. The installer itself makes no network calls, but
`pip install` may need network access for PyYAML and jsonschema unless those dependencies
are already available locally.

Use `--install-home <absolute-path>` for an isolated profile and `--core-only` to omit
adapter copies. The installer does not create or change
`trusted-executables.json`, Codex hooks/`AGENTS.md`, or Claude settings.

## 2. Activate the Codex monitoring layer

The Codex files are installed at `~/.codex/skills/dev-supervisor/`. Add the following
policy to your user-level Codex `AGENTS.md` after reviewing it:

```markdown
Apply the `dev-supervisor` skill as the default monitoring layer whenever a workspace is
available. Begin each round with `scripts/supervisor-bootstrap.ps1`, pass the newest
request and classify it as continue, extend, or replace. Require criterion-bound
EvidenceRecords, independent review, registered gates, and successful finalization before
claiming completion. Project AGENTS.md and the current user request remain authoritative.
```

Complete the executable-trust step below before enabling lifecycle hooks. On Windows,
the native Codex adapter requires an exact `python` path and SHA-256 in
`trusted-executables.json`; without it the hook deliberately fails open as degraded. On
Linux and macOS, the running Python and `pwsh` must resolve through a supported,
root-owned fixed path or an exact registry entry.

If your Codex host supports project hooks, configure the installed
`scripts/codex-supervisor-hook.py` for the supported lifecycle events and confirm the
result in `/hooks` after starting a fresh task. Host hook availability is a platform
capability; do not claim it is active until a real probe reaches the adapter.

## 3. Activate the Claude adapter

The Claude files are installed at `~/.claude/skills/supervisor/`. The settings
configurator preserves unrelated settings and replaces only exact Supervisor-owned hook
entries. Run it explicitly, inspect its before/after hashes, and restart Claude Code:

The configurator intentionally refuses a missing or invalid settings file. Start Claude
Code once so it creates `~/.claude/settings.json`. If Claude has never been started, you
may instead create that file with exactly `{}` after confirming it does not already
exist; never overwrite existing settings.

```powershell
python "$HOME/.claude/skills/supervisor/scripts/configure-v3-hooks.py"
```

## 4. Configure executable trust for Codex hooks and external gates

The machine-local registry is used by the Codex lifecycle adapter as well as registered
external commands. The Windows adapter requires the exact Python executable entry shown
below. On Linux and macOS, add exact `python` and `pwsh` entries when the trusted,
root-owned fixed candidates are unavailable or when deterministic selection is desired.
Repository-declared external commands additionally remain disabled until the machine
owner registers each exact canonical argv digest.

Compute an executable SHA-256 with your operating-system tooling. Compute an exact argv
approval from the installed package:

```powershell
python -c "from supervisor_core.executable_trust import trusted_command_approval_sha256 as d; print(d([r'C:\absolute\python.exe','-m','pytest','-q']))"
```

The registry shape is:

```json
{
  "contract": "TrustedExecutableRegistry/v1",
  "entries": {
    "python": {
      "kind": "local",
      "path": "C:/absolute/python.exe",
      "sha256": "<64 lowercase hex characters>",
      "allowed_argv_sha256": ["<exact canonical argv SHA-256>"]
    }
  },
  "generated_at": "2026-08-25T00:00:00Z"
}
```

Resolve and hash the same Python that will run the hook. On Windows PowerShell:

```powershell
$PythonPath = (Get-Command python -CommandType Application -ErrorAction Stop).Source
$PythonSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PythonPath).Hash.ToLowerInvariant()
[pscustomobject]@{ path = $PythonPath; sha256 = $PythonSha256 }
```

Review those values, then place them in the `python` entry. A POSIX `pwsh` entry uses
the same `kind`, absolute `path`, and lowercase SHA-256 fields. `allowed_argv_sha256` is
not required for the lifecycle adapter itself; add it only for exact registered gate
commands.

Do not commit this file. Recompute approvals whenever an executable path, executable
bytes, or gate argv changes.

## Uninstall and rollback

The installer reports a backup directory when it replaces managed files and preserves the
prior valid release in the v4 pointer. No automatic repository-triggered rollback occurs.
Before changing an active pointer, stop running hooks, preserve the current pointer, and
validate both release bundles. There is intentionally no recursive uninstall command;
remove only explicitly inspected installation paths when you choose to uninstall.
