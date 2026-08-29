# Installation

The installer performs no network calls and is a dry run unless `--apply` is present.
It builds a deterministic runtime bundle, validates it, installs the release beside any
previous version, backs up changed managed files, copies the thin adapters, and publishes
`ActiveVersionPointer/v4` last.

## 1. Clone and inspect

```powershell
git clone https://github.com/SevenTeenBoy17/agent-supervisor.git
Set-Location agent-supervisor
git checkout v3.1.12
python -m pip install .
python bin/install-agent-supervisor.py --no-codex-global-activation
```

Linux and macOS:

```bash
git clone https://github.com/SevenTeenBoy17/agent-supervisor.git
cd agent-supervisor
git checkout v3.1.12
python3 -m pip install .
python3 bin/install-agent-supervisor.py --no-codex-global-activation
```

The package install supplies the declared PyYAML and jsonschema dependencies used by
the isolated runtime. Review the JSON plan. The first applied pass intentionally
installs the core and adapters without writing global Codex hooks:

```powershell
python bin/install-agent-supervisor.py --no-codex-global-activation --apply
python "$HOME/.agent-supervisor/bin/agent-supervisor.py" --version
```

Use `python3` for those two commands on Linux and macOS. The published wheel installs
the Python core and console entry point only; it does not install the Codex or Claude
adapters. For a full adapter installation, use the tagged source tree or extract the
runtime ZIP and run its installer. The installer itself makes no network calls, but
`pip install` may need network access for PyYAML and jsonschema unless those dependencies
are already available locally.

Complete the executable-trust step below, then return to the Codex activation step and
run the installer without `--no-codex-global-activation`. This ordering prevents a new
global hook from running before its exact Python executable is trusted.

Use `--install-home <absolute-path>` for an isolated profile and `--core-only` to omit
adapter copies. A normal adapter install merges Agent Supervisor into the user-level
Codex `hooks.json` and inserts one replaceable managed block in `AGENTS.md`; it preserves
unrelated entries and backs up changed files. Use `--no-codex-global-activation` to
install adapters without those two Codex activation changes. The installer does not
change `trusted-executables.json` or Claude settings.

When upgrading from an earlier v3.1.x installation, use the same two-pass sequence:
first apply with `--no-codex-global-activation`, refresh executable trust if the Python
path or hash changed, and only then apply without the opt-out flag. The final pass
replaces the legacy PATH-resolved Codex handler with commands bound to the installer
Python while preserving unrelated hooks.

## 2. Configure executable trust for Codex hooks and external gates

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

## 3. Activate the Codex monitoring layer

The Codex files are installed at `~/.codex/skills/dev-supervisor/`. The installer also
creates or merges `~/.codex/hooks.json` and a marked global policy block in
`~/.codex/AGENTS.md`. Those user-level hooks are discovered in every project, including
projects without `.codex/hooks.json`.

After the trust registry is ready, review the normal plan and enable the global layer:

```powershell
python bin/install-agent-supervisor.py
python bin/install-agent-supervisor.py --apply
```

Use `python3` on Linux and macOS. On Windows, the native Codex adapter requires the exact
`python` path and SHA-256 in `trusted-executables.json`; without it the hook deliberately
fails open as degraded. On Linux and macOS, the running Python and `pwsh` must resolve
through a supported, root-owned fixed path or an exact registry entry.

Open `/hooks`, review and trust the user-level Agent Supervisor definitions, then start
a fresh task. In `enforce` mode, the Stop hook requests one bounded continuation whenever
the assistant's last message omits the rendered `RoundProcessSummary/v1`. In `observe`
and `warn` modes it records the omission as an advisory warning without blocking the
host loop. The supplied summary contains the timestamped Skill/Agent/Plugin/native-command
timeline and completed contribution for each signed invocation. Host hook availability
remains a platform capability; do not claim activation until `/hooks` lists the user
source and a fresh-session probe reaches the adapter.

## 4. Activate the Claude adapter

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

## Uninstall and rollback

The installer reports a backup directory when it replaces managed files and preserves the
prior valid release in the v4 pointer. No automatic repository-triggered rollback occurs.
Before changing an active pointer, stop running hooks, preserve the current pointer, and
validate both release bundles. There is intentionally no recursive uninstall command;
remove only explicitly inspected installation paths when you choose to uninstall.
