#!/usr/bin/env python3
"""Supervisor event logger v4 — called by Claude Code hooks.

Usage: python sup-log.py <event-type> [extra-info...]

Events:
  session-start
  prompt-submit   — user submitted a prompt; resets per-turn state, injects banner
  pre-tool        — about to run a tool (name from stdin JSON or argv[2])
  post-tool       — finished a tool
  stop            — turn ending; HARD-GATES the brief report when dev work happened

v4 (P0 upgrade, 2026-07-02):
  ① Per-project context: ~/.claude/supervisor/state/contexts/<key>.md selected by stdin `cwd`
     (NOT ~/.claude/skills/supervisor/state/contexts/ - that legacy dir is never read)
     (walks up 3 parents; NEVER injects another project's context)
  ② Stop true gate: returns {"decision":"block","reason":...} ONCE per dev turn
     (honors stop_hook_active; anti-infinite-loop via state flag)
  ③ Conditional banner: classifies stdin `prompt` — full protocol for dev turns,
     one-line lite banner for chat/slash/non-dev turns
  ④ (companion change) supervisor agent frontmatter downgraded to sonnet

The script must NEVER break the conversation: every branch is fail-open.
"""
from __future__ import annotations
import io
import hashlib
import json
import os
import re
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Force UTF-8 stdout on Windows (Python 3.7+); silently no-op elsewhere
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


SUP_HOME = Path.home() / ".claude" / "supervisor"
LOG_DIR = SUP_HOME / "logs"
STATE_DIR = SUP_HOME / "state"
CONTEXTS_DIR = STATE_DIR / "contexts"   # v4: per-project context files
TRANSCRIPTS_DIR = SUP_HOME / "transcripts"
PROMPT_ARCHIVE_ENABLED = os.environ.get(
    "SUPERVISOR_LEGACY_PERSIST_PROMPTS", ""
).strip().casefold() in {"1", "true", "yes"}


def _ensure_private_directory(path: Path) -> None:
    """Create one directory with owner-only access where POSIX modes apply."""
    if path.is_symlink():
        raise OSError("private-directory-link-rejected")
    path.mkdir(mode=0o700, exist_ok=True)
    absolute = Path(os.path.abspath(os.fspath(path)))
    if (
        path.is_symlink()
        or not path.is_dir()
        or os.path.normcase(os.path.realpath(os.fspath(absolute)))
        != os.path.normcase(str(absolute))
    ):
        raise OSError("private-directory-link-rejected")
    if os.name == "posix":
        path.chmod(0o700)


def _is_reparse_info(info: os.stat_result) -> bool:
    return bool(
        stat.S_ISLNK(info.st_mode)
        or (
            hasattr(info, "st_file_attributes")
            and bool(
                info.st_file_attributes
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            )
        )
    )


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns) if os.name == "posix" else 0,
    )


def _private_text_open(path: Path, flags: int, mode: str, *, newline=None):
    """Open one link-free regular text file and constrain it to mode 0600."""
    try:
        before = path.lstat()
    except FileNotFoundError:
        before = None
    if before is not None and (
        _is_reparse_info(before) or not stat.S_ISREG(before.st_mode)
    ):
        raise OSError("private-file-link-rejected")
    descriptor = os.open(
        str(path),
        flags | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError("private-file-not-regular")
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
            opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            _is_reparse_info(current)
            or not stat.S_ISREG(current.st_mode)
            or _file_identity(opened) != _file_identity(current)
        ):
            raise OSError("private-file-path-changed")
        return os.fdopen(
            descriptor,
            mode,
            encoding="utf-8",
            newline=newline,
            closefd=True,
        )
    except Exception:
        os.close(descriptor)
        raise


STORAGE_READY = True
try:
    claude_home = SUP_HOME.parent
    claude_home_created = not claude_home.exists()
    claude_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    if claude_home_created and os.name == "posix":
        claude_home.chmod(0o700)
except OSError:
    STORAGE_READY = False
for d in (SUP_HOME, LOG_DIR, STATE_DIR, CONTEXTS_DIR, TRANSCRIPTS_DIR):
    try:
        _ensure_private_directory(d)
    except OSError:
        # Legacy hooks are fail-open. Remember initialization failure so later
        # helpers neither raise nor claim that a write happened.
        STORAGE_READY = False

turn_marker_file = STATE_DIR / "current-turn.json"
LOG_FILE_NAME = re.compile(r"^sup-\d{8}\.jsonl$")
STATE_FILE_NAME = re.compile(r"^current-turn-[0-9a-f]{16}\.json$")
TRANSCRIPT_FILE_NAME = re.compile(r"^\d{4}-\d{2}\.md$")
SESSION_ID_VALUE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
PROJECT_KEY_INVALID = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
PROJECT_KEY_MAX_CHARS = 180
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *("COM" + str(index) for index in range(1, 10)),
    *("LPT" + str(index) for index in range(1, 10)),
}


def _current_log_file() -> Path:
    """Resolve the daily event log at use time, including midnight rollover."""
    return LOG_DIR / f"sup-{datetime.now().strftime('%Y%m%d')}.jsonl"

# Tools that count as "dev work" for the Stop gate
DEV_TOOLS = {"Edit", "Write", "NotebookEdit", "MultiEdit"}
# Tools echoed to the status line (avoid spam for the rest)
ECHO_TOOLS = {"Skill", "Agent", "TaskCreate", "TaskUpdate"}

# Dev-intent classifier for the conditional banner (zh + en, deliberately recall-biased)
# v5: 词表扩容 —— v4 版对『视觉审美/排版/资产/数据』类请求漏判率实测 90%
# (用户真实原话样本 10 条中 9 条被误判为非研发轮 -> 协议不注入 -> 监工形同虚设)
DEV_SIGNAL = re.compile(
    r"(做|写|改|修|审|调试|规划|提交|优化|重构|部署|测试|实现|开发|构建|上线|排查|报错|接口|组件|页面|样式|前端|后端|全栈"
    r"|美观|好看|难看|高级|不满意|风格|视觉|设计感|质感|精致|粗糙|激发|兴趣|吸引"
    r"|排版|布局|对齐|居中|留白|间距|边距|大小|尺寸|比例|扁平|矮胖|平铺|展开|收起|折叠|溢出|显示不全|挡住|遮挡|错位|层级"
    r"|图片|图标|图案|插画|卡片|按钮|字体|字号|文字|颜色|配色|色调|背景|边框|阴影|圆角|动效|动画|过渡|交互|悬停|轮播|滚动"
    r"|文案|标题|说明|太多|过多|简化|精简|少即是多|删去|删掉|去掉|替换|重做|重新|调整|升级|完善"
    r"|数据|账号|登录|注册|权限|隔离|演示|真实用户|数据库|缓存|会话|状态"
    r"|生图|素材|模型|渲染|IP形象|形象|调研|检索|参考|借鉴|对比|方案"
    r"|调用|调用库|派单|调度|触发|规则|条件|限制|上限|下限|数量|台账|清单|简报|回执|时间节点"
    r"|返回|输出|验证|复核|核查|交付|安装|新增|卸载|配置|钩子|权限|流程|机制|工作规则|自检|门禁"
    r"|监工|升级|排查|梳理|盘点|覆盖|遗漏|偷懒|不够全面|不够灵活"
    r"|skill|agent|plugin|connector|mcp|hook|workflow|subagent|supervisor|ledger|dispatch"
    r"|浏览器|网页|应用|端口|服务|启动|重启|跑一下|运行|环境|本地|线上|预览"
    r"|待跟进|跟进|剩下|未完成|没做完|收尾|接着|上次|遗留|欠的|补齐|补上|补完"
    r"|完成|继续完成|做完|搞定|落地|交付物"
    r"|build|implement|cod(e|ing)|fix|debug|review|refactor|optimi[sz]e|deploy|test|ship|commit|design|create|develop"
    r"|frontend|backend|api|bug|component|layout|css|refine|audit|critique|polish"
    r"|ugly|beautiful|premium|spacing|padding|margin|align|crop|overflow|icon|font|color|animation|render|asset|表结构|建表|字段|索引|主键|外键|迁移|数据模型|数据表|建模|schema|图表|折线图|柱状图|饼图|看板|仪表盘|可视化|统计|报表|chart|dashboard|课件|教案|讲义|教学|课程|试卷|习题|题库|知识点|设计|清洗|脏数据|去重|归一|论文|文献|综述|投稿|算法|性能|并发|超时|日志|埋点|监控|限流|重试)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------- state/io ---

def read_stdin_json() -> dict:
    """Read the hook payload as BYTES, then decode UTF-8 explicitly.

    Do NOT use text-mode sys.stdin here. On a zh-CN Windows box sys.stdin.encoding
    is gbk/cp936 while Claude Code writes UTF-8, so any CJK payload raised inside
    this function and the old bare `except` swallowed it into {} - losing the prompt
    and the tool name. Measured before this fix: 1507/1772 (85%) of prompt-submit
    rows had an empty payload and the full protocol fired on only 4.6% of turns.
    """
    if sys.stdin.isatty():
        return {}
    try:
        raw = sys.stdin.buffer.read()
    except Exception:
        try:
            raw = sys.stdin.read().encode("utf-8", "replace")
        except Exception:
            return {}
    if not raw or not raw.strip():
        return {}
    for enc in ("utf-8", "utf-8-sig", "gbk", "cp936"):
        try:
            return json.loads(raw.decode(enc))
        except Exception:
            continue
    try:  # last resort: never lose the payload just because one byte is bad
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {}


def append_event(event: dict) -> bool:
    if _current_sid and not event.get("sid"):
        event["sid"] = _current_sid
    event["ts"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if DRYRUN or not STORAGE_READY:
        return False
    log_file = _current_log_file()
    fd, lock = _acquire_state_lock(lock_path=_log_lock_file(log_file))
    if fd is None:
        return False
    try:
        with _private_text_open(
            log_file,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            "a",
        ) as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
        return True
    except Exception:
        return False  # hooks must never break the conversation
    finally:
        _release_state_lock(fd, lock)


_current_sid = ""          # set once per invocation from the hook payload


def _validated_session_id(value) -> str:
    if not isinstance(value, str) or not SESSION_ID_VALUE.fullmatch(value):
        return ""
    return value


def _stable_full_value_token(value) -> str:
    """Hash a complete opaque host id without persisting any raw portion."""
    try:
        raw = str(value) if value is not None else ""
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16] if raw else ""
    except Exception:
        return ""


def _session_token(value) -> str:
    """Stable non-reversible token over the complete host session id."""
    try:
        raw = _validated_session_id(value)
        return _stable_full_value_token(raw)
    except Exception:
        return ""


def set_session(stdin_data: dict) -> None:
    """Remember which Claude session this hook invocation belongs to.

    Before this existed, every concurrent session shared one current-turn.json:
    session B starting a turn reset session A's dev_tool_used/stop_blocked and
    silently disarmed A's Stop gate.
    """
    global _current_sid
    try:
        sid = stdin_data.get("session_id") or stdin_data.get("sessionId") or ""
        # Never persist the raw id. Hash the complete value so ids sharing a prefix
        # cannot collide while every event/state file still uses one stable token.
        _current_sid = _session_token(sid)
    except Exception:
        _current_sid = ""


def _state_file():
    if _current_sid:
        return STATE_DIR / ("current-turn-" + _current_sid + ".json")
    return turn_marker_file          # legacy shared file when the id is unknown


def read_turn_state() -> dict:
    f = _state_file()
    try:
        if f.exists():
            return json.loads(f.read_text(encoding="utf-8"))
        # first touch for this session: inherit the legacy file so an in-flight
        # turn is not lost the moment we switch to per-session state
        if _current_sid and turn_marker_file.exists():
            st = json.loads(turn_marker_file.read_text(encoding="utf-8"))
            st["session_id"] = _current_sid
            return st
    except Exception:
        pass
    return {"session_id": _current_sid} if _current_sid else {}


DRYRUN = os.environ.get("SUP_DRYRUN", "") not in ("", "0", "false", "False")


def write_turn_state(state: dict) -> bool:
    # Guard against a verification run trampling the LIVE turn state. Learned the hard
    # way 2026-08-20: an ad-hoc "end-to-end check" invoked prompt-submit against the real
    # HOME with the real session id, which reset turn_started_at and blanked that turn's
    # ledger window. Tests must use an isolated HOME or SUP_DRYRUN=1.
    if DRYRUN or not STORAGE_READY:
        return False
    target = _state_file()
    temporary = target.with_name(
        target.name + "." + str(os.getpid()) + "." + str(time.time_ns()) + ".tmp"
    )
    try:
        if _current_sid:
            state["session_id"] = _current_sid   # makes render_ledger's filter live
        with _private_text_open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            "w",
        ) as handle:
            handle.write(json.dumps(state, ensure_ascii=False))
        os.replace(temporary, target)
        return True
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        return False


def _state_lock_file() -> Path:
    state_file = _state_file()
    return state_file.with_name(state_file.name + ".lock")


def _log_lock_file(log_file: Path) -> Path:
    """One process-safe lock per daily JSONL file, shared across sessions."""
    return log_file.with_name(log_file.name + ".lock")


def _acquire_state_lock(timeout_seconds: float = 1.5, lock_path: Path | None = None):
    """Acquire an exclusive lock for state or another Supervisor-owned file."""
    lock = lock_path if lock_path is not None else _state_lock_file()
    deadline = time.monotonic() + timeout_seconds
    windows_permission_retries = 0
    try:
        lock.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None, lock
    while time.monotonic() < deadline:
        try:
            descriptor = os.open(
                str(lock),
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0),
                0o600,
            )
            try:
                if os.name == "posix":
                    os.fchmod(descriptor, 0o600)
            except OSError:
                os.close(descriptor)
                raise
            return descriptor, lock
        except FileExistsError:
            try:
                if time.time() - lock.stat().st_mtime > 30:
                    lock.unlink(missing_ok=True)
                    continue
            except OSError:
                pass
            time.sleep(0.01)
        except PermissionError:
            # Windows can report access denied while the prior owner has closed
            # and unlinked the lock but NTFS is still completing delete-pending.
            # Treat that bounded platform state as contention; other platforms
            # retain the immediate fail-open behavior for a real permission fault.
            if os.name != "nt" or windows_permission_retries >= 3:
                return None, lock
            windows_permission_retries += 1
            time.sleep(0.01)
        except OSError:
            return None, lock
    return None, lock


def _release_state_lock(fd, lock: Path) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass
    try:
        lock.unlink(missing_ok=True)
    except OSError:
        pass


def _update_turn_state(mutator):
    """Serialize one session-scoped read/modify/write and return its new snapshot."""
    if DRYRUN or not STORAGE_READY:
        state = read_turn_state()
        mutator(state)
        write_turn_state(state)
        return state
    fd, lock = _acquire_state_lock()
    if fd is None:
        return None
    try:
        state = read_turn_state()
        mutator(state)
        return state if write_turn_state(state) else None
    finally:
        _release_state_lock(fd, lock)


def _safe_direct_children(root: Path):
    """Return only lexical, non-link children of one validated directory."""
    try:
        root_abs = Path(os.path.abspath(os.fspath(root)))
        root_key = os.path.normcase(str(root_abs))
        if os.path.normcase(os.path.realpath(os.fspath(root_abs))) != root_key:
            return ()
        if not root_abs.is_dir():
            return ()
        children = []
        for child in root_abs.iterdir():
            try:
                child_abs = Path(os.path.abspath(os.fspath(child)))
                if os.path.normcase(str(child_abs.parent)) != root_key:
                    continue
                if os.path.normcase(os.path.realpath(os.fspath(child_abs))) != os.path.normcase(str(child_abs)):
                    continue
                children.append(child_abs)
            except Exception:
                continue
        return tuple(children)
    except Exception:
        return ()


def _confined_direct_child(root: Path, name: str):
    """Return one non-link direct child, or None when it can escape ``root``."""
    try:
        if (
            not isinstance(name, str)
            or not name
            or name in (".", "..")
            or any(char in name for char in ("/", "\\", ":", "\x00"))
        ):
            return None
        root_abs = Path(os.path.abspath(os.fspath(root)))
        root_key = os.path.normcase(str(root_abs))
        if os.path.normcase(os.path.realpath(os.fspath(root_abs))) != root_key:
            return None
        candidate = Path(os.path.abspath(os.fspath(root_abs / name)))
        if os.path.normcase(str(candidate.parent)) != root_key:
            return None
        if candidate.is_symlink():
            return None
        if candidate.exists() and (
            os.path.normcase(os.path.realpath(os.fspath(candidate)))
            != os.path.normcase(str(candidate))
        ):
            return None
        return candidate
    except (OSError, TypeError, ValueError):
        return None


def _prune_old_direct_files(root: Path, name_pattern, cut: float, protected_names=()) -> None:
    protected = set(protected_names)
    for candidate in _safe_direct_children(root):
        snapshot = None
        try:
            if candidate.name in protected or not name_pattern.fullmatch(candidate.name):
                continue
            if candidate.is_symlink() or not candidate.is_file():
                continue
            initial = candidate.stat(follow_symlinks=False)
            snapshot = (
                initial.st_dev, initial.st_ino, initial.st_size,
                initial.st_mtime_ns, initial.st_mode,
            )
            if initial.st_mtime >= cut:
                continue
        except Exception:
            continue
        fd, lock = _acquire_state_lock(
            timeout_seconds=0.25,
            lock_path=candidate.with_name(candidate.name + ".retention.lock"),
        )
        if fd is None:
            continue
        try:
            if candidate.is_symlink() or not candidate.is_file():
                continue
            current = candidate.stat(follow_symlinks=False)
            current_snapshot = (
                current.st_dev, current.st_ino, current.st_size,
                current.st_mtime_ns, current.st_mode,
            )
            if current_snapshot == snapshot and current.st_mtime < cut:
                candidate.unlink()
        except Exception:
            continue
        finally:
            _release_state_lock(fd, lock)


def prune_state_files(keep_days: int = 3) -> None:
    """Prune validated legacy state/log/transcript files. Best effort, never raises."""
    if not STORAGE_READY:
        return
    try:
        days = float(keep_days)
        if not 0 <= days < float("inf"):
            return
        cut = time.time() - days * 86400
        _prune_old_direct_files(
            STATE_DIR,
            STATE_FILE_NAME,
            cut,
            protected_names=(_state_file().name,),
        )
        _prune_old_direct_files(
            LOG_DIR,
            LOG_FILE_NAME,
            cut,
            protected_names=(_current_log_file().name,),
        )
        current_transcript = datetime.now().strftime("%Y-%m") + ".md"
        for project_dir in _safe_direct_children(TRANSCRIPTS_DIR):
            if project_dir.is_dir():
                _prune_old_direct_files(
                    project_dir,
                    TRANSCRIPT_FILE_NAME,
                    cut,
                    protected_names=(current_transcript,),
                )
    except Exception:
        pass


def _turn_log_files(state: dict):
    """Return this turn's bounded log files across a calendar rollover.

    The persisted path is treated as untrusted state: only an expected daily log
    directly inside LOG_DIR is accepted. The current process log is also included,
    which covers a turn that started before midnight and stops afterwards.
    """
    raw_paths = []
    first = state.get("turn_log_path")
    if isinstance(first, str):
        raw_paths.append(first)
    history = state.get("turn_log_paths")
    if isinstance(history, list):
        raw_paths.extend(value for value in history if isinstance(value, str))
    raw_paths.append(str(_current_log_file()))

    root = Path(os.path.abspath(os.fspath(LOG_DIR)))
    out, seen = [], set()
    for raw in raw_paths:
        try:
            candidate = Path(os.path.abspath(os.fspath(Path(raw).expanduser())))
            key = os.path.normcase(str(candidate))
            if key in seen:
                continue
            if os.path.normcase(str(candidate.parent)) != os.path.normcase(str(root)):
                continue
            if not LOG_FILE_NAME.fullmatch(candidate.name) or candidate.is_symlink():
                continue
            if not candidate.is_file():
                continue
            seen.add(key)
            out.append(candidate)
        except (OSError, TypeError, ValueError):
            continue
    return out


# ------------------------------------------------------- per-project context ---

def project_key(path_str: str) -> str:
    """Map a cwd to one deterministic filesystem-safe component (keeps CJK)."""
    try:
        raw = path_str.strip() if isinstance(path_str, str) else ""
    except Exception:
        raw = ""
    if not raw:
        return "unknown"

    digest = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]

    def fallback() -> str:
        return "unknown-" + digest

    # A forged cwd may contain lexical traversal even though separators are later
    # replaced. Keep it distinct, but never let it become a filesystem component.
    if any(part in (".", "..") for part in re.split(r"[:\\/]+", raw) if part):
        return fallback()

    key = re.sub(r"[:\\/]+", "--", raw)
    key = re.sub(r"[\s]+", "-", key)
    key = key.strip("-").rstrip(" .")
    if (
        not key
        or key in (".", "..")
        or PROJECT_KEY_INVALID.search(key)
        or key.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES
    ):
        return fallback()
    if len(key) > PROJECT_KEY_MAX_CHARS:
        prefix = key[: PROJECT_KEY_MAX_CHARS - len(digest) - 1].rstrip(" .-") or "project"
        key = prefix + "-" + digest
    return key


def find_context_file(cwd: str):
    """Exact cwd first, then up to 3 parents. Returns (path, key) or (None, key-of-cwd).

    NEVER falls back to another project's file — a wrong-project injection is
    worse than no injection (root cause of the v3 stale-context incidents).
    """
    if not cwd:
        return None, "unknown"
    p = Path(cwd)
    candidates = [p] + list(p.parents)[:3]
    for cand in candidates:
        key = project_key(str(cand))
        f = _confined_direct_child(CONTEXTS_DIR, key + ".md")
        if f is not None and f.is_file():
            return f, key
    return None, project_key(str(p))


def load_context_summary(cwd: str, max_chars: int = 1800) -> str:
    f, key = find_context_file(cwd)
    if f is None:
        return (f"（项目 [{key}] 尚无上下文档案。如本项目需要跨会话状态持久化，"
                f"请让我初始化 ~/.claude/supervisor/state/contexts/{key}.md）")
    try:
        text = f.read_text(encoding="utf-8")
        age_days = (datetime.now().timestamp() - f.stat().st_mtime) / 86400
    except Exception:
        return f"（[{key}] 上下文读取失败）"
    stale = f"\n⚠️ 上次更新 {age_days:.1f} 天前，可能过期" if age_days > 7 else ""
    sections = []
    for marker in ("## 🎯 Active Project", "## 📄 Active Documents", "## ⏭ 下一步候选"):
        idx = text.find(marker)
        if idx == -1:
            continue
        nxt = text.find("\n## ", idx + len(marker))
        sections.append((text[idx:nxt] if nxt != -1 else text[idx:]).strip())
    body = "\n\n".join(sections) or text.strip()
    if len(body) > max_chars:
        body = body[:max_chars] + f"\n...(截断，全文见 contexts/{key}.md)"
    return f"[{key}]\n{body}{stale}"


# ------------------------------------------------------------------ banners ---

# 机器噪声：task-notification / system-reminder / Stop 钩子回灌等，都不是用户意图。
# 实测：全历史 102 次「研发轮」里 74 次（73%）是这类噪声，每次都白白注入完整协议。
# 只在**开头**匹配——用户正常引用这些词时不该被误判。
HARNESS_BLOB = re.compile(
    r"^\s*(?:<task-notification>|<system-reminder>|\[SYSTEM NOTIFICATION"
    r"|Stop hook feedback|<function_results>|<local-command-)", re.I)


def is_harness_noise(prompt: str) -> bool:
    try:
        return bool(HARNESS_BLOB.search(prompt or ""))
    except Exception:
        return False


def is_dev_prompt(prompt: str) -> bool:
    p = (prompt or "").strip()
    if not p or p.startswith("/"):
        return False          # slash commands / empty → lite
    if len(p) <= 6 and not DEV_SIGNAL.search(p):
        return False          # ultra-short non-dev（"好的"/"继续"沿用上一轮语境，轻横幅即可）
    return bool(DEV_SIGNAL.search(p))


def emit_full_banner(turn_no: int, cwd: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(
        f"🛡️ SUPERVISOR v8.5 — Turn #{turn_no} {ts} [dev]\n"
        "协议: ①Karpathy四查 ②调度双向预算[有下限:视觉>=2/动效>=1/前端>=2,少调须给SKIP具体理由] "
        "③code-review-graph门禁 ④[效果验收门]用户可感知改动须亲自看after图或跑关键命令+答视觉四问,数字达标!=效果达成 "
        "⑤本轮有改动时Stop门禁会强制6行简报 ⑥阶段末写穿本项目context文件\n⑦[拆解对表]动手前先出「子任务/需要能力/候选/决定/理由」表，横幅列的候选每条都要处置(用或[SKIP]指名理由)\n"
        "─────────────────────────────────"
    )
    print("📌 项目上下文 " + load_context_summary(cwd))
    print("─────────────────────────────────")


def emit_lite_banner(turn_no: int) -> None:
    print(f"🛡️ SUP v8.5 — Turn #{turn_no} [lite] 非研发轮，协议待命（说「启用监工」可强制全量注入）")


# -------------------------------------------------------------------- events ---

# ---------------------------------------------------- v7: 提示词全文存档 ----
MAX_PROMPT_CHARS = 20000      # 单条上限，防病态巨型输入把文件撑爆


SECRET_PATTERNS = [
    # (regex, label) — keep these conservative; a false redaction loses real content
    # Anthropic's prefix is a strict subset of the broader sk-* shape, so it must
    # be classified first or the OpenAI rule consumes it with the wrong label.
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}"), "ANTHROPIC_KEY"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), "OPENAI_KEY"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"), "GITHUB_TOKEN"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS_KEY"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "SLACK_TOKEN"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "JWT"),
    (re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"
                r"auth[_-]?token|client[_-]?secret)\s*[:=]\s*[\"']?([^\s\"',;]{6,})"), "CREDENTIAL"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{16,}"), "BEARER"),
    (re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s]+:[^\s]+@[^\s]+"),
     "DB_URL_WITH_PASSWORD"),
]


def redact_secrets(text: str):
    """Strip credentials before anything is written to disk forever.

    The archive exists so the user's ORIGINAL WORDS survive; it must not become a
    plaintext credential store the moment they paste a key while asking for help.
    Returns (cleaned_text, n_redactions). Never raises.
    """
    n = 0
    try:
        for rx, label in SECRET_PATTERNS:
            text, k = rx.subn("[[已抹除:" + label + "]]", text)
            n += k
    except Exception:
        pass
    return text, n


def _fence_for(body: str) -> str:
    """Pick a fence longer than any backtick run in the body.

    Otherwise a prompt containing ``` terminates the block early and its content
    starts masquerading as archive markup.
    """
    try:
        longest = 0
        run = 0
        for ch in body:
            run = run + 1 if ch == "`" else 0
            longest = max(longest, run)
        return "`" * max(3, longest + 1)
    except Exception:
        return "`" * 8


def append_transcript(prompt: str, cwd: str, turn: int, dev: bool) -> str:
    """Optionally append a redacted prompt archive after explicit user opt-in.

    Prompt content is never persisted by default. The legacy archive remains
    available only through ``SUPERVISOR_LEGACY_PERSIST_PROMPTS=1`` for users who
    knowingly accept that local retention tradeoff.
    """
    if not STORAGE_READY or not PROMPT_ARCHIVE_ENABLED:
        return ""
    try:
        key = project_key(cwd) if cwd else "unknown"
        d = _confined_direct_child(TRANSCRIPTS_DIR, key)
        if d is None:
            return ""
        _ensure_private_directory(d)
        # Recheck after mkdir so an existing link cannot redirect the write.
        d = _confined_direct_child(TRANSCRIPTS_DIR, key)
        if d is None or not d.is_dir():
            return ""
        f = _confined_direct_child(d, datetime.now().strftime("%Y-%m") + ".md")
        if f is None:
            return ""
        head = ("# 提示词全文存档 · " + key + chr(10) + chr(10)
                + "> 已明确启用 legacy prompt archive；内容会先做凭据抹除。" + chr(10)
                + "> 只增不改；需要检索用 `sup-query.py`。" + chr(10) + chr(10))
        try:
            with _private_text_open(
                f,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                "w",
            ) as fh:
                fh.write(head)
        except FileExistsError:
            pass
        # Redact the complete prompt first. Truncating first can split a credential at
        # the boundary so neither half matches a secret pattern and the prefix leaks.
        cleaned_prompt, redacted = redact_secrets(prompt)
        truncated = len(prompt) > MAX_PROMPT_CHARS or len(cleaned_prompt) > MAX_PROMPT_CHARS
        if truncated:
            visible = cleaned_prompt[:MAX_PROMPT_CHARS]
            # Do not leave a partial redaction placeholder at the size boundary.
            open_marker = visible.rfind("[[已抹除:")
            if open_marker >= 0 and visible.find("]]", open_marker) < 0:
                visible = visible[:open_marker]
            body = (visible + chr(10) + "…（超长，已截断，原长 "
                    + str(len(prompt)) + " 字）")
        else:
            body = cleaned_prompt
        fence = _fence_for(body)
        head_line = ("## 第 " + str(turn) + " 轮 · "
                     + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                     + " · " + ("研发轮" if dev else "非研发轮")
                     + ((" · 已抹除 " + str(redacted) + " 处疑似凭据") if redacted else ""))
        block = (head_line + chr(10) + chr(10)
                 + fence + "text" + chr(10) + body + chr(10) + fence + chr(10) + chr(10))
        with _private_text_open(
            f,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            "a",
        ) as fh:
            fh.write(block)
        return str(f)
    except Exception:
        return ""


def plan_block(prompt: str) -> str:
    """每轮的候选派单检索。sup-plan.py 缺失/出错时返回空串，绝不阻断。"""
    try:
        import importlib.util
        p = Path(__file__).resolve().parent / "sup-plan.py"
        if not p.exists():
            return ""
        spec = importlib.util.spec_from_file_location("_supplan", str(p))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m.render_plan_block(prompt, k=6)
    except Exception:
        return ""


def handle_prompt_submit(stdin_data: dict) -> None:
    current_log = _current_log_file()

    def start_turn(state):
        state["turn"] = state.get("turn", 0) + 1
        # v4: per-turn flags reset
        state["dev_tool_used"] = False
        state["stop_blocked"] = False
        # 必须清空：否则轻量分支（"继续"等）不写 candidates，V-1 会拿上一轮的清单
        # 去判这一轮的简报，模型写得再诚实也无法满足。实测已复现。
        state["candidates"] = []
        state["turn_started_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        state["turn_log_path"] = str(current_log)
        state["turn_log_paths"] = [str(current_log)]

    state = _update_turn_state(start_turn)
    if state is None:
        return
    turn_number = state.get("turn")
    turn_started_at = state.get("turn_started_at")

    prompt = stdin_data.get("prompt", "") or ""
    cwd = stdin_data.get("cwd", "") or ""
    noise = is_harness_noise(prompt)
    dev = (not noise) and is_dev_prompt(prompt)
    tpath = append_transcript(prompt, cwd, state["turn"], dev)
    append_event({"event": "prompt-submit", "turn": state["turn"], "dev": dev,
                  "cwd": cwd,
                  "prompt_len": len(prompt), "transcript": bool(tpath),
                  "noise": noise})
    if dev:
        emit_full_banner(state["turn"], cwd)
        blk = plan_block(prompt)      # 真实候选，不是记忆里的池表
        if blk:
            print(blk)
            # remember what was offered, so the Stop gate can check each was disposed of
            try:
                # The banner uses an explicit delimiter so callable names remain
                # complete regardless of spaces or length.
                names = []
                for ln in blk.splitlines():
                    p = ln.find("] ")
                    if p < 0 or not ln.lstrip().startswith("["):
                        continue
                    nm = ln[p + 2:].split(" :: ", 1)[0].strip()
                    if nm:
                        names.append(nm)
                candidates = names[:8]

                def remember_candidates(latest):
                    # A newer prompt may already have started while routing ran.
                    if (
                        latest.get("turn") == turn_number
                        and latest.get("turn_started_at") == turn_started_at
                    ):
                        latest["candidates"] = candidates

                _update_turn_state(remember_candidates)
            except Exception:
                pass
    else:
        emit_lite_banner(state["turn"])


# ------------------------------------------------------- v6: dispatch ledger ---

def _short(s, n: int = 80) -> str:
    s = str(s).replace(chr(10), " ").replace(chr(13), " ").strip()
    return s if len(s) <= n else s[:n] + "..."


def _usable_status(value) -> str:
    """Return one concrete status, never an unexpanded hook-template token."""
    try:
        status = str(value or "").strip()
        if not status or _looks_unsubstituted(status):
            return ""
        return status[:24]
    except Exception:
        return ""


def resolve_status(stdin_data: dict) -> str:
    """Did the tool succeed? stdin_data["status"] is NOT a real hook field - reading it
    made every row say "ok", so failures were invisible. Try the plausible shapes and
    return "unknown" rather than claiming success we cannot observe."""
    try:
        tr = stdin_data.get("tool_response") or stdin_data.get("toolResponse") or {}
        if isinstance(tr, dict):
            if tr.get("is_error") or tr.get("isError") or tr.get("error"):
                return "error"
        if stdin_data.get("is_error") or stdin_data.get("isError") or stdin_data.get("error"):
            return "error"
        raw = _usable_status(stdin_data.get("status"))
        if not raw and isinstance(tr, dict):
            raw = _usable_status(tr.get("status") or tr.get("result_status"))
        if raw:
            return raw
        environment_status = _usable_status(os.environ.get("CLAUDE_TOOL_STATUS"))
        if environment_status:
            return environment_status
        if tr:
            return "ok"
    except Exception:
        pass
    return "unknown"


def _looks_unsubstituted(v: str) -> bool:
    """True if the shell handed us a literal template instead of a value.

    settings.json may pass the tool name as an argv token. If the harness does NOT
    expand it, argv[2] arrives as the literal "$CLAUDE_TOOL_NAME" / "%CLAUDE_TOOL_NAME%"
    and blindly trusting it would poison EVERY row with a fake name - strictly worse
    than logging "?". So reject anything that still looks like a template.
    """
    v = (v or "").strip()
    if not v:
        return True
    return any(ch in v for ch in ("$", "%", "{", "}")) or v.startswith("-")


# --- v6.2: what actually counts as "this turn changed files" --------------------
# The gate used to trust the tool NAME (Edit/Write/...). But most edits in this
# environment go through Bash (today: 958 Bash vs 41 Write + 10 Edit), so the gate
# was silent on the dominant path. Decide by EFFECT instead.
DEV_MCP_RE = re.compile(
    r"(write_file|edit_block|edit_page|write_page|create_new_file|create_directory"
    r"|apply_migration|write_pdf|move_file|update_node|upload_assets)", re.I)

# NOTE on the redirect branch: a bare ">" matches ordinary read-only commands
# (`print(1 > 0)`, `awk '$3 > 100'`, `jq 'select(.n > 2)'`) and would fire the gate
# constantly, training everyone to ignore it. So the redirect target must look like a
# PATH (contain . / or \) and must not be /dev/null or NUL.
SHELL_MUTATE_RE = re.compile(
    r"(sed\s+-i"
    r"|\btee\s"
    r"|>>\s*[^\s&]"
    r"|>\s*(?!&|/dev/null(?:\s|$)|NUL\b)(?:"
    r"[A-Za-z]:[\\/][A-Za-z0-9_./\\-]+"
    r"|(?:[\\/]|\.{1,2}[\\/]|~[\\/])[A-Za-z0-9_./\\-]+"
    r"|[A-Za-z_][A-Za-z0-9_~-]*[./\\][A-Za-z0-9_./\\-]+"
    r"|\.[A-Za-z_][A-Za-z0-9_.-]*"
    r")"
    r"|\brm\s+-|\bmv\s+|\bcp\s+|\bmkdir\s+|\btouch\s+|\bpatch\s+"
    r"|\bgit\s+(apply|checkout|restore|revert|clean|stash)\b"
    r"|Set-Content|Add-Content|Out-File|New-Item|Remove-Item|Copy-Item|Move-Item"
    r")", re.I)


# Writers that live INSIDE an interpreter, invisible to shell-redirection matching.
# `python - <<PY ... open(p,"w") ... PY` is the dominant edit path in this environment,
# and it left the Stop gate disarmed.
INPROC_WRITE_RE = re.compile(
    r"(open\s*\([^)]*['\"][wax]"          # python open(p,'w'/'a'/'x')
    r"|\.write_text\s*\(|\.write_bytes\s*\("
    r"|\bwriteFile(?:Sync)?\s*\(|\bfs\.write"
    r"|\bshutil\.(?:copy|copy2|copyfile|move|rmtree)\s*\("
    r"|\bos\.(?:remove|unlink|rename|replace|makedirs|mkdir)\s*\("
    r"|\bPath\s*\([^)]*\)\s*\.\s*(?:write_text|write_bytes|unlink|mkdir)"
    r"|\bjson\.dump\s*\(|\bpickle\.dump\s*\("
    r")", re.I)


def is_dev_call(tool: str, ti) -> bool:
    """Did this call plausibly MUTATE the working tree? Never raises."""
    try:
        if tool in DEV_TOOLS:
            return True
        if not isinstance(ti, dict):
            return False
        if tool.startswith("mcp__") and DEV_MCP_RE.search(tool):
            return True
        if tool in ("Bash", "PowerShell"):
            cmd = str(ti.get("command") or "")
            return bool(SHELL_MUTATE_RE.search(cmd) or INPROC_WRITE_RE.search(cmd))
    except Exception:
        pass
    return False


def mark_dev_turn() -> None:
    """Flip dev_tool_used once. Uses the REAL state helpers - the audit's proposed
    update_turn_state() does not exist and would have silently killed the gate."""
    try:
        def mark(state):
            state["dev_tool_used"] = True

        _update_turn_state(mark)
    except Exception:
        pass


def resolve_tool_name(stdin_data: dict) -> str:
    """Best-effort tool name. ~27% of hook invocations arrive with EMPTY stdin
    (measured 2026-08-20: 39/39 unknown rows had zero stdin keys), so try argv,
    then stdin under several spellings, then the environment."""
    cand = sys.argv[2] if len(sys.argv) > 2 else None
    if cand and not _looks_unsubstituted(cand):
        return cand
    for k in ("tool_name", "toolName", "tool", "name"):
        v = stdin_data.get(k)
        if v:
            return str(v)
    for k in ("CLAUDE_TOOL_NAME", "CLAUDE_HOOK_TOOL_NAME", "CLAUDE_TOOL",
              "TOOL_NAME", "CLAUDE_CODE_TOOL_NAME"):
        v = os.environ.get(k)
        if v:
            return str(v)
    return "?"


def _env_probe() -> str:
    """Which CLAUDE_* env vars a hook can actually see - recorded once per unknown
    row so the blind spot is diagnosable instead of invisible."""
    try:
        KNOWN = {"Bash", "Write", "Edit", "Read", "Skill", "Agent", "Glob", "Grep",
                 "PowerShell", "Workflow", "MultiEdit", "NotebookEdit", "TaskUpdate"}
        hits = [k + "=" + v for k, v in os.environ.items()
                if v in KNOWN or v.startswith("mcp__")]
        return ("HIT:" + ";".join(hits)) if hits else "NO-TOOL-NAME-IN-ENV"
    except Exception:
        return ""


def describe_call(tool: str, ti):
    """Identify WHAT was dispatched -> (kind, name, detail).

    kind is one of: skill / agent / workflow / connector / edit / shell / tool
    Never raises: every lookup is guarded; unknown shapes degrade to ("tool", tool, "").
    """
    if not isinstance(ti, dict):
        ti = {}

    def safe_detail(value, limit=80):
        cleaned, _ = redact_secrets(str(value or ""))
        return _short(cleaned, limit)

    def callable_name(value, fallback="?"):
        # Callable identifiers are evidence keys. Preserve the complete identifier;
        # only neutralize row/control delimiters rather than truncating it.
        name = str(value or fallback)
        return " ".join(name.replace(chr(10), " ").replace(chr(13), " ").split()) or fallback

    try:
        if tool == "Skill":
            return ("skill", callable_name(ti.get("skill")), safe_detail(ti.get("args")))
        if tool == "Agent":
            return ("agent",
                    callable_name(ti.get("subagent_type"), "general-purpose"),
                    safe_detail(ti.get("description")))
        if tool == "Workflow":
            nm = ti.get("name") or ti.get("scriptPath") or "inline-script"
            return ("workflow", callable_name(nm, "inline-script"), "")
        if tool.startswith("mcp__"):
            parts = tool.split("__")
            server = parts[1] if len(parts) > 2 else "?"
            return ("connector", server, parts[-1])
        if tool in ("Edit", "Write", "NotebookEdit", "MultiEdit"):
            fp = str(ti.get("file_path") or ti.get("notebook_path") or "")
            base = fp.replace(chr(92), "/").rstrip("/").split("/")[-1] or "?"
            return ("edit", base, safe_detail(fp, 70))
        if tool in ("Bash", "PowerShell"):
            return ("shell", tool, safe_detail(ti.get("description") or ti.get("command")))
    except Exception:
        pass
    return ("tool", str(tool), "")


def _cell(v) -> str:
    """Make a value safe to sit inside a markdown table cell.

    The ledger is the anti-fabrication mechanism: the Stop gate injects it and tells
    the model to quote it verbatim. If a model-controlled string (a skill name) can
    carry "|" or a newline, it can inject a whole fake row and the mechanism is
    defeated. Verified exploitable before this fix.
    """
    v = str(v if v is not None else "")
    v = v.replace(chr(10), " ").replace(chr(13), " ").replace("|", "/")
    v = " ".join(v.split())
    return v


LEDGER_KINDS = ("skill", "agent", "workflow", "connector")
SUCCESS_STATUSES = frozenset({"ok", "success", "succeeded", "complete", "completed", "pass", "passed"})
FAILURE_STATUSES = frozenset({
    "error", "failed", "failure", "denied", "rejected", "cancelled", "canceled",
})


def _utc_datetime(value):
    """Parse aware/legacy timestamps into UTC; invalid values are not comparable."""
    try:
        text = str(value or "").strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _ledger_time(value) -> str:
    parsed = _utc_datetime(value)
    return parsed.strftime("%H:%M:%S") if parsed is not None else ""


def _turn_event_rows(state: dict):
    """Yield owned, in-turn tool events from every bounded rollover log."""
    started = _utc_datetime(state.get("turn_started_at", ""))
    sid = state.get("session_id", "")
    if started is None:
        return
    for log_file in _turn_log_files(state):
        try:
            lines = log_file.open(encoding="utf-8")
        except OSError:
            continue
        with lines:
            for line in lines:
                try:
                    event = json.loads(line)
                except Exception:
                    continue
                if event.get("event") not in ("pre-tool", "post-tool"):
                    continue
                event_time = _utc_datetime(event.get("ts", ""))
                if event_time is None or event_time < started or "kind" not in event:
                    continue
                if sid and event.get("sid") != sid:
                    continue
                yield event


def _event_identity(event: dict):
    kind = event.get("kind") or "unknown"
    name = event.get("name") or "?"
    if name == "?":
        kind = "unknown"
    return str(kind), str(name)


def _post_outcome(post: dict | None) -> str:
    if post is None:
        return "declared"
    status = str(post.get("status") or "").strip().casefold()
    if status in SUCCESS_STATUSES:
        return "success"
    if status in FAILURE_STATUSES:
        return "failed"
    return "unverified"


def _turn_call_records(state: dict):
    """Resolve each call to its final observed outcome.

    PreToolUse proves only an attempt. A matching PostToolUse is authoritative for
    the outcome, so a failure or non-success status can never remain tallied as a
    successful dispatch. UID-less legacy rows are paired FIFO by captured identity.
    """
    records = []
    by_uid = {}
    by_identity = {}
    for event in _turn_event_rows(state):
        event_type = event.get("event")
        uid = str(event.get("uid") or "")
        kind, name = _event_identity(event)
        identity = (str(event.get("tool") or ""), kind, name)

        if event_type == "pre-tool":
            existing = by_uid.get(uid) if uid else None
            if existing is not None and existing.get("post") is None:
                continue  # duplicate flush of the same attempt
            record = {"pre": event, "post": None, "uid": uid}
            records.append(record)
            if uid:
                by_uid[uid] = record
            else:
                by_identity.setdefault(identity, []).append(record)
            continue

        record = by_uid.get(uid) if uid else None
        if record is None and not uid:
            pending = by_identity.get(identity) or []
            if pending:
                record = pending.pop(0)
        if record is None:
            record = {"pre": None, "post": None, "uid": uid}
            records.append(record)
            if uid:
                by_uid[uid] = record
        record["post"] = event  # the latest terminal observation wins

    resolved = []
    for record in records:
        pre, post = record.get("pre"), record.get("post")
        source = pre or post or {}
        kind, name = _event_identity(source)
        if kind == "unknown" and post is not None:
            post_kind, post_name = _event_identity(post)
            if post_kind != "unknown":
                kind, name = post_kind, post_name
        resolved.append({
            "ts": (pre or post or {}).get("ts", ""),
            "kind": kind,
            "name": name,
            "detail": (pre or {}).get("detail") or (post or {}).get("detail") or "",
            "outcome": _post_outcome(post),
            "uid": record.get("uid") or "",
        })
    return resolved


def render_ledger() -> str:
    """Machine-generated dispatch ledger for the CURRENT turn.

    Read straight from the event log so the model cannot fabricate it.
    Returns "" on any failure - the gate must still fire without a ledger.
    """
    try:
        state = read_turn_state()
        if not state.get("turn_started_at", ""):
            return ""
        rows = []
        counts = {}
        for call in _turn_call_records(state):
            kind = call["kind"]
            outcome = call["outcome"]
            if outcome == "success":
                counts[kind] = counts.get(kind, 0) + 1
            else:
                label = outcome.upper()
                counts[label] = counts.get(label, 0) + 1
                if kind == "unknown":
                    counts["unknown"] = counts.get("unknown", 0) + 1
            if kind in LEDGER_KINDS:
                detail = call.get("detail") or ""
                status_note = "status=" + outcome
                detail = detail + "; " + status_note if detail else status_note
                rows.append((_ledger_time(call.get("ts", "")), kind,
                             call.get("name") or "?", detail))
        # NOTE: no early bail-out on an empty tally. A turn that dispatched nothing at all
        # is precisely the turn the [SKIP] warning exists for.
        out = ["", "---- 本轮调度台账（钩子实录，请原样引用，不得改写或补写）----"]
        if rows:
            out.append("| 时刻 | 类别 | 名称 | 备注 |")
            out.append("|---|---|---|---|")
            for ts, kind, name, detail in rows[:40]:
                out.append("| " + _cell(ts) + " | " + _cell(kind) + " | "
                           + _cell(name) + " | " + _cell(detail or "-") + " |")
            if len(rows) > 40:
                out.append("| ... | | 另有 " + str(len(rows) - 40) + " 条未列 | |")
        else:
            out.append("（本轮未调用任何 skill / agent / workflow / connector）")
        if rows:
            out.append("注：子 agent 继承父会话 id，其调用会混入本表且无法区分；本轮若跑过 Agent/Workflow，不要当成主窗口自己的战绩。")
        tally = ", ".join(k + "=" + str(v) for k, v in sorted(counts.items()))
        out.append("注：时刻为钩子落账时刻，可能晚于实际发起时刻（实测最大偏移约 9 分钟）。")
        out.append("合计：" + (tally or "无"))
        if counts.get("unknown", 0):
            out.append("\u6ce8\uff1a\u6709 " + str(counts["unknown"]) +
                       " \u6b21\u8c03\u7528\u56e0\u94a9\u5b50\u672a\u6536\u5230 stdin \u800c\u65e0\u6cd5\u8bc6\u522b"
                       "\uff08\u5df2\u77e5\u5c40\u9650\uff0c\u4e0d\u5f97\u81ea\u884c\u8865\u5199\uff09\u3002")
        if counts.get("skill", 0) == 0:
            out.append("[!] 本轮 0 次 skill 调用 —— 若属研发轮，必须在 ⑧ 写明 [SKIP] 指名理由。")
        return chr(10).join(out)
    except Exception:
        return ""


def handle_pre_tool(stdin_data: dict) -> None:
    tool = resolve_tool_name(stdin_data)
    ti = stdin_data.get("tool_input") or stdin_data.get("toolInput") or stdin_data.get("input") or {}
    kind, name, detail = describe_call(tool, ti)
    ev = {"event": "pre-tool", "tool": tool, "kind": kind, "name": name}
    if detail:
        ev["detail"] = detail
    sid = stdin_data.get("session_id") or stdin_data.get("sessionId")
    sid_token = _session_token(sid)
    if sid_token:
        ev["sid"] = sid_token
    tid = stdin_data.get("tool_use_id") or stdin_data.get("toolUseId")
    uid_token = _stable_full_value_token(tid)
    if uid_token:
        ev["uid"] = uid_token
    if tool == "?":
        ev["rawkeys"] = ",".join(sorted(stdin_data.keys()))[:200]
        ev["envkeys"] = _env_probe()
    append_event(ev)
    if tool in ECHO_TOOLS or tool.startswith("mcp__"):
        print(f"[🛡️ SUP {datetime.now().strftime('%H:%M:%S')}] {tool}")


def handle_post_tool(stdin_data: dict) -> None:
    tool = resolve_tool_name(stdin_data)
    argv_status = _usable_status(sys.argv[3] if len(sys.argv) > 3 else None)
    status = argv_status or resolve_status(stdin_data)
    ti = stdin_data.get("tool_input") or stdin_data.get("toolInput") or stdin_data.get("input") or {}
    kind, name, _d = describe_call(tool, ti)
    ev = {"event": "post-tool", "tool": tool, "kind": kind, "name": name, "status": status}
    # sid MUST be recorded here too: edit/shell are tallied from post-tool rows, and
    # render_ledger's session filter is a no-op on rows that carry no sid, so another
    # concurrent session's edits were silently counted into this session's 合计 line.
    sid = stdin_data.get("session_id") or stdin_data.get("sessionId")
    sid_token = _session_token(sid)
    if sid_token:
        ev["sid"] = sid_token
    tid = stdin_data.get("tool_use_id") or stdin_data.get("toolUseId")
    uid_token = _stable_full_value_token(tid)
    if uid_token:
        ev["uid"] = uid_token
    if tool == "?":
        ev["rawkeys"] = ",".join(sorted(stdin_data.keys()))[:200]
        ev["envkeys"] = _env_probe()
    append_event(ev)
    # A PostToolUse event proves only that the call returned, not that it succeeded.
    # Unknown/ambiguous outcomes must not arm the development-completion gate.
    if str(status).strip().casefold() in SUCCESS_STATUSES:
        if is_dev_call(tool, ti):
            mark_dev_turn()


# ------------------------------------------------- v8: 第二方校验（测谎） ----
TRANSCRIPT_TAIL_BYTES = 400_000     # 108MB 的会话记录只读尾部；实测 2-6ms


def _session_transcript(stdin_data: dict):
    """Locate this session's transcript. Prefer what the harness hands us."""
    try:
        raw_sid = stdin_data.get("session_id") or stdin_data.get("sessionId")
        sid = _validated_session_id(raw_sid)
        if raw_sid and not sid:
            return None
        tp = stdin_data.get("transcript_path") or stdin_data.get("transcriptPath")
        if tp and Path(tp).exists():
            return Path(tp)
        cwd = stdin_data.get("cwd") or ""
        if sid:
            base = Path.home() / ".claude" / "projects"
            if cwd:
                project_dir = _confined_direct_child(base, project_key(cwd))
                cand = (
                    _confined_direct_child(project_dir, str(sid) + ".jsonl")
                    if project_dir is not None else None
                )
                if cand is not None and cand.is_file():
                    return cand
            for project_dir in _safe_direct_children(base):
                if not project_dir.is_dir():
                    continue
                cand = _confined_direct_child(project_dir, str(sid) + ".jsonl")
                if cand is not None and cand.is_file():
                    return cand
    except Exception:
        pass
    return None


BRIEF_MARKS = ("\u2460", "\u2461", "\u2462", "\u2463", "\u2464", "\u2465", "\u2466", "\u2467", "\u2468",
               "FLOOR", "\u5b9e\u8c03", "\u62c6\u89e3\u5bf9\u8868")


def _find_briefing(path, look_back=6):
    """Pick the newest briefing out of the last few assistant messages.

    Reading ONLY the final message let a model skip pass 2 entirely by ending with a
    short line: anything under 120 chars was treated as "no briefing yet" and the
    verifier returned silently. Scan back and take whichever message actually looks
    like a briefing.
    """
    try:
        for txt in _recent_assistant_texts(path, look_back):
            score = sum(1 for m in BRIEF_MARKS if m in txt)
            if score >= 3:
                return txt
    except Exception:
        pass
    return ""


def _recent_assistant_texts(path, limit=6):
    """Newest-first assistant texts from a bounded tail read."""
    out = []
    try:
        size = path.stat().st_size
        start = max(0, size - TRANSCRIPT_TAIL_BYTES)
        with io.open(path, "rb") as f:
            f.seek(start)
            blob = f.read()
        if start:
            nl = blob.find(b"\n")
            blob = blob[nl + 1:] if nl >= 0 else b""
        for line in reversed(blob.decode("utf-8", "replace").splitlines()):
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("type") != "assistant":
                continue
            m = e.get("message") or e
            c = m.get("content")
            parts = []
            if isinstance(c, str):
                parts.append(c)
            elif isinstance(c, list):
                for b in c:
                    if isinstance(b, dict) and b.get("type") == "text":
                        parts.append(b.get("text") or "")
            t = "\n".join(parts).strip()
            if t:
                out.append(t)
            if len(out) >= limit:
                break
    except Exception:
        pass
    return out


def _last_assistant_text(path) -> str:
    """Newest assistant text via a bounded tail read - never load the whole file."""
    try:
        size = path.stat().st_size
        start = max(0, size - TRANSCRIPT_TAIL_BYTES)
        with io.open(path, "rb") as f:
            f.seek(start)
            blob = f.read()
        if start:
            nl = blob.find(b"\n")
            blob = blob[nl + 1:] if nl >= 0 else b""
        for line in reversed(blob.decode("utf-8", "replace").splitlines()):
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("type") != "assistant":
                continue
            m = e.get("message") or e
            c = m.get("content")
            parts = []
            if isinstance(c, str):
                parts.append(c)
            elif isinstance(c, list):
                for b in c:
                    if isinstance(b, dict) and b.get("type") == "text":
                        parts.append(b.get("text") or "")
            txt = "\n".join(parts).strip()
            if txt:
                return txt
    except Exception as exc:
        # A bare `except: pass` here is what let a NameError masquerade as
        # "no briefing found" — the same silent-swallow that hid the encoding bug
        # for months. Leave a trace instead of vanishing.
        try:
            append_event({"event": "verify-error", "where": "_last_assistant_text",
                          "err": type(exc).__name__ + ": " + str(exc)[:120]})
        except Exception:
            pass
    return ""


def _turn_ledger_facts(state: dict, *, include_outcomes: bool = False):
    """Return success facts, optionally with every recorded capability outcome."""
    dispatch_names, successful_dispatches = set(), 0
    dispatch_outcomes = {}
    saw_visual, saw_shell = False, False
    try:
        if not state.get("turn_started_at", ""):
            facts = (dispatch_names, successful_dispatches, saw_visual, saw_shell)
            return facts + (dispatch_outcomes,) if include_outcomes else facts
        for call in _turn_call_records(state):
            kind, name = call.get("kind"), (call.get("name") or "")
            outcome = call.get("outcome") or "unverified"
            if kind in LEDGER_KINDS and name and name != "?":
                identity = (str(kind).casefold(), str(name).strip().casefold())
                dispatch_outcomes.setdefault(identity, set()).add(str(outcome).casefold())
            if outcome != "success":
                continue
            if kind in LEDGER_KINDS and name and name != "?":
                successful_dispatches += 1
                dispatch_names.add(kind + ":" + name)
            if kind == "connector" and name:
                saw_visual = True
            if kind == "shell":
                saw_shell = True
    except Exception:
        pass
    facts = (dispatch_names, successful_dispatches, saw_visual, saw_shell)
    return facts + (dispatch_outcomes,) if include_outcomes else facts


def verify_briefing(stdin_data: dict, state: dict):
    """Cross-examine the briefing against the hook's own records.

    Returns a list of concrete contradictions. Empty list = nothing provable is wrong
    (NOT "the work was good" - this only catches checkable lies, never judges quality).
    Deliberately biased toward silence: an ambiguous case is not a violation.
    """
    problems = []
    try:
        tpath = _session_transcript(stdin_data)
        if not tpath:
            return []                      # cannot verify -> do not accuse
        text = _find_briefing(tpath)
        if not text or len(text) < 120:
            return []                      # no briefing to check yet
        (dispatch_names, successful_dispatches, saw_visual, saw_shell,
         dispatch_outcomes) = _turn_ledger_facts(state, include_outcomes=True)

        # V-1 候选处置：横幅列过的候选必须在简报里被提到
        cands = state.get("candidates") or []
        missed = [c for c in cands if c and c not in text]
        if cands and len(missed) > len(cands) // 2 and len(missed) >= 3:
            problems.append("V-1 候选未处置：横幅列了 " + str(len(cands))
                            + " 条候选，简报里只字未提其中 " + str(len(missed))
                            + " 条 —— " + "、".join(missed[:4])
                            + "。⑨ 要求每条都要写「用」或「[SKIP]+指名理由」。")

        # V-2 调度声明：说"实调 N 项"就要对得上台账
        m = re.search(r"实调\s*\**\s*(\d+)", text)
        if m:
            claimed = int(m.group(1))
            if claimed > successful_dispatches:
                problems.append("V-2 调度数对不上：简报说实调 " + str(claimed)
                                + " 项，台账只记到 " + str(successful_dispatches) + " 次成功调度"
                                + ("（" + "、".join(sorted(dispatch_names)) + "）"
                                   if dispatch_names else "")
                                + "。要么少写了，要么这次调用没发生。")

        # V-3 亲验声明：**声明什么就要有什么**。
        # 早先写成"有任何工具记录就算数"，那几乎每轮都满足，等于抓不到人；
        # 收紧成按声明类型配对，这样跟样本量无关。
        said_look = re.search(r"亲自(看|视|目检)|亲眼", text)
        said_run = re.search(r"亲自(跑|执行|验)|实跑|亲自运行", text)
        # SCOPED, not global. A bare substring search meant that writing "不适用"
        # anywhere in a 2000-word briefing switched off every V-3 check - including a
        # briefing that claimed "我亲自跑了 npm test 全绿" three lines earlier.
        # Only honour it when it sits in the ⑦ section it belongs to.
        neg = None
        try:
            mark = text.find("\u2466")          # ⑦
            # 窗口切到**下一个段标记**为止，不用固定字数：160 字会把 ⑧⑨ 和
            # 句尾的闲话一起吞进来，等于又变回全局匹配。
            if mark < 0:
                window = ""
            else:
                nxt = len(text)
                for mk in ("⑧", "⑨", "⑩"):
                    j = text.find(mk, mark + 1)
                    if j >= 0:
                        nxt = min(nxt, j)
                window = text[mark:min(nxt, mark + 300)]
            neg = re.search(r"(不适用|无用户可感知|纯内部改动)", window)
        except Exception:
            neg = None
        # V-3a 原本只认 connector(mcp__) 记录，但看图最常用的 Read 根本不在钩子
        # matcher 里、不产生任何记录，于是门禁一边要求「亲自看 after 图」一边惩罚
        # 真的去看的人——实测三个诚实场景全被误拦。判据放宽为「有任一执行证据」：
        # 宁可这条弱一点，也不能拦住诚实工作。
        if said_look and not (saw_visual or saw_shell) and not neg:
            problems.append("V-3a 看图无据：简报声称「亲自看」，"
                            "但本轮台账没有任何工具调用记录（截图/浏览器/命令都没有）。"
                            "（若本轮确无可感知改动，请写「⑦ 不适用」而不是声称看过。）")
        if said_run and not saw_shell and not neg:
            problems.append("V-3b 跑命令无据：简报声称「亲自跑/实跑」，"
                            "但本轮台账没有任何命令执行记录。")

        # V-5 引用的台账必须真实存在：粘一行伪造的台账行此前可以直接过。
        try:
            quoted = re.findall(r"^\|\s*\d{2}:\d{2}(?::\d{2})?\s*\|\s*"
                                r"(skill|agent|workflow|connector)\s*\|\s*([^|\r\n]+?)\s*\|"
                                r"\s*([^|\r\n]{0,240}?)\s*\|",
                                text, re.M)
            for kind, name, detail in quoted:
                nm = name.strip().casefold()
                if nm in ("-", "", "名称"):
                    continue
                outcomes = dispatch_outcomes.get((kind.casefold(), nm))
                if not outcomes:
                    problems.append("V-5 引用了台账里没有的记录：简报贴出「" + kind
                                    + " / " + name.strip()
                                    + "」，但本轮台账里查无此项。台账只能原样引用，不能补写。")
                    break
                claimed_match = re.search(r"\bstatus\s*=\s*([A-Za-z_-]+)", detail, re.I)
                if claimed_match:
                    claimed = claimed_match.group(1).casefold()
                    if claimed in SUCCESS_STATUSES:
                        claimed = "success"
                    elif claimed in FAILURE_STATUSES:
                        claimed = "failed"
                    if claimed not in outcomes:
                        problems.append("V-5 引用的调度状态不实：简报贴出「" + kind
                                        + " / " + name.strip() + " / status="
                                        + claimed_match.group(1) + "」，台账实际状态为 "
                                        + "、".join(sorted(outcomes)) + "。")
                        break
        except Exception:
            pass

        # V-6 [SKIP] 必须指名：全历史 skill 只被真实调用过 15 次，FLOOR 形同虚设，
        # 因为一句光秃秃的 [SKIP] 就能绕过去。要求每个 SKIP 说清跳过的是谁。
        try:
            cands = state.get("candidates") or []
            if cands and "[SKIP]" in text:
                named = sum(1 for c in cands if c and c in text)
                skips = text.count("[SKIP]")
                if skips >= 2 and named == 0:
                    problems.append("V-6 [SKIP] 未指名：简报里有 " + str(skips)
                                    + " 处 [SKIP]，但一个候选名都没提到。"
                                    + "⑨ 要求逐条指名说明为什么不适用，不能整片打发。")
        except Exception:
            pass

        # V-4 调度充分性整段缺失：只在"确实是一份简报"时才追究，避免误伤
        if len(text) > 400 and not re.search(r"⑧|FLOOR|实调|调度充分性", text):
            problems.append("V-4 ⑧ 调度充分性整段缺失：门禁要求交代 FLOOR 要求几项、"
                            "实调几项、未达下限的 [SKIP] 理由，简报里一个字都没有。")
    except Exception:
        return []                          # verifier must never break the session
    return problems


def handle_stop(stdin_data: dict) -> None:
    # NOTE: the bare {"event":"stop"} row this used to write is why self-auditability
    # scored 4.0 across two versions - 2276 stop rows with no record of whether the gate
    # actually blocked, or which check fired. Every exit below now says what it did.
    def _record(outcome, checks=None):
        ev = {"event": "stop", "gate": outcome}
        if checks:
            ev["checks"] = checks
        sid_now = stdin_data.get("session_id") or stdin_data.get("sessionId")
        sid_token = _session_token(sid_now)
        if sid_token:
            ev["sid"] = sid_token
        append_event(ev)

    transition = {}
    hook_active = bool(stdin_data.get("stop_hook_active"))

    def advance_stop(state):
        if not state.get("dev_tool_used"):
            transition["action"] = "skip-no-edits"
            return
        n_blocked = int(state.get("stop_blocked") or 0)
        if n_blocked >= 2:
            transition["action"] = "skip-cap-reached"
            return
        if hook_active and n_blocked == 0:
            transition["action"] = "skip-foreign-block"
            return
        if n_blocked == 1:
            state["stop_blocked"] = 2
            transition["action"] = "pass2"
            return
        state["stop_blocked"] = 1
        transition["action"] = "pass1"

    state = _update_turn_state(advance_stop)
    if state is None:
        _record("skip-state-lock-unavailable")
        return
    action = transition.get("action")
    if action == "skip-no-edits":
        _record("skip-no-edits")
        return
    # stop_hook_active is TRUE on exactly the continuation that follows our own pass-1
    # block. Returning here (as v8.0/v8.1 did) made pass 2 UNREACHABLE: measured over the
    # whole transcript history, 790 real pass-1 blocks and ZERO pass-2 runs, ever.
    # The stop_blocked counter is the real loop guard (hard cap 2), so the flag is now
    # only a belt-and-braces for the odd case where we never blocked at all.
    # stop_blocked is a COUNTER now: pass 1 demands the briefing, pass 2 cross-examines
    # it. Hard ceiling of 2 so this can never become a loop.
    if action == "skip-cap-reached":
        _record("skip-cap-reached")
        return                      # hard cap: never more than two blocks per turn
    if action == "skip-foreign-block":
        _record("skip-foreign-block")
        return                      # continuing from someone else's block; stay out

    if action == "pass2":
        # ---- pass 2: second-party verification -----------------------------
        problems = verify_briefing(stdin_data, state)
        if not problems:
            _record("pass2-clean")
            return                          # nothing provably wrong -> let it end
        msg = ("🛡️ 监工二次校验：简报与钩子记录对不上。这不是质量评判，"
               "只是把可机械判定的声明拿去对质——请逐条更正或补齐后再结束。" + chr(10)
               + chr(10).join("  · " + p for p in problems))
        _record("pass2-block", [p.split(" ", 1)[0] for p in problems])
        print(json.dumps({"decision": "block", "reason": msg}, ensure_ascii=False))
        return

    reason = (
        "🛡️ 监工门禁 v8.5：本轮发生了文件改动。停止前请输出简报——"
        "①本轮目标 ②改动的文件 ③测试/验证结果(真实输出) ④Karpathy K1-K4 自评 "
        "⑤code-review-graph 门禁执行情况或一句话豁免理由 ⑥待跟进事项。"
        "⑦[v5 效果验收]本轮若有用户可感知改动(UI/视觉/文案/交互/动效)必答：我亲自看的 after 图路径或亲自跑的关键命令"
        "(不许只引子agent回执)+视觉四问结论(元素是否真变少/层级是否建立/是否更高级/是否更想点)；纯内部改动写「C2 不适用」。"
        "⑧[v5 调度充分性]FLOOR 要求 N 项/实调 M 项；未达下限须给 [SKIP] 指名理由。"
        "⑨[v7 拆解对表]贴出本轮的「子任务/需要能力/候选/决定/理由」表；横幅列出的候选每一条都必须处置(用 或 [SKIP]+指名理由)，不许整段无视。"
        "另请把本项目 ~/.claude/supervisor/state/contexts/<项目键>.md 的状态写穿(若有实质进展)。"
        "补交后即可正常结束；本门禁每轮仅拦截一次。"
    )
    reason = reason + render_ledger()
    _record("pass1-block")
    print(json.dumps({"decision": "block", "reason": reason}, ensure_ascii=False))


def main() -> int:
    if len(sys.argv) < 2:
        return 0
    event_type = sys.argv[1]
    try:
        stdin_data = read_stdin_json()
        set_session(stdin_data)      # must precede any read/write of turn state
        if event_type == "session-start":
            def start_session(state):
                state.update({
                    "session_started_at": datetime.now().isoformat(timespec="seconds"),
                    "turn": 0,
                })

            _update_turn_state(start_session)
            prune_state_files()
            append_event({"event": "session-start", "cwd": stdin_data.get("cwd", "")})
        elif event_type == "prompt-submit":
            handle_prompt_submit(stdin_data)
        elif event_type == "pre-tool":
            handle_pre_tool(stdin_data)
        elif event_type == "post-tool":
            handle_post_tool(stdin_data)
        elif event_type == "stop":
            handle_stop(stdin_data)
    except Exception:
        return 0  # fail-open: hooks must never break the conversation
    return 0


if __name__ == "__main__":
    sys.exit(main())
