#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sup-plan — 每轮把「真实存在的候选」摆到模型面前，并逼它逐条对表。

诚实说明这东西不是什么：
    它**不做智能判断**。它是检索器 + 强制器，不是大脑。
    智能拆解由模型做；本脚本只保证模型看到的是**磁盘上真实存在、且名字可以直接调用**
    的候选，而不是它记忆里那张会过期的手写池表。
    过去「调用不够灵活/偷懒少调」的机械成因就是：模型只能凭记忆想起几个 skill。

索引两类对象：
    skill  ~/.claude/skills/**          -> 调用名＝目录名
           ~/.claude/plugins/cache/**   -> 调用名＝ <plugin>:<name>（裸名会 Unknown skill）
    agent  ~/.claude/agents/*.md        -> 调用名＝ frontmatter 的 name 字段
           实测 185 个 agent 里 **184 个**的文件名 ≠ 调用名
           （engineering-backend-architect.md 的调用名是 "Backend Architect"）

中英文都要能检索：中文按字符二元组匹配，英文按词元匹配，两者加权合并。

用法：
    python sup-plan.py "把首页卡片的排版改好看一点"     # 看候选
    python sup-plan.py --rebuild                        # 强制重建索引
    python sup-plan.py --stats                          # 索引概况
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sys
import time
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

CLAUDE = Path.home() / ".claude"
SKILLS_DIR = CLAUDE / "skills"
PLUGINS_DIR = CLAUDE / "plugins"
AGENTS_DIR = CLAUDE / "agents"
SETTINGS = CLAUDE / "settings.json"
INDEX = CLAUDE / "supervisor" / "state" / "dispatch-index.json"
CLAUDE_JSON = Path.home() / ".claude.json"
AUTH_CACHE = CLAUDE / "mcp-needs-auth-cache.json"
PLUGIN_CONFIG_STATUS = "unknown"
PLUGIN_FINGERPRINT_PREFIX_BYTES = 4096
PERSONAL_FINGERPRINT_PREFIX_BYTES = 4096

CJK = re.compile(r"[一-鿿]")
WORD = re.compile(r"[a-z0-9][a-z0-9_+.-]*")
STOP = {"the", "and", "for", "use", "when", "this", "that", "with", "from", "you",
        "your", "are", "not", "should", "used", "using", "skill", "user", "will",
        "can", "any", "all", "its", "into", "than", "then", "them", "have", "has"}


# ------------------------------------------------------------------ index ----
def _fm(path: Path, limit=4000):
    """(name, description) from frontmatter; falls back to the directory name."""
    try:
        with io.open(path, encoding="utf-8", errors="replace") as handle:
            txt = handle.read(limit)
    except Exception:
        return None
    m = re.search(r"^---\s*$(.*?)^---\s*$", txt, re.M | re.S)
    fm = m.group(1) if m else txt[:1500]
    n = re.search(r"^name:\s*(.+)$", fm, re.M)
    d = re.search(r"^description:\s*(.+?)(?:^\w+:|\Z)", fm, re.M | re.S)
    name = n.group(1).strip().strip("'\"") if n else path.parent.name
    desc = " ".join(d.group(1).split())[:400] if d else ""
    return name, desc


def _enabled_plugins():
    global PLUGIN_CONFIG_STATUS
    try:
        with io.open(SETTINGS, encoding="utf-8") as handle:
            cfg = json.load(handle)
        configured = cfg.get("enabledPlugins") if isinstance(cfg, dict) else None
        if not isinstance(configured, dict):
            PLUGIN_CONFIG_STATUS = "unavailable"
            return None
        PLUGIN_CONFIG_STATUS = "available"
        return {k.split("@")[0] for k, v in configured.items() if v}
    except Exception:
        PLUGIN_CONFIG_STATUS = "unavailable"
        return None


def _sources_stamp():
    """Cheap fingerprint of the on-disk sources, so the cache self-invalidates."""
    newest, count = 0.0, 0
    plugin_count = 0
    plugin_digest = hashlib.sha256()
    personal_count = 0
    personal_digest = hashlib.sha256()
    enabled = _enabled_plugins()
    for root_label, root in (("skills", SKILLS_DIR), ("agents", AGENTS_DIR)):
        if not root.exists():
            continue
        for p in sorted(root.rglob("*.md"), key=lambda path: path.as_posix().casefold()):
            try:
                if p.is_symlink():
                    continue
                root_real = os.path.normcase(os.path.realpath(os.fspath(root)))
                path_real = os.path.normcase(os.path.realpath(os.fspath(p)))
                if os.path.commonpath((root_real, path_real)) != root_real:
                    continue
                rel = p.relative_to(root).as_posix()
                with p.open("rb") as handle:
                    data = handle.read(PERSONAL_FINGERPRINT_PREFIX_BYTES)
                stat_result = p.stat()
                personal_digest.update(root_label.encode("ascii"))
                personal_digest.update(b"/")
                personal_digest.update(rel.encode("utf-8", "surrogatepass"))
                personal_digest.update(b"\0")
                personal_digest.update(hashlib.sha256(data).digest())
                newest = max(newest, stat_result.st_mtime)
                count += 1
                personal_count += 1
            except Exception:
                pass
    cache = PLUGINS_DIR / "cache"
    if cache.exists():
        for p in sorted(cache.rglob("SKILL.md"), key=lambda path: path.as_posix().casefold()):
            try:
                rel = p.relative_to(PLUGINS_DIR).as_posix()
                parts = rel.split("/")
                plugin = parts[2] if len(parts) > 2 and parts[0] == "cache" else "?"
                if enabled is None or plugin not in enabled:
                    continue
                with p.open("rb") as handle:
                    data = handle.read(PLUGIN_FINGERPRINT_PREFIX_BYTES)
                stat_result = p.stat()
                plugin_digest.update(rel.encode("utf-8", "surrogatepass"))
                plugin_digest.update(b"\0")
                plugin_digest.update(hashlib.sha256(data).digest())
                newest = max(newest, stat_result.st_mtime)
                count += 1
                plugin_count += 1
            except Exception:
                pass
    connector_sources = {
        "claude_json": _connector_source_stamp(CLAUDE_JSON, "mcpServers"),
        "auth_cache": _connector_source_stamp(AUTH_CACHE),
    }
    return {
        "newest": round(newest, 2),
        "count": count,
        "plugin_skill_count": plugin_count,
        "plugin_fingerprint": plugin_digest.hexdigest(),
        "personal_markdown_count": personal_count,
        "personal_fingerprint": personal_digest.hexdigest(),
        "plugin_config_status": PLUGIN_CONFIG_STATUS,
        "enabled_plugins": sorted(enabled) if enabled is not None else None,
        "connector_sources": connector_sources,
    }


def _connector_source_stamp(path: Path, nested_key: str | None = None):
    """Fingerprint only index-relevant connector names plus safe file metadata.

    Connector configuration can contain credentials.  The dispatch cache therefore
    never stores raw JSON or secret-derived values; it records presence, metadata,
    parse state, and a digest of the connector names that the index itself exposes.
    """
    try:
        stat_result = path.stat()
    except FileNotFoundError:
        return {"present": False}
    except OSError:
        return {"present": True, "status": "unavailable"}

    status = "malformed"
    names = []
    try:
        with path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
        source = payload.get(nested_key) if nested_key and isinstance(payload, dict) else payload
        if isinstance(source, dict):
            names = sorted(str(name) for name in source if isinstance(name, str))
            status = "available"
        else:
            status = "unavailable"
    except Exception:
        pass

    digest = hashlib.sha256()
    for name in names:
        digest.update(name.encode("utf-8", "surrogatepass"))
        digest.update(b"\0")
    return {
        "present": True,
        "status": status,
        "size": stat_result.st_size,
        "mtime_ns": stat_result.st_mtime_ns,
        "names_fingerprint": digest.hexdigest(),
    }


def _build_df(items):
    """Document frequency per token and per CJK bigram, over the whole index.

    This is what separates a term that identifies something from a term that is just
    common English. Without it, "content"/"design"/"agent" drown out the real signal.
    """
    import math
    df_w, df_b = {}, {}
    for it in items:
        w, b = _feats(it.get("blob") or "")
        for t in w:
            df_w[t] = df_w.get(t, 0) + 1
        for t in b:
            df_b[t] = df_b.get(t, 0) + 1
    n = max(1, len(items))
    idf_w = {t: math.log(1.0 + n / (1.0 + c)) for t, c in df_w.items()}
    idf_b = {t: math.log(1.0 + n / (1.0 + c)) for t, c in df_b.items()}
    return idf_w, idf_b, n


def build_index():
    items = []

    if SKILLS_DIR.exists():
        for p in SKILLS_DIR.rglob("SKILL.md"):
            r = _fm(p)
            if not r:
                continue
            name, desc = r
            items.append({"kind": "skill", "call": name, "desc": desc, "src": "personal"})

    if PLUGINS_DIR.exists():
        en = _enabled_plugins()
        for p in PLUGINS_DIR.rglob("SKILL.md"):
            rel = p.relative_to(PLUGINS_DIR).as_posix().split("/")
            if "skills" not in rel or rel[0] != "cache":      # marketplaces/ = 未安装
                continue
            plugin = rel[2] if len(rel) > 2 else "?"
            # Match sup-discover.py: an empty enabledPlugins map enables nothing,
            # while an unreadable/malformed map is an unavailable capability source.
            if en is None or plugin not in en:
                continue
            r = _fm(p)
            if not r:
                continue
            name, desc = r
            items.append({"kind": "skill", "call": plugin + ":" + name,
                          "desc": desc, "src": "plugin"})

    if AGENTS_DIR.exists():
        for p in sorted(AGENTS_DIR.glob("*.md")):
            r = _fm(p)
            if not r:
                continue
            name, desc = r
            # frontmatter name IS the callable subagent_type (184/185 differ from filename)
            items.append({"kind": "agent", "call": name, "desc": desc, "src": "personal"})

    # ---- plugins（settings.json 的 enabledPlugins）--------------------------
    try:
        with io.open(SETTINGS, encoding="utf-8") as handle:
            cfg = json.load(handle)
        for full, on in (cfg.get("enabledPlugins") or {}).items():
            if not on:
                continue
            nm = full.split("@")[0]
            items.append({"kind": "plugin", "call": nm,
                          "desc": "已启用插件（来源 " + full.split("@")[-1] + "）；"
                                  "它带的 skill 已单独索引，调用写 " + nm + ":<skill>",
                          "src": "settings"})
    except Exception:
        pass

    # ---- connectors（本地 MCP + claude.ai 侧）--------------------------------
    try:
        with io.open(CLAUDE_JSON, encoding="utf-8") as handle:
            cj = json.load(handle)
        for nm in (cj.get("mcpServers") or {}):
            items.append({"kind": "connector", "call": nm,
                          "desc": "本地 MCP 服务，工具名形如 mcp__" + nm + "__<tool>",
                          "src": "local"})
    except Exception:
        pass
    try:
        with io.open(AUTH_CACHE, encoding="utf-8") as handle:
            ac = json.load(handle)
        for nm in (ac if isinstance(ac, dict) else {}):
            items.append({"kind": "connector", "call": nm,
                          "desc": "claude.ai 连接器（**需先授权**，未授权时不可调用）；"
                                  "磁盘上只有名字没有描述，所以只能按名字检索",
                          "src": "claude.ai"})
    except Exception:
        pass

    seen, uniq = set(), []
    for it in items:
        k = (it["kind"], it["call"].casefold())
        if k in seen:
            continue
        seen.add(k)
        # connector/plugin 只有样板描述，没有真实说明。把样板放进检索用的 blob，
        # 等于让「连接器」「调用」「检索」这些词给每一条连接器凭空加分——
        # 实测「让 skill 能够灵活调用起来」因此召回了 claude.ai Box。只用名字。
        if it["kind"] in ("connector", "plugin"):
            it["blob"] = it["call"].casefold()
        else:
            it["blob"] = (it["call"] + " " + it["desc"]).casefold()
        uniq.append(it)
    idf_w, idf_b, ndoc = _build_df(uniq)
    return {"stamp": _sources_stamp(), "built": time.strftime("%Y-%m-%d %H:%M:%S"),
            "plugin_config_status": PLUGIN_CONFIG_STATUS,
            "items": uniq, "idf_w": idf_w, "idf_b": idf_b, "ndoc": ndoc}


def load_index(force=False):
    if not force:
        try:
            with io.open(INDEX, encoding="utf-8") as handle:
                idx = json.load(handle)
            if idx.get("stamp") == _sources_stamp():
                return idx, False
        except Exception:
            pass
    idx = build_index()
    try:
        _atomic_write_index(idx)
    except Exception:
        pass
    return idx, True


def _atomic_write_index(index):
    """Durably replace the cache without exposing a partial JSON document."""
    INDEX.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(index, ensure_ascii=False).encode("utf-8")
    temporary = INDEX.with_name(
        "." + INDEX.name + "." + str(os.getpid()) + "." + str(time.time_ns()) + ".tmp"
    )
    fd = None
    try:
        fd = os.open(str(temporary), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = None
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, INDEX)
        try:
            directory_fd = os.open(str(INDEX.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    finally:
        if fd is not None:
            os.close(fd)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


# -------------------------------------------------------------- retrieval ----
# ------------------------------------------------------------- 中英桥接 ----
# 用户用中文提需求，而 skill/agent 的描述几乎全是英文。不做这层映射，
# 「排版」永远匹配不到 "layout"，检索命中率实测为 0。
LEXICON = {
    # 视觉 / 设计
    # 以下映射的英文词均**反查自真实描述文本**，不是凭空猜的
    # （审计给的 18 条补充被其检验员驳回，正因为那些英文词语料里没有）
    "数据表": "database table schema sql",
    "表结构": "schema database table design",
    "字段": "field column schema database",
    "索引": "index indexing query database",
    "查询": "query sql database select",
    "建表": "schema table database migration",
    "无障碍": "accessibility wcag assistive inclusive",
    "可访问性": "accessibility wcag inclusive",
    "读屏": "screen reader accessibility assistive",
    "代码": "code source implementation review",
    "通读": "review read through inspect",
    "评审": "review reviewer feedback critique",
    "审稿": "review reviewer peer academic paper",
    "同行": "peer review academic",
    "文献": "literature research paper academic",
    "综述": "literature review survey research",
    "初稿": "draft writing editing",
    "润色": "polish edit rewrite natural writing",
    "改写": "rewrite edit revise writing",
    "自然": "natural human-written authentic",
    "口吻": "tone voice writing style",
    "味": "style tone flavour",
    # 3D 重建类（2026-08-20 装 img2threejs 后补；英文词反查自其 description）
    "参考图": "reference image photo input",
    "重建": "reconstruction rebuild reconstruct",
    "建模": "model modeling sculpt mesh geometry",
    "模型": "model mesh geometry asset",
    "程序化": "procedural generated code-only",
    "角色": "character humanoid figure avatar",
    "网格": "mesh geometry topology",
    "贴图": "texture uv material map",
    "骨骼": "rig skeleton bone skinning armature",
    "绑定": "rig rigging skinning bind",
    "材质": "material pbr shader surface",
    # 元/工具链类需求（实测最弱的一类：本轮自身的提示词检索结果就很差）
    "记录": "log logging record track audit trail history",
    "存档": "archive transcript record history",
    "归档": "archive retention cleanup",
    "台账": "ledger record audit log",
    "派单": "dispatch routing delegate orchestrate",
    "调度": "dispatch orchestrate route schedule",
    "编排": "orchestrate workflow pipeline agent",
    "监工": "supervisor monitor governance hook",
    "插件": "plugin extension marketplace",
    "技能": "skill capability tool",
    "代理": "agent subagent delegate",
    "连接器": "connector mcp integration",
    "自动": "automation automatic workflow hook",
    "触发": "trigger hook event fire",
    "规则": "rule policy governance guideline",
    "门禁": "gate gating enforcement check",
    # 短键优先：长词做子串匹配太脆，实测「没反应」匹配不到「没有任何反应」
    "解决": "fix solve debug resolve troubleshoot",
    "彻底": "root cause thorough systematic",
    "反应": "bug debug broken unresponsive not working",
    "问题": "issue bug problem debug",
    "错误": "error bug exception debug",
    "失败": "fail failure error debug test",
    "崩": "crash bug error",
    "卡": "hang freeze slow performance",
    "慢": "slow performance optimize latency",
    "排查": "debug investigate troubleshoot root cause",
    "定位": "locate debug investigate trace",
    "复现": "reproduce repro debug test",
    "回归": "regression test verify",
    "覆盖": "coverage test",
    "重写": "rewrite refactor",
    "整理": "organize cleanup refactor structure",
    "检查": "check review audit inspect verify",
    "评分": "score rating evaluate benchmark",
    "评估": "evaluate assessment benchmark review",
    "对比": "compare comparison benchmark diff",
    "升级": "upgrade improve enhance refactor",
    "扩展": "extend scale expand",
    "迁移": "migrate migration port",
    "配置": "config configuration setup",
    "安装": "install setup bootstrap",
    "钩子": "hook lifecycle event",
    "脚本": "script automation cli",
    "命令": "command cli terminal",
    "终端": "terminal cli shell",
    "浏览器": "browser chrome playwright e2e",
    "截图": "screenshot visual capture",
    "端口": "port server localhost",
    "服务": "server service backend api",
    "排版": "layout typography spacing grid composition",
    "布局": "layout grid composition responsive",
    "对齐": "align alignment layout",
    "留白": "spacing whitespace padding margin",
    "间距": "spacing padding margin",
    "字体": "font typography typeface",
    "字号": "font size typography scale",
    "颜色": "color palette theme contrast",
    "配色": "color palette theme",
    "美观": "design visual aesthetic beautiful polish",
    "好看": "design visual aesthetic beautiful polish",
    "高级": "premium refined elegant polish design",
    "质感": "premium texture visual design",
    "风格": "style aesthetic design brand",
    "审美": "aesthetic taste design visual",
    "卡片": "card component ui",
    "按钮": "button component ui",
    "图标": "icon svg asset",
    "图片": "image asset photo visual",
    "界面": "interface ui screen",
    "页面": "page screen ui frontend",
    "首页": "landing homepage hero page",
    "组件": "component ui react",
    "设计": "design ui visual brand",
    "品牌": "brand identity logo",
    "海报": "poster canvas design print",
    "幻灯片": "slides pptx presentation deck",
    "文档": "document docx report writing",
    # 动效
    "动效": "animation motion transition gsap",
    "动画": "animation motion gsap transition",
    "过渡": "transition animation motion",
    "滚动": "scroll scrolltrigger parallax",
    "悬停": "hover interaction micro",
    # 前端 / 工程
    "前端": "frontend react ui web component",
    "响应式": "responsive mobile breakpoint adaptive",
    "移动端": "mobile responsive ios android",
    "样式": "css style styling tailwind",
    "重构": "refactor cleanup simplify",
    "性能": "performance optimize speed profiling",
    "优化": "optimize performance improve refine",
    "调试": "debug bug troubleshoot root cause",
    "报错": "error bug debug exception failure",
    "没反应": "bug debug broken not working",
    "修复": "fix bug repair debug",
    "登录": "login auth authentication signin",
    "注册": "signup registration auth",
    "权限": "permission auth access role",
    "接口": "api endpoint interface backend",
    "后端": "backend server api database",
    "数据库": "database sql schema query postgres",
    "部署": "deploy deployment ci release ship",
    "测试": "test testing verify qa assertion",
    "验证": "verify verification validate check",
    "审查": "review audit critique inspect",
    "代码审查": "code review audit",
    "安全": "security vulnerability audit threat",
    "架构": "architecture system design scalable",
    "规划": "plan planning roadmap brainstorm",
    "拆解": "decompose breakdown plan task subtask",
    "文案": "copy copywriting content messaging",
    "内容": "content copy writing",
    "精简": "concise simplify distill reduce",
    # 数据 / 分析
    "数据": "data analytics dataset metrics",
    "统计": "statistics analytics data analysis",
    "分析": "analysis analytics research insight",
    "图表": "chart graph visualization dataviz",
    "报表": "report dashboard analytics",
    "表格": "spreadsheet xlsx table data",
    # 内容 / 教育 / 研究
    "教学": "teaching education classroom lesson",
    "课件": "slides teaching presentation lesson",
    "论文": "paper academic research writing",
    "研究": "research investigate study",
    "调研": "research survey investigate benchmark",
    "检索": "search retrieval lookup research",
    "翻译": "translate translation language",
    # 媒体
    "视频": "video editing render footage",
    "音频": "audio sound speech voice",
    "生图": "image generation generate art",
    "渲染": "render rendering 3d graphics",
    "三维": "3d three threejs webgl render",
    "形象": "character avatar mascot 3d model",
    # 流程 / 协作
    "提交": "commit git version control",
    "分支": "branch git workflow",
    "发布": "release ship publish deploy",
    "版本": "version release changelog",
    "文档化": "document documentation write",
    "自动化": "automation workflow pipeline",
    "监控": "monitor observability logging metrics",
    "日志": "log logging observability",
}


def expand_cjk(text):
    """Chinese query -> the English vocabulary the descriptions actually use."""
    extra = []
    for zh, en in LEXICON.items():
        if zh in text:
            extra.append(en)
    return " ".join(extra)


# 内容为零的中文二元组。它们在 9 条中文描述里出现一次就能拿满分，
# 却完全不表达需求（「帮我」是客套，不是意图）。
CJK_STOP_BIGRAMS = {
    "帮我", "一下", "这个", "那个", "一个", "我们", "可以", "什么", "怎么", "如何",
    "现在", "然后", "还有", "以及", "进行", "需要", "应该", "是否", "或者", "但是",
    "因为", "所以", "这样", "那样", "东西", "内容", "方面", "问题", "情况", "时候",
    "一些", "有些", "比较", "非常", "特别", "已经", "还是", "就是", "不是", "没有",
}


def _feats(text):
    t = text.casefold()
    words = {w for w in WORD.findall(t) if len(w) > 2 and w not in STOP}
    cjk = CJK.findall(t)
    bigrams = {cjk[i] + cjk[i + 1] for i in range(len(cjk) - 1)}
    bigrams -= CJK_STOP_BIGRAMS
    return words, bigrams


_I18N = re.compile(r"[-_](zh|zht|cn|tw|ar|de|es|fr|ja|ko|pt|ru|it|nl|pl|tr|vi|th|hi)$", re.I)


def _family(call):
    """Group near-identical entries so one family cannot swamp the list.

    planning-with-files ships 6 language variants; without grouping they filled every
    slot in a real query and hid all the genuinely different candidates.
    """
    base = call.split(":")[-1].casefold()
    base = _I18N.sub("", base)
    return (call.split(":")[0].casefold() if ":" in call else "") + "/" + base


def retrieve(prompt, idx, k=6):
    # bridge Chinese -> English BEFORE feature extraction, otherwise a Chinese
    # request can never match an English description (measured: 0 hits)
    # 用户真正打出来的词 > 我推断扩展出来的词。此前两者同权，于是「内容」扩成
    # content 后把 Content Creator 顶到了第一——而那个「内容」只是「那几条内容」的意思。
    pw, pb = _feats(prompt)
    ew, _eb = _feats(expand_cjk(prompt))
    ew = ew - pw
    if not pw and not pb:
        return []
    # Meta-infrastructure prompts are especially vulnerable to incidental name
    # collisions ("内容" -> Content Creator, "脚本" -> Roblox Scripter, "测试" ->
    # API Tester). Those vertical specialists have a hard negative trigger unless
    # the user actually names their vertical. This is a routing boundary, not a
    # score tweak: a supervisor/hook/ledger task is not an API, game, sales, or
    # content-production task merely because its prose shares one generic word.
    meta_query = any(token in prompt.casefold() for token in (
        "监工", "钩子", "校验器", "台账", "skill.md", "待跟进", "继续完成", "supervisor", "hook", "ledger"
    ))
    meta_negative_markers = (
        "content creator", "bilibili", "xiaohongshu", "weibo", "ad creative",
        "app store", "xcode", "api tester", "agentic search", "roblox", "godot",
        "blender", "paid media", "sales ",
    )
    # IDF: a term present in most descriptions carries almost no information.
    # Flat weights let "content"/"design"/"agent" outrank the actual answer.
    idf_w = idx.get("idf_w") or {}
    idf_b = idx.get("idf_b") or {}
    default_idf = 1.0 if not idf_w else 0.6

    def _w(tok, table):
        return table.get(tok, default_idf)

    out = []
    for it in idx.get("items", []):
        blob = it.get("blob") or ""
        name = it["call"].casefold()
        if meta_query and any(marker in name for marker in meta_negative_markers):
            continue
        score = 0.0
        for w in pw:
            iw = _w(w, idf_w)
            if w in name:
                # 名字命中用 idf 的平方：线性 idf 对常见词区分度不够
                # （常见词 2.36 vs 罕见词 4.88，只差 2 倍），而名字命中有 6 倍加成，
                # 于是 "Content" Creator、"API" Tester、"Agentic" Search 这类
                # 名字里含通用词的条目会被顶到前排。平方后差距拉到 5 倍以上。
                score += 6.0 * iw * iw / 4.0
            elif w in blob:
                score += 2.0 * iw
        for w in ew:
            # 扩展词**不享受名字命中加成**。用户没打出这个词，是我从中文推断的；
            # 再把「推断词命中名字」当强证据，等于把两次猜测叠在一起。
            # 实测根因：「脚本」推出 script 命中 Roblox Systems Scripter（idf 5.29，
            # 词本身很罕见，IDF 救不了）；「内容」推出 content 命中 Content Creator；
            # 「测试」推出 test 命中 API Tester。三条噪声同一个成因。
            # 定权原则（不是凑出来的数）：
            #   「我推断的词命中名字」 ≈ 「用户真打的词命中描述」 —— 证据强度相当。
            # 完全取消名字加成会把中文查询打残（登录→auth、排查→debug 全靠扩展），
            # 实测那样 Recall@6 从 10/10 掉到 9/10、留出组 6/6 掉到 5/6。
            iw = _w(w, idf_w)
            if w in name:
                score += 2.0 * iw
            elif w in blob:
                score += 1.2 * iw
        for b in pb:
            # 中文二元组**不做 IDF 加权**。全库只有 9/393 条描述含中文，
            # 于是每个中文词的 idf 都顶格（min 4.60 / median 5.29 / max 5.29），
            # IDF 判定「极罕见＝极有信息量」——在这里完全反了：它们罕见是因为
            # 几乎没人用中文写描述，不是因为有区分度。
            # 实测后果：「帮我」一词 14.65 分，把 planning-with-files-zh(22.84)
            # 顶到 ce-debug(11.08) 之上；带「帮我」的查询有一半 rank-1 被劫持。
            # 英文那 393 条语料上 IDF 成立，中文这 9 条上不成立 —— 按语言分治。
            if b in CJK_STOP_BIGRAMS:
                continue
            if b in name:
                score += 4.0
            if b in blob:
                score += 3.0
        # mild length normalisation: a 400-char description should not win on volume
        if score:
            score = score / (1.0 + len(blob) / 900.0)
            # 需先授权的连接器当前根本调不动，不该和可用项抢前排
            if it["kind"] == "connector" and it.get("src") == "claude.ai":
                score *= 0.35
            out.append((score, it))
    out.sort(key=lambda x: (-x[0], x[1]["call"]))
    # Diversity pass. Without it a single skill family swamps the whole list:
    # planning-with-files ships 6 i18n variants (-ar/-de/-es/-zh/-zht) and they took
    # all 6 slots, hiding every genuinely different candidate.
    top = []
    seen_kind = {"skill": 0, "agent": 0, "plugin": 0, "connector": 0}
    fam_used = {}
    for sc, it in out:
        kind = it["kind"]
        cap = {"skill": max(3, k - 2), "agent": max(2, k // 3)}.get(kind, 2)
        if seen_kind.get(kind, 0) >= cap:
            continue
        fam = _family(it["call"])
        if fam_used.get(fam, 0) >= 1:      # at most ONE member per family
            continue
        fam_used[fam] = fam_used.get(fam, 0) + 1
        seen_kind[kind] = seen_kind.get(kind, 0) + 1
        top.append((sc, it))
        if len(top) >= k:                  # respect k exactly
            break
    # Relative noise floor: anything scoring far below the best match is almost
    # certainly an incidental word collision (a "Book Co-Author" showing up for a
    # login bug), and printing it every turn trains the reader to ignore the list.
    if top:
        best = top[0][0]
        top = [(sc, it) for sc, it in top if sc >= max(0.8, best * 0.30)]
    return top


# ----------------------------------------------------------- 分句检索 ------
# 一句话多诉求时，整句检索会让强势诉求的词占满分数，弱势诉求一条候选都拿不到。
# 切开分别检索，每个诉求各自归位。
CLAUSE_SPLIT = re.compile(
    r"[。！？!?；;\n]+"                                  # 句末
    r"|，(?=\s*(?:同时|另外|此外|以及|并且|并|还要|还需|还有|然后|接着|再|顺便|其次|最后))"
    r"|(?<=[。；])\s*"
)
CONJ_LEAD = re.compile(r"^(同时|另外|此外|以及|并且|并|还要|还需|还有|然后|接着|再|顺便|其次|最后|请|帮我|麻烦)[，,、\s]*")


def split_clauses(text, max_clauses=4, min_len=6):
    """Break a multi-intent prompt into intent-sized pieces."""
    try:
        raw = [c.strip() for c in CLAUSE_SPLIT.split(text or "") if c and c.strip()]
        out = []
        for c in raw:
            c = CONJ_LEAD.sub("", c).strip()
            if len(c) >= min_len:
                out.append(c)
        if not out:
            return [text.strip()] if text and text.strip() else []
        # 长句还带并列诉求时，再按逗号切一层
        if len(out) == 1 and len(out[0]) > 40 and "，" in out[0]:
            parts = [p.strip() for p in out[0].split("，") if len(p.strip()) >= min_len]
            if len(parts) > 1:
                out = parts
        return out[:max_clauses]
    except Exception:
        return [text] if text else []


def retrieve_by_clause(prompt, idx, per_clause=3, total=6):
    """Retrieve per intent, then merge. Returns [(clause, [(score,item),...]), ...].

    Guarantees every clause that matches anything gets at least one slot, so a
    secondary request cannot be crowded out by the dominant one.
    """
    clauses = split_clauses(prompt)
    if len(clauses) <= 1:
        return [(None, retrieve(prompt, idx, total))]
    groups, seen = [], set()
    for c in clauses:
        hits = []
        for sc, it in retrieve(c, idx, per_clause + 2):
            if it["call"] in seen:
                continue
            seen.add(it["call"])
            hits.append((sc, it))
            if len(hits) >= per_clause:
                break
        if hits:
            groups.append((c, hits))
    if not groups:
        return [(None, [])]
    # 总量裁剪：从最长的组开始削，保证每组至少留 1 条
    while sum(len(h) for _c, h in groups) > total:
        biggest = max(range(len(groups)), key=lambda i: len(groups[i][1]))
        if len(groups[biggest][1]) <= 1:
            break
        groups[biggest] = (groups[biggest][0], groups[biggest][1][:-1])
    return groups


def render_plan_block(prompt, k=6, max_chars=1500):
    """The block injected into the turn banner. Must stay small - it is paid every turn."""
    try:
        idx, _ = load_index()
        cnt = {}
        for i in idx.get("items", []):
            cnt[i["kind"]] = cnt.get(i["kind"], 0) + 1
        L = []
        L.append("🔎 候选派单（磁盘实时检索 · skill %d / agent %d / plugin %d / connector %d · 名字照抄即可调用）"
                 % (cnt.get("skill", 0), cnt.get("agent", 0),
                    cnt.get("plugin", 0), cnt.get("connector", 0)))
        if idx.get("plugin_config_status") == "unavailable":
            L.append("   ⚠ enabledPlugins 不可用；已排除全部缓存插件 Skill，不把缓存冒充为可调用能力。")

        def _row(it):
            tag = {"skill": "skill", "agent": "agent",
                   "plugin": "plug ", "connector": "conn "}.get(it["kind"], "?    ")
            return "   [%s] %s :: %s" % (tag, it["call"], it["desc"][:64])

        groups = retrieve_by_clause(prompt, idx, per_clause=3, total=k)
        any_hit = any(h for _c, h in groups)
        if not any_hit:
            L.append("   本轮无关键词命中——若属研发轮，仍须自己跑 sup-plan.py 或 sup-discover.py 复核。")
        elif len(groups) == 1 and groups[0][0] is None:
            for _sc, it in groups[0][1]:
                L.append(_row(it))
        else:
            # 多诉求：按诉求分组，弱势诉求也保底有一条，不被强势诉求挤掉
            for n, (clause, hits2) in enumerate(groups, 1):
                L.append("   诉求%d「%s」" % (n, (clause or "")[:26]))
                for _sc, it in hits2:
                    L.append(_row(it))
        L.append("   ⚠ 这是检索结果不是决定。必须逐条判断用不用，不用要在 ⑧ 写 [SKIP] 指名理由。")
        s = "\n".join(L)
        if len(s) <= max_chars:
            return s
        prefix = s[:max_chars]
        if s[max_chars:max_chars + 1] == "\n":
            return prefix
        complete, separator, _partial = prefix.rpartition("\n")
        return complete if separator else prefix
    except Exception:
        return ""


def main():
    if "--rebuild" in sys.argv:
        idx, _ = load_index(force=True)
        print("索引已重建：%d 条" % len(idx["items"]))
        return
    if "--stats" in sys.argv:
        idx, fresh = load_index()
        sk = [i for i in idx["items"] if i["kind"] == "skill"]
        ag = [i for i in idx["items"] if i["kind"] == "agent"]
        print("索引构建于 %s（本次 %s）" % (idx.get("built"), "重建" if fresh else "命中缓存"))
        print("  skill %d（个人 %d / 插件 %d）" %
              (len(sk), sum(1 for i in sk if i["src"] == "personal"),
               sum(1 for i in sk if i["src"] == "plugin")))
        print("  agent %d" % len(ag))
        print("  索引文件 %s" % INDEX)
        return
    q = " ".join(a for a in sys.argv[1:] if not a.startswith("--"))
    if not q:
        print(__doc__)
        return
    print(render_plan_block(q, k=8))


if __name__ == "__main__":
    main()
