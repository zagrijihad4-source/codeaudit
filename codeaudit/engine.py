# -*- coding: utf-8 -*-
"""
CodeAudit 扫描引擎

设计原则：
  1. 零第三方依赖 —— 客户机器上 python 直跑，不需要 pip install 任何东西；
  2. 规则与引擎分离 —— rules.json 可热更新、可私有化定制（这是交付的增值点）；
  3. 降噪优先 —— 安全报告最大的敌人是噪声，误报会让客户直接不看了。
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Iterable

# ---------------------------------------------------------------- 常量表

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_WEIGHT = {"critical": 40, "high": 18, "medium": 7, "low": 2}
SEVERITY_LABEL = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}

DEFAULT_RULES = Path(__file__).with_name("rules.json")

EXT_LANG = {
    ".py": "python", ".pyw": "python",
    ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "jsx",
    ".ts": "ts", ".tsx": "tsx", ".vue": "vue", ".svelte": "js",
    ".java": "java", ".kt": "java", ".scala": "java",
    ".php": "php", ".rb": "ruby", ".go": "go", ".rs": "rust",
    ".cs": "cs", ".c": "c", ".h": "c", ".cpp": "c", ".cc": "c", ".hpp": "c",
    ".html": "html", ".htm": "html", ".ejs": "html", ".jsp": "html",
    ".json": "json", ".yaml": "yaml", ".yml": "yaml", ".toml": "toml",
    ".env": "env", ".ini": "ini", ".conf": "ini", ".cfg": "ini",
    ".sh": "shell", ".bash": "shell", ".ps1": "shell", ".bat": "shell",
    ".sql": "sql", ".xml": "xml", ".properties": "ini",
}

# 无扩展名但需要扫描的文件
SPECIAL_FILES = {".env", ".env.local", ".env.production", ".env.example",
                 "dockerfile", "docker-compose.yml", "docker-compose.yaml",
                 ".mcp.json", "mcp.json", "settings.json", ".npmrc", ".pypirc"}

SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv", "venv",
    "env", "dist", "build", "target", "out", ".next", ".nuxt", "vendor",
    ".idea", ".vscode", ".pytest_cache", ".mypy_cache", ".tox", "site-packages",
    "coverage", ".cache", "bower_components", "Pods", ".gradle", ".terraform",
}

SKIP_FILE_SUFFIX = (
    ".min.js", ".min.css", ".map", ".lock", ".pyc", ".pyo", ".so", ".dll",
    ".exe", ".jar", ".war", ".class", ".o", ".a", ".zip", ".tar", ".gz",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".bmp",
    ".mp3", ".mp4", ".mov", ".avi", ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore",
)

MAX_FILE_BYTES = 2 * 1024 * 1024
SNIPPET_MAX_LEN = 200

# 前端目录启发：.js/.ts 既可能是浏览器代码也可能是服务端代码，
# 而「密钥泄露到前端」这类规则只对真正的前端文件成立。
# 命中这些目录片段的 js/ts 会被重新标记为伪语言 frontend。
FRONTEND_DIR_HINTS = (
    "web/", "static/", "public/", "frontend/", "assets/", "client/",
    "ui/", "views/", "pages/", "components/", "src/web/",
)

# 注释行判定（用于降噪；critical/high 不受影响）
COMMENT_PREFIXES = ("#", "//", "*", "/*", "<!--", "-- ", ";", "%", "'")

SECRETISH_RULES = {
    "SEC101", "SEC102", "SEC103", "SEC104", "SEC105", "SEC106", "SEC107",
    "SEC108", "SEC109", "SEC110", "SEC111", "SEC112", "SEC901", "SEC905",
}

# ------------------------------------------------------------ 轻量污点追踪
# 规则 pattern 里出现 {{TAINT}} 时，引擎把它展开为「外部输入来源」联合模式，
# 并把本文件中「从 request / req / params 取值后赋给普通变量」的变量名一并纳入。
# 效果：从纯关键词匹配升级为单文件内的数据流追踪，
#       能抓到 `url = request.args.get("url")` → `requests.get(url)` 这类跨行传递，
#       同时不误报普通的 `requests.get(API_BASE)`。

TAINT_SOURCES = re.compile(
    r"(?i)\b([A-Za-z_]\w{1,})\s*=\s*[^=\n]{0,80}?"
    r"(request\.(args|form|json|values|data|get_json|files)"
    r"|req\.(query|body|params|headers|cookies)"
    r"|params\[|getParameter|ctx\.(query|params)"
    r"|process\.argv|\$_(GET|POST|REQUEST|COOKIE))"
)

# 注意：这里只写裸 alternation，外层括号由 _compile_for 统一补上。
# 漏掉外层括号会让每个污点变量变成顶级分支，从而独立匹配任意位置的同名变量，
# 造成严重过报（已踩过这个坑）。
TAINT_INLINE = ("req\\.|request\\.|params\\.|query\\.|args\\.|getParameter"
                "|body\\.|form\\.")

TAINT_STOPWORDS = {
    "request", "response", "self", "config", "params", "req", "res",
    "data", "body", "query", "cls", "ctx", "args", "kwargs",
}

_TAINT_CACHE: dict = {}
_TAINT_CACHE_MAX = 512


def _compile_for(rule: dict, tainted: set):
    """按当前文件的污点变量集合，为该规则产出（带缓存的）编译结果。"""
    pattern = rule["pattern"]
    if "{{TAINT}}" not in pattern:
        return rule["_re"]

    key = (rule["id"], tuple(sorted(tainted)))
    rx = _TAINT_CACHE.get(key)
    if rx is None:
        extra = "".join(rf"|\b{re.escape(t)}\b" for t in sorted(tainted))
        rx = re.compile(
            pattern.replace("{{TAINT}}", f"({TAINT_INLINE}{extra})"),
            re.MULTILINE,
        )
        if len(_TAINT_CACHE) < _TAINT_CACHE_MAX:
            _TAINT_CACHE[key] = rx
    return rx


def find_tainted(text: str) -> set:
    return {m.group(1) for m in TAINT_SOURCES.finditer(text)} - TAINT_STOPWORDS



# ---------------------------------------------------------------- 数据结构

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    cwe: str
    file: str
    line: int
    code: str
    context: list = field(default_factory=list)
    fix: str = ""
    verify: str = ""
    tags: list = field(default_factory=list)
    lang: str = ""

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABEL.get(self.severity, self.severity)

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass
class AuditResult:
    target: str
    title: str = "代码安全体检报告"
    started_at: str = ""
    duration_ms: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    lines_scanned: int = 0
    findings: list = field(default_factory=list)
    suppressed: int = 0
    rule_version: str = ""
    rules_total: int = 0
    scan_root: str = ""

    # -------- 派生统计
    @property
    def score(self) -> int:
        penalty = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        s = self.score
        for threshold, g in ((90, "A"), (80, "B"), (65, "C"), (45, "D")):
            if s >= threshold:
                return g
        return "F"

    @property
    def by_severity(self) -> dict:
        out = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    @property
    def by_category(self) -> dict:
        out: dict = {}
        for f in self.findings:
            key = f.tags[0] if f.tags else "other"
            out[key] = out.get(key, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    @property
    def top_files(self) -> list:
        counter: dict = {}
        for f in self.findings:
            w = SEVERITY_WEIGHT.get(f.severity, 0)
            counter[f.file] = counter.get(f.file, 0) + w
        return sorted(counter.items(), key=lambda kv: -kv[1])[:10]

    def sorted_findings(self) -> list:
        return sorted(self.findings,
                      key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line))

    def to_dict(self) -> dict:
        d = asdict(self)
        d.update({
            "score": self.score,
            "grade": self.grade,
            "by_severity": self.by_severity,
            "by_category": self.by_category,
            "top_files": self.top_files,
            "findings": [asdict(f) for f in self.sorted_findings()],
        })
        return d


# ---------------------------------------------------------------- 工具函数

def load_rules(path: str | os.PathLike | None = None) -> tuple:
    """返回 (rules, deny_patterns, version)。"""
    p = Path(path) if path else DEFAULT_RULES
    data = json.loads(p.read_text(encoding="utf-8"))
    rules = []
    for r in data.get("rules", []):
        try:
            r["_re"] = re.compile(r["pattern"], re.MULTILINE)
        except re.error as exc:  # 规则写错不该让整个扫描崩掉
            print(f"[warn] 规则 {r.get('id')} 正则无效，已跳过: {exc}")
            continue
        rules.append(r)
    denies = [re.compile(p, re.I) for p in data.get("deny_patterns", [])]
    return rules, denies, data.get("version", "unknown")


def read_text(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except (OSError, PermissionError):
        return None
    if b"\x00" in raw[:4096]:          # 二进制
        return None
    for enc in ("utf-8", "utf-8-sig", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def detect_lang(path: Path) -> str | None:
    name = path.name.lower()
    if name in SPECIAL_FILES:
        if name.startswith(".env"):
            return "env"
        return EXT_LANG.get(path.suffix.lower(), "json" if name.endswith(".json") else "yaml")
    return EXT_LANG.get(path.suffix.lower())


def iter_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            p = Path(dirpath) / fn
            if fn.lower().endswith(SKIP_FILE_SUFFIX):
                continue
            yield p


def mask_secret(text: str) -> str:
    """把命中的密钥本体部分打码，报告即便外发也不至于二次泄露。"""
    def _mask(m: re.Match) -> str:
        s = m.group(0)
        if len(s) <= 8:
            return s
        keep = max(2, len(s) // 5)
        return s[:keep] + "*" * (len(s) - keep * 2) + s[-keep:]

    patterns = [
        r"AKIA[0-9A-Z]{16}", r"LTAI[0-9A-Za-z]{12,}", r"AKID[A-Za-z0-9]{13,}",
        r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", r"xox[baprs]-[0-9A-Za-z\-]{10,}",
        r"AIza[0-9A-Za-z_\-]{35}", r"\bsk-(proj-)?[A-Za-z0-9_\-]{16,}\b",
        r"\bsk-ant-[A-Za-z0-9_\-]{16,}\b",
        r"[A-Za-z0-9+/]{40}(?=[\"'])",
        r"(?<=:)[^@/\s\"']{6,}(?=@)",
    ]
    for pat in patterns:
        text = re.sub(pat, _mask, text)
    return text


def is_comment_line(line: str) -> bool:
    s = line.strip()
    return s.startswith(COMMENT_PREFIXES)


def snippet_of(lines: list, idx: int, radius: int = 1) -> list:
    lo = max(0, idx - radius)
    hi = min(len(lines), idx + radius + 1)
    return [lines[i].rstrip("\n")[:SNIPPET_MAX_LEN] for i in range(lo, hi)]


# ---------------------------------------------------------------- 核心扫描

def scan_file(path: Path, rel: str, rules: list, denies: list,
              lang: str, include_comments: bool) -> tuple:
    """返回 (findings, suppressed_count, line_count, size)。"""
    text = read_text(path)
    if text is None:
        return [], 0, 0, 0

    lines = text.splitlines()
    findings, suppressed = [], 0
    tainted = find_tainted(text)

    for rule in rules:
        langs = rule.get("langs", ["*"])
        if "*" not in langs and lang not in langs:
            continue

        for m in _compile_for(rule, tainted).finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            raw_line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
            matched = m.group(0)

            # --- 降噪 1：明显的占位符 / 环境变量引用
            if any(d.search(raw_line) for d in denies):
                suppressed += 1
                continue

            # --- 降噪 2：注释里的中低危（critical/high 保留，注释里也可能真泄露）
            if (not include_comments and rule["severity"] in ("medium", "low")
                    and is_comment_line(raw_line)):
                suppressed += 1
                continue

            code = matched.strip()[:SNIPPET_MAX_LEN]
            if rule["id"] in SECRETISH_RULES:
                code = mask_secret(code)
                ctx = [mask_secret(l[:SNIPPET_MAX_LEN]) for l in snippet_of(lines, line_no - 1)]
            else:
                ctx = snippet_of(lines, line_no - 1)

            findings.append(Finding(
                rule_id=rule["id"],
                title=rule["title"],
                severity=rule["severity"],
                cwe=rule.get("cwe", ""),
                file=rel,
                line=line_no,
                code=code,
                context=ctx,
                fix=rule.get("fix", ""),
                verify=rule.get("verify", ""),
                tags=rule.get("tags", []),
                lang=lang,
            ))

    # 同文件同行同规则去重
    seen, uniq = set(), []
    for f in findings:
        key = (f.rule_id, f.line)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)

    return uniq, suppressed, len(lines), len(text.encode("utf-8", errors="ignore"))


def scan(target: str, rules_path: str | None = None, title: str = "代码安全体检报告",
         include_comments: bool = False, min_severity: str | None = None) -> AuditResult:
    rules, denies, version = load_rules(rules_path)
    root = Path(target).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"扫描目标不存在: {root}")

    result = AuditResult(
        target=str(root),
        title=title,
        started_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        rule_version=version,
        rules_total=len(rules),
        scan_root=str(root),
    )

    t0 = time.perf_counter()
    targets = [root] if root.is_file() else list(iter_files(root))

    for p in targets:
        rel = p.name if root.is_file() else str(p.relative_to(root)).replace("\\", "/")
        lang = detect_lang(p)
        if lang is None:
            result.files_skipped += 1
            continue
        if lang in ("js", "ts") and any(h in rel.lower() for h in FRONTEND_DIR_HINTS):
            lang = "frontend"
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                result.files_skipped += 1
                continue
        except OSError:
            result.files_skipped += 1
            continue

        found, supp, nlines, nbytes = scan_file(p, rel, rules, denies, lang, include_comments)
        if nlines == 0 and not found:
            result.files_skipped += 1
            continue
        result.files_scanned += 1
        result.lines_scanned += nlines
        result.bytes_scanned += nbytes
        result.suppressed += supp
        result.findings.extend(found)

    if min_severity:
        cutoff = SEVERITY_ORDER.get(min_severity, 9)
        result.findings = [f for f in result.findings
                           if SEVERITY_ORDER.get(f.severity, 9) <= cutoff]

    result.duration_ms = int((time.perf_counter() - t0) * 1000)
    return result


def scan_paths_for_demo() -> Path:
    return Path(__file__).resolve().parent.parent / "samples" / "vuln_demo"
