# -*- coding: utf-8 -*-
"""报告生成：客户可直接阅读的中文 HTML / Markdown 报告。

交付物设计的两个关键点：
  1. HTML 报告自包含（单文件、内联 CSS、零外链）——客户不需要装任何东西，直接双击打开；
  2. 每条问题都带「修复建议」和「验证方法」——这是把扫描器变成服务的地方。
"""
from __future__ import annotations

import html
import json
from pathlib import Path

from .engine import SEVERITY_LABEL, SEVERITY_ORDER, AuditResult, Finding

SEV_COLOR = {
    "critical": "#b3261e",
    "high": "#e8710a",
    "medium": "#c99700",
    "low": "#3b7dd8",
}
SEV_BG = {
    "critical": "#fdeceb",
    "high": "#fef3e8",
    "medium": "#fdf8e6",
    "low": "#eaf2fc",
}


def executive_summary(r: AuditResult) -> str:
    sev = r.by_severity
    crit, high = sev.get("critical", 0), sev.get("high", 0)
    total = len(r.findings)

    if crit:
        head = (f"本次体检在 {r.files_scanned} 个文件中发现 <b>{total}</b> 处安全问题，"
                f"其中 <b>{crit} 处严重问题</b>需要立即处理。"
                f"严重问题通常意味着攻击者可以直接获取系统权限、窃取数据或执行任意代码，"
                f"建议在 24 小时内完成修复并复测。")
    elif high:
        head = (f"本次体检在 {r.files_scanned} 个文件中发现 <b>{total}</b> 处安全问题，"
                f"其中 <b>{high} 处高危问题</b>建议优先修复。"
                f"高危问题在特定条件下可被利用，建议在两周内完成整改。")
    elif total:
        head = (f"本次体检在 {r.files_scanned} 个文件中发现 <b>{total}</b> 处问题，"
                f"以中低危为主，暂无直接可利用的严重缺陷。建议按计划在版本迭代中逐步收敛。")
    else:
        head = (f"本次体检覆盖 {r.files_scanned} 个文件，"
                f"<b>未发现规则库覆盖范围内的安全问题</b>。"
                f"这说明代码在常见缺陷模式上是干净的，但不代表系统绝对安全——"
                f"业务逻辑漏洞、权限设计缺陷需要人工审计才能发现。")

    cats = r.by_category
    cat_txt = ""
    if cats:
        name_map = {
            "credential": "密钥与凭据泄露", "injection": "注入类缺陷",
            "deserialization": "不安全反序列化", "crypto": "密码学实现问题",
            "ai": "AI / 大模型特有风险", "xss": "前端跨站脚本",
            "ssrf": "服务端请求伪造", "config": "配置与部署缺陷",
            "filesystem": "文件与路径处理", "info-leak": "信息泄露",
            "network": "网络与传输安全", "auth": "认证与授权",
            "dependency": "依赖与供应链", "agent": "Agent 权限",
            "mcp": "MCP 配置", "sql": "SQL 注入", "rce": "远程代码执行",
            "upload": "文件上传", "csrf": "CSRF", "prompt-injection": "提示注入",
            "frontend": "前端实现", "database": "数据库", "path-traversal": "路径穿越",
            "cloud": "云凭据", "high-risk": "高风险项",
        }
        top = list(cats.items())[:3]
        cat_txt = "问题集中在：" + "、".join(
            f"{name_map.get(k, k)}（{v} 处）" for k, v in top) + "。"

    return head + (" " + cat_txt if cat_txt else "")


# ------------------------------------------------------------------ HTML

_HTML_HEAD = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
  :root{{
    --crit:#b3261e; --high:#e8710a; --med:#c99700; --low:#3b7dd8;
    --ink:#1c1e21; --muted:#5f6368; --line:#e3e6ea; --bg:#f6f7f9;
  }}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--bg);color:var(--ink);
    font:15px/1.7 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}}
  .wrap{{max-width:960px;margin:0 auto;padding:32px 20px 80px}}
  header{{background:linear-gradient(135deg,#141b2d,#25324f);color:#fff;
    border-radius:14px;padding:34px 32px;margin-bottom:24px}}
  header h1{{margin:0 0 6px;font-size:26px;letter-spacing:.5px}}
  header .meta{{opacity:.72;font-size:13px;line-height:1.9}}
  .score-row{{display:flex;align-items:center;gap:28px;flex-wrap:wrap;margin-top:22px}}
  .ring{{position:relative;width:132px;height:132px;flex:none}}
  .ring svg{{transform:rotate(-90deg)}}
  .ring .val{{position:absolute;inset:0;display:flex;flex-direction:column;
    align-items:center;justify-content:center}}
  .ring .val b{{font-size:32px;line-height:1}}
  .ring .val span{{font-size:12px;opacity:.7;margin-top:4px}}
  .sev-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;flex:1;min-width:300px}}
  .sev-cell{{background:rgba(255,255,255,.08);border-radius:10px;padding:12px 14px}}
  .sev-cell b{{display:block;font-size:24px;line-height:1.2}}
  .sev-cell span{{font-size:12px;opacity:.72}}
  section{{background:#fff;border:1px solid var(--line);border-radius:12px;
    padding:24px 26px;margin-bottom:18px}}
  h2{{font-size:19px;margin:0 0 16px;padding-left:11px;border-left:4px solid #25324f}}
  h3{{font-size:16px;margin:26px 0 8px}}
  p{{margin:0 0 12px}}
  .badge{{display:inline-block;padding:2px 10px;border-radius:20px;
    font-size:12px;font-weight:600;color:#fff}}
  .finding{{border:1px solid var(--line);border-left-width:4px;border-radius:9px;
    padding:16px 18px;margin-bottom:14px;background:#fff}}
  .finding .fhead{{display:flex;justify-content:space-between;gap:12px;
    align-items:baseline;flex-wrap:wrap}}
  .finding .ftitle{{font-weight:600;font-size:15px}}
  .finding .fmeta{{font-size:12px;color:var(--muted);font-family:Consolas,monospace}}
  pre{{background:#f4f6f8;border:1px solid var(--line);border-radius:7px;
    padding:11px 13px;overflow:auto;font:12.5px/1.6 Consolas,"Courier New",monospace;
    margin:10px 0}}
  .fix{{background:#f0f7f0;border-left:3px solid #3f8f4a;border-radius:6px;
    padding:10px 13px;margin-top:10px;font-size:14px}}
  .verify{{background:#eef4fd;border-left:3px solid #3b7dd8;border-radius:6px;
    padding:10px 13px;margin-top:8px;font-size:14px}}
  .fix b,.verify b{{font-size:12px;letter-spacing:.5px}}
  table{{width:100%;border-collapse:collapse;font-size:14px}}
  th,td{{padding:9px 11px;border-bottom:1px solid var(--line);text-align:left;
    vertical-align:top}}
  th{{background:#f6f7f9;font-weight:600;font-size:13px;color:var(--muted)}}
  td.loc{{font-family:Consolas,monospace;font-size:12.5px;white-space:nowrap}}
  .bar{{height:9px;border-radius:5px;background:#eef0f3;overflow:hidden;margin-top:3px}}
  .bar i{{display:block;height:100%}}
  footer{{text-align:center;color:var(--muted);font-size:12.5px;padding-top:14px}}
  .kpi{{display:flex;gap:22px;flex-wrap:wrap;font-size:13px;color:var(--muted)}}
  .kpi b{{color:var(--ink)}}
</style>
</head>
<body><div class="wrap">
"""


def _ring(score: int, grade: str) -> str:
    r = 56
    circ = 2 * 3.14159 * r
    dash = circ * score / 100
    color = "#3f8f4a" if score >= 80 else ("#c99700" if score >= 60 else "#b3261e")
    return f"""<div class="ring">
  <svg width="132" height="132">
    <circle cx="66" cy="66" r="{r}" fill="none" stroke="rgba(255,255,255,.15)" stroke-width="11"/>
    <circle cx="66" cy="66" r="{r}" fill="none" stroke="{color}" stroke-width="11"
      stroke-linecap="round" stroke-dasharray="{dash:.1f} {circ:.1f}"/>
  </svg>
  <div class="val"><b>{score}</b><span>评级 {grade}</span></div>
</div>"""


def _finding_html(f: Finding) -> str:
    color = SEV_COLOR.get(f.severity, "#666")
    ctx = "\n".join(f.context) if f.context else f.code
    verify = (f'<div class="verify"><b>如何验证 ›</b><br>{html.escape(f.verify)}</div>'
              if f.verify else "")
    cwe = f'<span class="fmeta">{html.escape(f.cwe)}</span>' if f.cwe else ""
    return f"""<div class="finding" style="border-left-color:{color};
    background:{SEV_BG.get(f.severity,'#fff')}">
  <div class="fhead">
    <div class="ftitle">
      <span class="badge" style="background:{color}">{f.severity_label}</span>
      &nbsp;{html.escape(f.title)}
    </div>
    <div class="fmeta">{html.escape(f.file)}:{f.line} &nbsp;│&nbsp; {html.escape(f.rule_id)} &nbsp;│&nbsp; {cwe}</div>
  </div>
  <pre>{html.escape(ctx)}</pre>
  <div class="fix"><b>修复建议 ›</b><br>{html.escape(f.fix)}</div>
  {verify}
</div>"""


def render_html(r: AuditResult) -> str:
    sev = r.by_severity
    total = len(r.findings)
    crit_high = [f for f in r.sorted_findings() if f.severity in ("critical", "high")]
    mid_low = [f for f in r.sorted_findings() if f.severity in ("medium", "low")]

    cells = "".join(
        f'<div class="sev-cell"><b style="color:{SEV_COLOR[k]}">{sev.get(k,0)}</b>'
        f'<span>{SEVERITY_LABEL[k]}</span></div>'
        for k in ("critical", "high", "medium", "low"))

    parts = [_HTML_HEAD.format(title=html.escape(r.title))]
    parts.append(f"""<header>
  <h1>{html.escape(r.title)}</h1>
  <div class="meta">
    扫描目标：{html.escape(r.scan_root)}<br>
    扫描时间：{html.escape(r.started_at)}　│　耗时 {r.duration_ms/1000:.2f} 秒<br>
    规则库 v{html.escape(r.rule_version)}（{r.rules_total} 条规则）
  </div>
  <div class="score-row">
    {_ring(r.score, r.grade)}
    <div class="sev-grid">{cells}</div>
  </div>
</header>""")

    parts.append(f"""<section>
  <h2>一、执行摘要</h2>
  <p>{executive_summary(r)}</p>
  <div class="kpi">
    <span>扫描文件 <b>{r.files_scanned}</b></span>
    <span>代码行 <b>{r.lines_scanned:,}</b></span>
    <span>跳过文件 <b>{r.files_skipped}</b></span>
    <span>降噪过滤 <b>{r.suppressed}</b> 处误报</span>
    <span>问题总数 <b>{total}</b></span>
  </div>
</section>""")

    if crit_high:
        items = "".join(_finding_html(f) for f in crit_high)
        parts.append(f"""<section>
  <h2>二、需优先处理的问题（{len(crit_high)} 项）</h2>
  <p>以下问题具备明确的利用路径或已构成信息泄露，建议按顺序处理。
     每一项都给出了修复建议；标注「如何验证」的项可通过括号内的操作确认修复是否生效。</p>
  {items}
</section>""")
        idx = 3
    else:
        idx = 2

    if mid_low:
        rows = "".join(
            f'<tr><td><span class="badge" style="background:{SEV_COLOR[f.severity]}">'
            f'{f.severity_label}</span></td>'
            f'<td>{html.escape(f.title)}</td>'
            f'<td class="loc">{html.escape(f.file)}:{f.line}</td>'
            f'<td>{html.escape(f.cwe)}</td></tr>'
            for f in mid_low)
        parts.append(f"""<section>
  <h2>{'三' if idx==3 else '二'}、建议排期修复的问题（{len(mid_low)} 项）</h2>
  <table><thead><tr><th>等级</th><th>问题</th><th>位置</th><th>标准</th></tr></thead>
  <tbody>{rows}</tbody></table>
</section>""")
        idx += 1

    cn = {1: "一", 2: "二", 3: "三", 4: "四", 5: "五", 6: "六", 7: "七"}
    if r.top_files:
        maxw = max(w for _, w in r.top_files) or 1
        rows = "".join(
            f'<tr><td class="loc">{html.escape(fp)}</td><td style="width:130px">'
            f'<div class="bar"><i style="width:{w*100//maxw}%;background:#e8710a"></i></div></td>'
            f'<td style="width:70px">{w} 分</td></tr>'
            for fp, w in r.top_files)
        parts.append(f"""<section>
  <h2>{cn.get(idx,'')}、问题集中的文件</h2>
  <table><thead><tr><th>文件</th><th>风险占比</th><th>风险分</th></tr></thead>
  <tbody>{rows}</tbody></table>
</section>""")
        idx += 1

    cats = r.by_category
    if cats:
        rows = "".join(f"<tr><td>{html.escape(k)}</td><td>{v}</td></tr>"
                       for k, v in cats.items())
        parts.append(f"""<section>
  <h2>{cn.get(idx,'')}、问题类型分布</h2>
  <table><thead><tr><th>类型</th><th>数量</th></tr></thead><tbody>{rows}</tbody></table>
</section>""")
        idx += 1

    parts.append(f"""<section>
  <h2>{cn.get(idx,'')}、体检方法与范围</h2>
  <p><b>扫描范围</b>：{html.escape(r.scan_root)}，共 {r.files_scanned} 个源文件、
     {r.lines_scanned:,} 行代码，耗时 {r.duration_ms/1000:.2f} 秒。</p>
  <p><b>检测方式</b>：基于 {r.rules_total} 条规则库进行模式匹配与数据流启发式分析，
     覆盖 OWASP Top 10 常见缺陷、密钥与凭据泄露、不安全反序列化、密码学误用、
     以及大模型应用特有风险（Prompt 注入面、模型输出执行、Agent 工具越权、MCP 配置泄露）。</p>
  <p><b>报告说明</b>：{r.suppressed} 处疑似命中经占位符/环境变量引用识别后判定为误报并已过滤。
     被识别为密钥的内容在报告中已做打码处理，报告可安全外发。</p>
  <p><b>边界声明</b>：自动化检测无法覆盖业务逻辑漏洞、权限设计缺陷、并发与状态竞态类问题，
     这类问题需要人工审计与渗透测试。本报告不构成对系统安全性的完整保证。</p>
</section>""")

    parts.append("""<footer>CodeAudit 代码安全体检报告 · 自动化生成</footer>
</div></body></html>""")
    return "".join(parts)


# ---------------------------------------------------------------- Markdown

def render_markdown(r: AuditResult) -> str:
    sev = r.by_severity
    lines = [
        f"# {r.title}", "",
        f"- **扫描目标**：`{r.scan_root}`",
        f"- **扫描时间**：{r.started_at}（耗时 {r.duration_ms/1000:.2f} 秒）",
        f"- **安全评分**：**{r.score} / 100（评级 {r.grade}）**",
        f"- **问题统计**：严重 {sev.get('critical',0)} · 高危 {sev.get('high',0)}"
        f" · 中危 {sev.get('medium',0)} · 低危 {sev.get('low',0)}",
        f"- **扫描规模**：{r.files_scanned} 个文件 / {r.lines_scanned:,} 行代码"
        f"（降噪过滤 {r.suppressed} 处）",
        "", "---", "", "## 一、执行摘要", "",
        executive_summary(r).replace("<b>", "**").replace("</b>", "**"), "",
    ]

    crit_high = [f for f in r.sorted_findings() if f.severity in ("critical", "high")]
    if crit_high:
        lines += ["## 二、需优先处理的问题", ""]
        for i, f in enumerate(crit_high, 1):
            lines += [
                f"### {i}. [{f.severity_label}] {f.title}", "",
                f"- **位置**：`{f.file}:{f.line}`",
                f"- **规则**：{f.rule_id}　**标准**：{f.cwe}",
                "", "```", (("\n".join(f.context)) if f.context else f.code).strip(), "```", "",
                f"**修复建议**：{f.fix}", "",
            ]
            if f.verify:
                lines += [f"**如何验证**：{f.verify}", ""]

    mid_low = [f for f in r.sorted_findings() if f.severity in ("medium", "low")]
    if mid_low:
        lines += ["## 三、建议排期修复的问题", "",
                  "| 等级 | 问题 | 位置 | 标准 |", "|---|---|---|---|"]
        lines += [f"| {f.severity_label} | {f.title} | `{f.file}:{f.line}` | {f.cwe} |"
                  for f in mid_low]
        lines += [""]

    if r.top_files:
        lines += ["## 四、问题集中的文件", "", "| 文件 | 风险分 |", "|---|---|"]
        lines += [f"| `{fp}` | {w} |" for fp, w in r.top_files]
        lines += [""]

    lines += [
        "---", "",
        "## 体检说明", "",
        f"基于 {r.rules_total} 条规则库（v{r.rule_version}）进行模式匹配与启发式分析，"
        "覆盖 OWASP Top 10 常见缺陷、密钥泄露、不安全反序列化、密码学误用，"
        "以及大模型应用特有风险。自动化检测不覆盖业务逻辑漏洞与权限设计缺陷，"
        "本报告不构成对系统安全性的完整保证。",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------- 落盘

def write_reports(r: AuditResult, outdir: str | Path, formats=("html", "md", "json"),
                  stem: str | None = None) -> dict:
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    ts = r.started_at.replace("-", "").replace(":", "").replace(" ", "-")
    stem = stem or f"codeaudit-{ts}"

    written = {}
    if "html" in formats:
        p = out / f"{stem}.html"
        p.write_text(render_html(r), encoding="utf-8")
        written["html"] = str(p)
    if "md" in formats:
        p = out / f"{stem}.md"
        p.write_text(render_markdown(r), encoding="utf-8")
        written["md"] = str(p)
    if "json" in formats:
        p = out / f"{stem}.json"
        p.write_text(json.dumps(r.to_dict(), ensure_ascii=False, indent=2),
                     encoding="utf-8")
        written["json"] = str(p)
    return written
