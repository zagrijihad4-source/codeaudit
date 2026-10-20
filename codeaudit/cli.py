# -*- coding: utf-8 -*-
"""CodeAudit 命令行入口。

用法：
    python -m codeaudit scan <目录或文件> [-o reports] [--title "某某科技"]
    python -m codeaudit rules
    python -m codeaudit demo
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import SEVERITY_LABEL, SEVERITY_ORDER, load_rules, scan
from .report import write_reports

BAR_CHARS = {"critical": "█", "high": "▓", "medium": "▒", "low": "░"}


def _init_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def print_summary(r, max_items: int = 8) -> None:
    sev = r.by_severity
    print()
    print("=" * 62)
    print(f"  {r.title}")
    print("=" * 62)
    print(f"  目标      : {r.scan_root}")
    print(f"  规模      : {r.files_scanned} 文件 / {r.lines_scanned:,} 行"
          f"（跳过 {r.files_skipped}，降噪过滤 {r.suppressed} 处）")
    print(f"  耗时      : {r.duration_ms/1000:.2f} 秒    规则库 v{r.rule_version}"
          f"（{r.rules_total} 条）")
    print(f"  安全评分  : {r.score}/100  评级 {r.grade}")
    print("-" * 62)
    print(f"  严重 {sev.get('critical',0):<4} 高危 {sev.get('high',0):<4}"
          f" 中危 {sev.get('medium',0):<4} 低危 {sev.get('low',0):<4}")
    print("-" * 62)

    findings = r.sorted_findings()
    shown = [f for f in findings if f.severity in ("critical", "high")][:max_items]
    if not shown:
        shown = findings[:max_items]

    if shown:
        print("  重点发现：")
        for f in shown:
            bar = BAR_CHARS.get(f.severity, "·")
            print(f"   {bar} [{f.severity_label}] {f.title}")
            print(f"      {f.file}:{f.line}   {f.rule_id} {f.cwe}")
    rest = len(findings) - len(shown)
    if rest > 0:
        print(f"   … 其余 {rest} 处见报告")
    print("=" * 62)


def cmd_scan(args) -> int:
    min_sev = None
    if args.min_severity:
        min_sev = args.min_severity.lower()
        if min_sev not in SEVERITY_ORDER:
            print(f"无效的 --min-severity: {args.min_severity}", file=sys.stderr)
            return 2

    try:
        result = scan(args.target, rules_path=args.rules, title=args.title,
                      include_comments=args.include_comments, min_severity=min_sev)
    except FileNotFoundError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2

    print_summary(result)
    formats = tuple(f.strip() for f in args.format.split(",") if f.strip())
    written = write_reports(result, args.out, formats=formats, stem=args.name)
    print("  报告已生成：")
    for kind, path in written.items():
        print(f"   · {kind:4} → {path}")
    print()

    if args.fail_on:
        cutoff = SEVERITY_ORDER.get(args.fail_on.lower(), 9)
        if any(SEVERITY_ORDER.get(f.severity, 9) <= cutoff for f in result.findings):
            return 1
    return 0


def cmd_rules(args) -> int:
    rules, _, version = load_rules(args.rules)
    print(f"规则库 v{version}，共 {len(rules)} 条：\n")
    print(f"{'ID':<8}{'等级':<6}{'标准':<12}标题")
    print("-" * 76)
    for r in sorted(rules, key=lambda x: x["id"]):
        sev = SEVERITY_LABEL.get(r["severity"], r["severity"])
        print(f"{r['id']:<8}{sev:<6}{r.get('cwe',''):<12}{r['title']}")
    return 0


def cmd_demo(args) -> int:
    from .engine import scan_paths_for_demo
    demo = scan_paths_for_demo()
    if not demo.exists():
        print(f"演示样本不存在：{demo}", file=sys.stderr)
        return 2
    args.target = str(demo)
    args.title = args.title or "演示项目 · 代码安全体检报告"
    return cmd_scan(args)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="codeaudit",
        description="CodeAudit —— AI 辅助代码安全体检引擎（零依赖）",
    )
    sub = p.add_subparsers(dest="command")

    def add_scan_args(sp, target_required=True):
        if target_required:
            sp.add_argument("target", help="扫描目标目录或单个文件")
        else:
            sp.add_argument("target", nargs="?",
                            help="扫描目标目录或单个文件（demo 可省略）")
        sp.add_argument("-o", "--out", default="reports", help="报告输出目录（默认 reports）")
        sp.add_argument("--title", default="代码安全体检报告", help="报告标题，通常填客户名")
        sp.add_argument("--name", default=None, help="报告文件名主干（默认按时间戳）")
        sp.add_argument("-f", "--format", default="html,md,json",
                        help="输出格式，逗号分隔：html,md,json")
        sp.add_argument("--min-severity", default=None,
                        help="只保留不低于该等级的问题：critical/high/medium/low")
        sp.add_argument("--include-comments", action="store_true",
                        help="不过滤注释中的中低危命中（默认过滤以降低噪声）")
        sp.add_argument("--rules", default=None, help="自定义规则库路径")
        sp.add_argument("--fail-on", default=None,
                        help="存在不低于该等级的问题时返回退出码 1（可接 CI）")

    sp = sub.add_parser("scan", help="扫描代码并生成体检报告")
    add_scan_args(sp)

    sp = sub.add_parser("demo", help="扫描内置演示样本，快速预览报告效果")
    add_scan_args(sp, target_required=False)

    sp = sub.add_parser("rules", help="列出规则库内容")
    sp.add_argument("--rules", default=None)

    return p


def main(argv=None) -> int:
    _init_console()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "demo":
        return cmd_demo(args)
    if args.command == "rules":
        return cmd_rules(args)
    parser.print_help()
    return 0
