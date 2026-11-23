"""Command line interface.

    aegis scan [PATH]      find vulnerabilities (text / json / sarif / markdown / html)
    aegis fix  [PATH]      apply verified patches (rules, then Claude with --ai)
    aegis baseline [PATH]  record current findings so CI only fails on new ones
    aegis demo             run the self-healing demo and write an HTML report
    aegis lab              run VulnShop on localhost and watch it heal itself live
    aegis range            real vulnerable apps (VulnShop, DSVW, vulpy) behind one Aegis Gateway
    aegis gateway -c FILE  protect any HTTP apps from one server (config in TOML)
    aegis rules            list detection rules
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .config import TEST_FILES, filter_baseline, load_config, write_baseline
from .models import SEVERITY_ORDER
from .scanner.engine import iter_python_files, scan_path, sort_by_severity
from .scanner.rules import RULES

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _ai_client(required: bool):
    from .ai import ClaudeClient

    client = ClaudeClient()
    if not client.available:
        if required:
            print("aegis: --ai needs the ANTHROPIC_API_KEY environment variable.", file=sys.stderr)
            sys.exit(EXIT_ERROR)
        return None
    return client


def _write(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
        print(f"aegis: wrote {output}", file=sys.stderr)
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


def cmd_scan(args) -> int:
    root = args.path
    cfg = load_config(root)
    errors: list[str] = []
    findings = scan_path(root, exclude=cfg.exclude + (args.exclude or []),
                         disabled=cfg.disable | {r.upper() for r in (args.disable or [])}, errors=errors)
    baseline = args.baseline or cfg.baseline
    suppressed = 0
    if baseline and Path(baseline).exists():
        findings, suppressed = filter_baseline(findings, baseline, root if Path(root).is_dir() else ".")
    findings = sort_by_severity(findings)
    if args.ai_triage:
        from .ai import triage

        client = _ai_client(required=True)
        triage(findings, client, args.lang or cfg.language)

    base = root if Path(root).is_dir() else str(Path(root).parent)
    fmt = args.format
    if fmt == "text":
        from .output import render_text
        text = render_text(findings, base)
        if suppressed:
            text += f"\n({suppressed} known finding(s) hidden by baseline)"
    elif fmt == "json":
        from .output import render_json
        text = render_json(findings, base, {"suppressed_by_baseline": suppressed, "errors": errors})
    elif fmt == "sarif":
        from .output import render_sarif
        text = render_sarif(findings, base)
    elif fmt == "markdown":
        from .output import render_markdown
        text = render_markdown(findings, base)
    else:
        from .report_html import render_scan_report
        text = render_scan_report(findings, base, lang=args.lang or cfg.language)
    _write(text, args.output)
    for err in errors:
        print(f"aegis: skipped {err}", file=sys.stderr)

    fail_on = args.fail_on or cfg.fail_on
    if fail_on == "never":
        return EXIT_OK
    limit = SEVERITY_ORDER.get(fail_on, 1)
    return EXIT_FINDINGS if any(SEVERITY_ORDER.get(f.severity, 9) <= limit for f in findings) else EXIT_OK


def cmd_fix(args) -> int:
    from .patcher.engine import fix_file

    cfg = load_config(args.path)
    ai_fixer = None
    if args.ai:
        from .ai import AIFixer
        ai_fixer = AIFixer(_ai_client(required=True), max_attempts=args.ai_attempts)
    only = {r.strip().upper() for r in args.only.split(",")} if args.only else None
    select = (lambda f: f.rule_id in only) if only else (lambda f: f.rule_id not in cfg.disable)

    exclude = cfg.exclude + ([] if (cfg.fix_tests or args.include_tests) else TEST_FILES)
    all_patches, all_escalations, diffs = [], [], []
    for file in iter_python_files(args.path, exclude):
        try:
            report = fix_file(str(file), select=select, ai_fixer=ai_fixer, test_cmd=args.test,
                              cwd=args.path if Path(args.path).is_dir() else None, write=not args.dry_run)
        except (SyntaxError, UnicodeDecodeError):
            continue
        all_patches += report.patches
        all_escalations += report.escalated
        if report.changed:
            diffs.append(report.diff)
    for p in all_patches:
        engine = "Claude" if p.engine == "ai" else "rules"
        print(f"  ✔ {p.finding.rule_id} {p.finding.title:<32} {Path(p.finding.file).name}:{p.finding.function or 'module'}"
              f"  [{engine}]  {p.description}")
    for e in all_escalations:
        print(f"  ! {e.finding.rule_id} {e.finding.title:<32} {Path(e.finding.file).name}:{e.finding.line}  {e.reason}")
    verb = "proposed" if args.dry_run else "applied"
    print(f"\naegis: {len(all_patches)} verified patch(es) {verb}, {len(all_escalations)} need a human.")
    if args.diff:
        Path(args.diff).write_text("".join(diffs), encoding="utf-8")
        print(f"aegis: wrote {args.diff}")
    elif args.dry_run and diffs:
        print("\n" + "".join(diffs))
    if args.report:
        from .report_html import render_scan_report
        from .scanner.engine import scan_path as rescan
        remaining = sort_by_severity(rescan(args.path, exclude=cfg.exclude))
        Path(args.report).write_text(render_scan_report(remaining, args.path, all_patches, all_escalations,
                                                        lang=args.lang or cfg.language), encoding="utf-8")
        print(f"aegis: wrote {args.report}")
    return EXIT_OK


def cmd_baseline(args) -> int:
    cfg = load_config(args.path)
    findings = scan_path(args.path, exclude=cfg.exclude, disabled=cfg.disable)
    n = write_baseline(findings, args.output, args.path if Path(args.path).is_dir() else ".")
    print(f"aegis: baseline with {n} known finding(s) written to {args.output}")
    return EXIT_OK


def cmd_demo(args) -> int:
    try:
        import flask  # noqa: F401
    except ImportError:
        print("aegis: the demo needs Flask: pip install \"aegis-selfheal[demo]\"", file=sys.stderr)
        return EXIT_ERROR
    from .demo import run_demo
    from .report_html import render_demo_report

    ai_fixer = None
    if args.ai:
        from .ai import AIFixer
        ai_fixer = AIFixer(_ai_client(required=True))
    result = run_demo(args.workdir, ai_fixer=ai_fixer)
    Path(args.report).write_text(render_demo_report(result, args.lang), encoding="utf-8")
    s = result.summary()
    print(f"\n  {s['attacks_blocked']}/{s['attacks_total']} attacks blocked · {s['incidents_healed']} healed · "
          f"mean time-to-heal {s['mean_heal_ms']} ms · {s['exploitable_after']} exploitable after · "
          f"{s['false_positives']} false positives")
    print(f"  report: {os.path.abspath(args.report)}")
    return EXIT_OK if s["exploitable_after"] == 0 and s["false_positives"] == 0 else EXIT_FINDINGS


def cmd_lab(args) -> int:
    try:
        import flask  # noqa: F401
    except ImportError:
        print("aegis: the lab needs Flask: pip install \"aegis-selfheal[demo]\"", file=sys.stderr)
        return EXIT_ERROR
    from .lab import run_lab

    ai_fixer = None
    if args.ai:
        from .ai import AIFixer
        ai_fixer = AIFixer(_ai_client(required=True))
    run_lab(args.workdir, args.port, args.shield, args.heal, args.fresh, ai_fixer)
    return EXIT_OK


def _optional_ai(args):
    if not getattr(args, "ai", False):
        return None
    from .ai import AIFixer
    return AIFixer(_ai_client(required=True))


def cmd_range(args) -> int:
    try:
        import flask  # noqa: F401
    except ImportError:
        print("aegis: the range needs Flask: pip install \"aegis-selfheal[demo]\"", file=sys.stderr)
        return EXIT_ERROR
    from .range import run
    run(args.dir, args.port, args.shield, args.heal, not args.no_fetch, _optional_ai(args))
    return EXIT_OK


def cmd_gateway(args) -> int:
    import time
    from .gateway import Gateway, load_specs, serve
    specs = load_specs(args.config)
    gateway = Gateway(specs, log_dir=args.log_dir, ai_fixer=_optional_ai(args))
    serve(gateway, args.port, args.host)
    print(f"Aegis Gateway on http://{args.host}:{args.port}/ protecting: " + ", ".join(
        f"{s.name} ({', '.join(s.hosts) or ':' + str(s.listen)})" for s in specs), flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return EXIT_OK


def cmd_rules(args) -> int:
    from .patcher.fixes import FIXERS
    for r in RULES:
        fix = "auto-fix" if r.id in FIXERS else "AI / manual"
        print(f"{r.id}  {r.cwe:<9} {r.severity:<8} {r.title:<34} {fix}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegis", description="Self-healing application security.")
    p.add_argument("--version", action="version", version=f"aegis {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="find vulnerabilities")
    s.add_argument("path", nargs="?", default=".", help="file or folder (default: current folder)")
    s.add_argument("-f", "--format", choices=["text", "json", "sarif", "markdown", "html"], default="text",
                   help="output format; sarif plugs into GitHub code scanning")
    s.add_argument("-o", "--output", help="write to this file instead of the terminal")
    s.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "never"],
                   help="exit with code 1 at or above this severity (for CI)")
    s.add_argument("--baseline", help="hide findings recorded by `aegis baseline`")
    s.add_argument("--exclude", action="append", help="glob, can repeat")
    s.add_argument("--disable", action="append", help="rule id, can repeat")
    s.add_argument("--ai-triage", action="store_true", help="ask Claude to confirm findings and explain them")
    s.add_argument("--lang", choices=["en", "ru", "kk"], help="language of AI explanations")
    s.set_defaults(func=cmd_scan)

    f = sub.add_parser("fix", help="apply verified patches")
    f.add_argument("path", nargs="?", default=".", help="file or folder (default: current folder)")
    f.add_argument("--dry-run", action="store_true", help="show patches, change nothing")
    f.add_argument("--ai", action="store_true", help="use Claude for issues rules cannot fix")
    f.add_argument("--ai-attempts", type=int, default=3, help="tries per issue when Claude fixes it (default 3)")
    f.add_argument("--test", help='command that must pass after each patch, e.g. "pytest -q"')
    f.add_argument("--only", help="comma separated rule ids")
    f.add_argument("--include-tests", action="store_true", help="also patch test files (skipped by default)")
    f.add_argument("--diff", help="write all patches to this .diff file")
    f.add_argument("--report", help="write an HTML report")
    f.add_argument("--lang", choices=["en", "ru"], help="language of the HTML report")
    f.set_defaults(func=cmd_fix)

    b = sub.add_parser("baseline", help="record existing findings")
    b.add_argument("path", nargs="?", default=".", help="file or folder (default: current folder)")
    b.add_argument("-o", "--output", default=".aegis-baseline.json", help="where to save it")
    b.set_defaults(func=cmd_baseline)

    d = sub.add_parser("demo", help="run the self-healing demo")
    d.add_argument("--ai", action="store_true", help="let Claude fix what rules cannot (needs ANTHROPIC_API_KEY)")
    d.add_argument("--report", default="aegis-demo-report.html", help="HTML report path")
    d.add_argument("--workdir", help="where to copy VulnShop (default: a temp folder)")
    d.add_argument("--lang", choices=["en", "ru"], default="en", help="language of the HTML report")
    d.set_defaults(func=cmd_demo)

    lab = sub.add_parser("lab", help="run VulnShop locally and watch it heal itself")
    lab.add_argument("--port", type=int, default=5000, help="local port (default 5000)")
    lab.add_argument("--shield", choices=["monitor", "block"], default="monitor",
                     help="monitor lets the first attack through so you can see the heal")
    lab.add_argument("--heal", choices=["auto", "propose", "off"], default="auto",
                     help="auto applies verified patches; propose writes .diff files")
    lab.add_argument("--workdir", default="aegis-lab", help="folder with the lab copy of VulnShop")
    lab.add_argument("--fresh", action="store_true", help="start again from the vulnerable version")
    lab.add_argument("--ai", action="store_true", help="let Claude fix what rules cannot (needs ANTHROPIC_API_KEY)")
    lab.set_defaults(func=cmd_lab)

    rg = sub.add_parser("range", help="real vulnerable apps behind one Aegis Gateway (local lab)")
    rg.add_argument("--dir", default="aegis-range", help="where the apps live (default ./aegis-range)")
    rg.add_argument("--port", type=int, default=8080, help="gateway port (default 8080)")
    rg.add_argument("--shield", choices=["monitor", "block"], default="monitor",
                    help="monitor lets the first attack through so you can see the heal")
    rg.add_argument("--heal", choices=["auto", "propose", "off"], default="auto",
                    help="auto patches and restarts the app; propose writes .diff files")
    rg.add_argument("--no-fetch", action="store_true", help="do not clone DSVW and vulpy from GitHub")
    rg.add_argument("--ai", action="store_true", help="let Claude fix what rules cannot (needs ANTHROPIC_API_KEY)")
    rg.set_defaults(func=cmd_range)

    gw = sub.add_parser("gateway", help="protect any HTTP apps from one server")
    gw.add_argument("-c", "--config", required=True, help="TOML file with [[app]] entries (see docs/GATEWAY.md)")
    gw.add_argument("--port", type=int, default=8080, help="main port (default 8080)")
    gw.add_argument("--host", default="127.0.0.1", help="address to listen on (default 127.0.0.1)")
    gw.add_argument("--log-dir", help="write incidents as JSON Lines here")
    gw.add_argument("--ai", action="store_true", help="let Claude fix what rules cannot (needs ANTHROPIC_API_KEY)")
    gw.set_defaults(func=cmd_gateway)

    r = sub.add_parser("rules", help="list rules")
    r.set_defaults(func=cmd_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:  # never crash on a console that cannot print ✔ (e.g. cp1251 when redirected on Windows)
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
