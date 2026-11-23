"""Machine and human readable outputs: text, JSON, SARIF 2.1.0, Markdown."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from . import __version__
from .models import SEVERITY_ORDER, Finding
from .scanner.rules import RULES

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
HELP_URI = "https://cwe.mitre.org/data/definitions/{}.html"


def _rel(path: str, root: str) -> str:
    try:
        return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()


# --------------------------------------------------------------------- text --

class _C:
    def __init__(self, enabled: bool):
        self.on = enabled

    def __call__(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.on else text


def render_text(findings: list[Finding], root: str = ".", color: bool | None = None) -> str:
    if color is None:
        color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    c = _C(color)
    sev_color = {"critical": "1;31", "high": "31", "medium": "33", "low": "36"}
    if not findings:
        return c("32", "✔ No vulnerabilities found.")
    lines = []
    for f in sorted(findings, key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), x.file, x.line)):
        tag = c(sev_color.get(f.severity, "0"), f"{f.severity.upper():<8}")
        fix = c("32", "auto-fix") if f.fixable else c("2", "manual")
        lines.append(f"{tag} {f.rule_id} {f.title} [{f.cwe}]  {fix}")
        lines.append(f"         {c('1', _rel(f.file, root))}:{f.line}" + (f" in {f.function}()" if f.function else ""))
        lines.append(f"         {c('2', f.snippet[:120])}")
        lines.append(f"         {f.message}")
        if f.ai_explanation:
            verdict = "AI: likely false positive" if f.ai_verdict == "likely_false_positive" else "AI"
            lines.append(f"         {c('35', verdict + ':')} {f.ai_explanation}")
        lines.append("")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    summary = ", ".join(f"{n} {s}" for s, n in counts.items() if n)
    fixable = sum(1 for f in findings if f.fixable)
    lines.append(c("1", f"{len(findings)} finding(s): {summary}. {fixable} can be fixed automatically "
                        f"(run `aegis fix`)."))
    return "\n".join(lines)


# --------------------------------------------------------------------- json --

def render_json(findings: list[Finding], root: str = ".", extra: dict | None = None) -> str:
    data = {
        "tool": "aegis", "version": __version__,
        "findings": [{**f.to_dict(), "file": _rel(f.file, root)} for f in findings],
        **(extra or {}),
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


# -------------------------------------------------------------------- sarif --

def render_sarif(findings: list[Finding], root: str = ".") -> str:
    rules = []
    for r in RULES:
        cwe_num = r.cwe.split("-")[-1]
        rules.append({
            "id": r.id,
            "name": r.title.title().replace(" ", "").replace("(", "").replace(")", "").replace("/", ""),
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": f"{r.title} ({r.cwe})"},
            "helpUri": HELP_URI.format(cwe_num),
            "properties": {
                "tags": ["security", r.cwe, f"external/cwe/cwe-{cwe_num}"],
                "security-severity": SECURITY_SEVERITY[r.severity],
                "precision": "high",
            },
        })
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message + (" Aegis can fix this automatically: `aegis fix`." if f.fixable else "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _rel(f.file, root), "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.line, "startColumn": f.col + 1,
                               "endLine": f.end_line, "endColumn": f.end_col + 1},
                }
            }],
            "properties": {"security-severity": SECURITY_SEVERITY.get(f.severity, "5.0"), "tainted": f.tainted},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Aegis", "version": __version__,
                                "informationUri": "https://github.com/facei7505-droid/aegis", "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


# ----------------------------------------------------------------- markdown --

def render_markdown(findings: list[Finding], root: str = ".", patches=None) -> str:
    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
    out = ["## 🛡 Aegis security report", ""]
    if not findings:
        out.append("No vulnerabilities found. ✅")
        return "\n".join(out)
    fixable = sum(1 for f in findings if f.fixable)
    out.append(f"**{len(findings)} finding(s)**, {fixable} auto-fixable with `aegis fix`.")
    out += ["", "| Severity | Rule | Location | Issue |", "| --- | --- | --- | --- |"]
    for f in sorted(findings, key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), x.file, x.line)):
        loc = f"`{_rel(f.file, root)}:{f.line}`"
        out.append(f"| {icon.get(f.severity, '')} {f.severity} | {f.rule_id} {f.title} ({f.cwe}) | {loc} | {f.message} |")
    if patches:
        out += ["", "<details><summary>Proposed verified patches</summary>", ""]
        for p in patches:
            out += [f"**{p.finding.rule_id} in `{p.finding.function or 'module'}`** — {p.description}", "",
                    "```diff", p.diff.rstrip(), "```", ""]
        out.append("</details>")
    return "\n".join(out)
