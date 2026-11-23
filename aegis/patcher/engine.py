"""Patch engine: plan a fix, apply it, and accept it only if verification passes.

Order of strategies for every finding:
  1. deterministic fixer (fast, predictable, explainable)
  2. AI fixer (Claude), retried with verifier feedback
  3. escalate to a human

A patch is accepted only when ALL gates pass:
  syntax     - the patched file compiles
  fixed      - the targeted vulnerability is gone from that function
  no_new     - no other vulnerability appeared anywhere in the file
  tests      - optional user command (e.g. `pytest -q`) exits with 0
"""
from __future__ import annotations

import ast
import difflib
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from ..models import Escalation, Finding, Patch
from ..scanner.astutil import source_lines
from ..scanner.engine import FileAnalysis, scan_source
from .fixes import FIXERS, FixPlan

Selector = Callable[[Finding], bool]


# ------------------------------------------------------------- text edits ---

def apply_edits(source: str, edits: list[tuple[int, int, str]]) -> str:
    ordered = sorted(edits, key=lambda e: e[0], reverse=True)
    for (s1, e1, _), (s2, e2, _) in zip(ordered[1:], ordered):
        if e1 > s2:
            raise ValueError("overlapping edits")
    for start, end, text in ordered:
        source = source[:start] + text + source[end:]
    return source


def _has_import(tree: ast.Module, module: str) -> bool:
    for node in tree.body:
        if isinstance(node, ast.Import) and any(a.name == module and a.asname is None for a in node.names):
            return True
    return False


def ensure_imports(source: str, modules: set[str] | list[str]) -> str:
    """Add missing imports where a human would put them.

    `import x` lines join the leading block of plain imports in alphabetical
    order; full `from a import b` lines go after the last leading import.
    """
    for mod in sorted(modules, key=lambda m: (m.startswith(("import ", "from ")), m.lower())):
        source = _add_import(source, mod)
    return source


def _add_import(source: str, mod: str) -> str:
    tree = ast.parse(source)
    lines = source_lines(source)
    full_line = mod.startswith(("import ", "from "))
    if full_line:
        if any(l.strip() == mod.strip() for l in lines):
            return source
        text = mod.strip()
    else:
        if _has_import(tree, mod):
            return source
        text = f"import {mod}"

    body = tree.body
    first = 0
    after_docstring = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
            and isinstance(body[0].value.value, str):
        after_docstring = body[0].end_lineno
        first = 1
    leading = []
    for node in body[first:]:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            leading.append(node)
        else:
            break
    real = [n for n in leading if not (isinstance(n, ast.ImportFrom) and n.module == "__future__")]

    def insert_before(lineno: int) -> str:
        return "".join(lines[: lineno - 1]) + text + "\n" + "".join(lines[lineno - 1:])

    def insert_after(lineno: int) -> str:
        head = lines[:lineno]
        if head and not head[-1].endswith("\n"):
            head[-1] += "\n"
        return "".join(head) + text + "\n" + "".join(lines[lineno:])

    if not full_line:
        plain = [n for n in real if isinstance(n, ast.Import)]
        for node in plain:
            if node.names[0].name.lower() > mod.lower():
                return insert_before(node.lineno)
        if plain:
            return insert_after(plain[-1].end_lineno)
        if real:
            return insert_before(real[0].lineno)
    if leading:
        return insert_after(leading[-1].end_lineno)
    if after_docstring:
        return insert_after(after_docstring)
    return text + "\n" + source


def _preferred_quote(text: str, fallback: str) -> str:
    """Quote style of the code being replaced: its first string delimiter, else the file's."""
    m = re.search(r"['\"]", text)
    return m.group(0) if m else fallback


def _file_quote(source: str) -> str:
    dq, sq = source.count('"'), source.count("'")
    if dq > sq:
        return '"'
    return "'" if sq > dq else '"'


def restyle_quotes(new_text: str, preferred: str) -> str:
    """Match the file's quote style when it is provably safe to do so."""
    if preferred == '"' and '"' not in new_text and "\\" not in new_text:
        return new_text.replace("'", '"')
    return new_text


def unified_diff(before: str, after: str, path: str) -> str:
    name = os.path.basename(path)
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{name}",
            tofile=f"b/{name}",
        )
    )


# ----------------------------------------------------------- verification ---

@dataclass
class Verification:
    checks: dict[str, bool]
    feedback: str = ""

    @property
    def ok(self) -> bool:
        return all(self.checks.values())


def _counts(findings: list[Finding]) -> Counter:
    return Counter((f.rule_id, f.function) for f in findings)


def verify(path: str, before: list[Finding], after_source: str, target: Finding,
           test_cmd: str | None = None, cwd: str | None = None) -> Verification:
    checks: dict[str, bool] = {}
    try:
        compile(after_source, path, "exec")
        checks["syntax"] = True
    except SyntaxError as exc:
        checks["syntax"] = False
        return Verification(checks, f"The patched code does not compile: {exc.msg} (line {exc.lineno}).")

    after = scan_source(path, after_source)
    b, a = _counts(before), _counts(after)
    key = (target.rule_id, target.function)
    checks["fixed"] = a[key] < b[key]
    new_issues = [k for k in a if a[k] > b.get(k, 0)]
    checks["no_new"] = not new_issues
    feedback = []
    if not checks["fixed"]:
        still = [f for f in after if (f.rule_id, f.function) == key]
        detail = still[0].snippet if still else ""
        feedback.append(f"The {target.title} ({target.cwe}) is still detected: `{detail}`.")
    if new_issues:
        feedback.append("The patch introduced new issues: " + ", ".join(f"{r} in {fn}" for r, fn in new_issues) + ".")

    if test_cmd and checks["syntax"] and checks["fixed"] and checks["no_new"]:
        passed, output = run_tests_on_copy(path, after_source, test_cmd, cwd)
        checks["tests"] = passed
        if not passed:
            feedback.append(f"The test suite failed after the patch:\n{output[-1500:]}")
    return Verification(checks, "\n".join(feedback))


COPY_IGNORE = shutil.ignore_patterns(".git", ".venv", "venv", "env", "node_modules", "__pycache__", ".tox",
                                     ".mypy_cache", ".pytest_cache", "build", "dist", "*.egg-info", ".aegis")


def run_tests_on_copy(path: str, patched: str, test_cmd: str, cwd: str | None,
                      timeout: int = 600) -> tuple[bool, str]:
    """Run the project's tests against a candidate in a temporary copy of the project.

    The real file is never touched before every gate has passed. The tests do execute the
    candidate (that is what tests are for), so run `--test` with AI patches in CI or a container.
    """
    root = Path(cwd or os.getcwd()).resolve()
    target = Path(path).resolve()
    if root not in target.parents:
        root = target.parent
    with tempfile.TemporaryDirectory(prefix="aegis-verify-") as tmp:
        copy = Path(tmp) / root.name
        shutil.copytree(root, copy, ignore=COPY_IGNORE, symlinks=True)
        (copy / target.relative_to(root)).write_text(patched, encoding="utf-8")
        try:
            # The test command is written by the project owner (CLI flag / config), never by a request.
            proc = subprocess.run(  # aegis: ignore[AEG002]
                test_cmd, shell=True, cwd=copy, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return False, f"the test command did not finish within {timeout} s"
        return proc.returncode == 0, proc.stdout + proc.stderr


# ---------------------------------------------------------------- planning --

def _locate(analysis: FileAnalysis, finding: Finding) -> Optional[ast.AST]:
    for node in ast.walk(analysis.tree):
        if (
            getattr(node, "lineno", None) == finding.line
            and getattr(node, "col_offset", None) == finding.col
            and getattr(node, "end_lineno", None) == finding.end_line
            and getattr(node, "end_col_offset", None) == finding.end_col
            and isinstance(node, (ast.Call, ast.Assign, ast.AnnAssign, ast.Return))
        ):
            return node
    return None


def deterministic_patch(path: str, source: str, finding: Finding) -> tuple[str, FixPlan] | None:
    fixer = FIXERS.get(finding.rule_id)
    if fixer is None:
        return None
    analysis = FileAnalysis(path, source)
    node = _locate(analysis, finding)
    if node is None:
        return None
    ctx = analysis.context(node)
    plan = fixer(node, ctx)
    if plan is None:
        return None
    if _shadowed(analysis.tree, ctx.function, plan.imports):
        return None  # e.g. a variable called `html` would hide the html module the fix needs
    file_quote = _file_quote(source)
    plan.edits = [
        (start, end, restyle_quotes(text, _preferred_quote(source[start:end], file_quote)))
        for start, end, text in plan.edits
    ]
    try:
        new = apply_edits(source, plan.edits)
        if plan.imports:
            new = ensure_imports(new, plan.imports)
    except (ValueError, SyntaxError):
        return None
    return new, plan


def _bound_names(scope: ast.AST, include_nested: bool) -> set[str]:
    names: set[str] = set()
    nodes = ast.walk(scope) if include_nested else _walk_shallow(scope)
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node is not scope:
            names.add(node.name)
        elif isinstance(node, ast.alias) and node.asname:
            names.add(node.asname)
        elif isinstance(node, ast.ImportFrom):
            names.update(a.asname or a.name for a in node.names)
    return names


def _walk_shallow(module: ast.AST):
    """Module-level statements only (do not descend into functions/classes)."""
    stack = list(ast.iter_child_nodes(module))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(node))


def _shadowed(tree: ast.Module, function, modules) -> bool:
    simple = {m for m in modules if not m.startswith(("import ", "from "))}
    if not simple:
        return False
    taken = _bound_names(tree, include_nested=False)
    if function is not None:
        taken |= _bound_names(function, include_nested=True)
    return bool(simple & taken)


# -------------------------------------------------------------- the loop ---

@dataclass
class FixReport:
    path: str
    original: str
    patched: str
    patches: list[Patch] = field(default_factory=list)
    escalated: list[Escalation] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.original != self.patched

    @property
    def diff(self) -> str:
        return unified_diff(self.original, self.patched, self.path)


def fix_file(
    path: str,
    select: Selector | None = None,
    ai_fixer=None,
    test_cmd: str | None = None,
    cwd: str | None = None,
    write: bool = True,
    max_rounds: int = 60,
) -> FixReport:
    """Fix every selected finding in `path`, one verified patch at a time."""
    original = Path(path).read_text(encoding="utf-8")
    source = original
    report = FixReport(path, original, original)
    attempted: set[tuple[str, str | None, str]] = set()

    for _ in range(max_rounds):
        findings = scan_source(path, source)
        todo = [
            f for f in findings
            if (select is None or select(f)) and (f.rule_id, f.function, f.snippet) not in attempted
        ]
        if not todo:
            break
        finding = todo[0]
        attempted.add((finding.rule_id, finding.function, finding.snippet))

        accepted: Patch | None = None
        reason = "No built-in rule can fix this pattern safely."
        planned = deterministic_patch(path, source, finding)
        if planned is not None:
            candidate, plan = planned
            result = verify(path, findings, candidate, finding, test_cmd, cwd)
            if result.ok:
                accepted = Patch(finding, plan.description, unified_diff(source, candidate, path), True,
                                 result.checks, engine="rules")
                source = candidate
            else:
                reason = "Rule-based patch failed verification: " + (result.feedback or "unknown reason")

        if accepted is None and ai_fixer is not None:
            outcome = ai_fixer.fix(path, source, finding,
                                   lambda cand: verify(path, findings, cand, finding, test_cmd, cwd))
            if outcome.accepted:
                accepted = Patch(finding, outcome.explanation, unified_diff(source, outcome.source, path), True,
                                 outcome.verification.checks, engine="ai", attempts=outcome.attempts)
                source = outcome.source
            else:
                reason = outcome.reason
        elif accepted is None:
            reason += " Enable the AI engine (ANTHROPIC_API_KEY) or review manually."

        if accepted is not None:
            report.patches.append(accepted)
        else:
            report.escalated.append(Escalation(finding, reason))

    report.patched = source
    if write and report.changed:
        Path(path).write_text(source, encoding="utf-8")
    return report


def fix_findings_in_function(path: str, function: str | None, rule_ids: set[str] | None, **kwargs) -> FixReport:
    def select(f: Finding) -> bool:
        return f.function == function and (rule_ids is None or f.rule_id in rule_ids)

    return fix_file(path, select=select, **kwargs)
