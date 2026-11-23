"""Runs every rule over every node of a Python file, with taint context."""
from __future__ import annotations

import ast
import fnmatch
import os
import re
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..models import SEVERITY_ORDER, Finding
from .astutil import SourceMap, build_parents, enclosing_function, route_info
from .rules import RULES, Rule
from .taint import REQUEST_ATTRS, Taint

SKIP_DIRS = {".git", ".venv", "venv", "env", "__pycache__", "node_modules", "site-packages", ".tox", "build", "dist"}


@dataclass
class NodeContext:
    """Everything a rule or a fixer needs to know about one node."""

    file: str
    tree: ast.Module
    sm: SourceMap
    function: ast.FunctionDef | ast.AsyncFunctionDef | None
    taint: Taint
    route: tuple[str, list[str]] | None
    aliases: dict[str, str] | None = None  # local name -> imported dotted name ("sp" -> "subprocess")


class FileAnalysis:
    """Parsed file + per-function taint, reusable by scanner and patcher."""

    def __init__(self, path: str | os.PathLike, source: str | None = None):
        self.path = str(path)
        self.source = source if source is not None else Path(path).read_text(encoding="utf-8")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # e.g. invalid escape sequences in the scanned code
            self.tree = ast.parse(self.source, filename=self.path)
        self.sm = SourceMap(self.source)
        self.parents = build_parents(self.tree)
        self.aliases = import_aliases(self.tree)
        self._taints: dict[ast.AST | None, Taint] = {}
        self._routes: dict[ast.AST, tuple[str, list[str]] | None] = {}

    def context(self, node: ast.AST) -> NodeContext:
        func = enclosing_function(node, self.parents)
        if func not in self._taints:
            if func is None:
                body = [s for s in self.tree.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
                self._taints[None] = Taint(body)
            else:
                route = route_info(func)
                arg_names = [a.arg for a in func.args.args + func.args.kwonlyargs]
                if route is None and _is_view(func, arg_names):
                    route = ("<view>", ["*"])  # Django-style view
                self_sources: tuple[str, ...] = ()
                if route is None and _is_http_server_method(func, self.parents):
                    route = ("<http.server>", [func.name[3:]])
                    self_sources = HTTP_SERVER_SOURCES
                self._routes[func] = route
                params = [a for a in arg_names if a not in ("self", "cls", "request")] if route else []
                self._taints[func] = Taint(func.body, params, self_sources)
        route = self._routes.get(func) if func is not None else None
        return NodeContext(self.path, self.tree, self.sm, func, self._taints[func], route, self.aliases)

    def routes(self) -> list[tuple[str, list[str], str]]:
        """All route handlers in the file: (path, methods, function name)."""
        out = []
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                info = route_info(node)
                if info:
                    out.append((info[0], info[1], node.name))
        return out


HTTP_SERVER_BASES = {"BaseHTTPRequestHandler", "SimpleHTTPRequestHandler", "CGIHTTPRequestHandler"}
HTTP_SERVER_SOURCES = ("path", "headers", "rfile", "requestline", "raw_requestline")


def _is_http_server_method(func, parents) -> bool:
    """do_GET / do_POST of a standard-library http.server handler: self.path etc. come from the client."""
    if not func.name.startswith("do_") or not func.name[3:].isupper():
        return False
    cls = parents.get(func)
    if not isinstance(cls, ast.ClassDef):
        return False
    bases = {b.attr if isinstance(b, ast.Attribute) else getattr(b, "id", None) for b in cls.bases}
    return bool(bases & HTTP_SERVER_BASES)


def import_aliases(tree: ast.Module) -> dict[str, str]:
    """`import subprocess as sp`, `from os import system`: what each local name really refers to."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    aliases[a.asname] = a.name
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for a in node.names:
                if a.name != "*":
                    aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    return aliases


def _is_view(func, arg_names: list[str]) -> bool:
    """Django-style view: first parameter `request` that is used like an HTTP request.

    (pytest fixtures are also called `request`, but use request.param / request.node.)
    """
    positional = [a for a in arg_names if a not in ("self", "cls")]
    if not positional or positional[0] != "request":
        return False
    for node in ast.walk(func):
        if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "request"
                and node.attr in REQUEST_ATTRS):
            return True
    return False


def _make_finding(rule: Rule, node: ast.AST, ctx: NodeContext, message: str, tainted: bool,
                  severity: str | None = None) -> Finding:
    from ..patcher.fixes import FIXERS  # local import: patcher depends on scanner

    fixer = FIXERS.get(rule.id)
    fixable = bool(fixer and fixer(node, ctx) is not None)
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        cwe=rule.cwe,
        severity=severity or (rule.severity if tainted else rule.severity_untainted),
        file=ctx.file,
        line=node.lineno,
        col=node.col_offset,
        end_line=node.end_lineno,
        end_col=node.end_col_offset,
        function=ctx.function.name if ctx.function else None,
        snippet=ctx.sm.line(node.lineno).strip(),
        message=message,
        tainted=tainted,
        fixable=fixable,
    )


SUPPRESS = re.compile(r"#\s*aegis:\s*ignore(?:\[([A-Z0-9,\s]+)\])?", re.I)


def _suppressed(sm: SourceMap, finding_line: int, rule_id: str) -> bool:
    """`# aegis: ignore` or `# aegis: ignore[AEG006]` on the line or the line above."""
    for lineno in (finding_line, finding_line - 1):
        text = sm.line(lineno)
        if lineno != finding_line and not text.lstrip().startswith("#"):
            continue  # a comment above only counts when it stands on its own line
        m = SUPPRESS.search(text)
        if m and (m.group(1) is None or rule_id in {r.strip().upper() for r in m.group(1).split(",")}):
            return True
    return False


def scan_source(path: str, source: str | None = None, disabled: set[str] | None = None) -> list[Finding]:
    analysis = FileAnalysis(path, source)
    disabled = disabled or set()
    findings: list[Finding] = []
    seen: set[tuple[str, int, int]] = set()
    for node in ast.walk(analysis.tree):
        if not isinstance(node, (ast.Call, ast.Assign, ast.AnnAssign, ast.Return)):
            continue
        ctx = analysis.context(node)
        for rule in RULES:
            if rule.id in disabled:
                continue
            match = rule.check(node, ctx)
            if match is None:
                continue
            key = (rule.id, node.lineno, node.col_offset)
            if key in seen:
                continue
            seen.add(key)
            if _suppressed(analysis.sm, node.lineno, rule.id):
                continue
            findings.append(_make_finding(rule, node, ctx, match.message, match.tainted, match.severity))
    findings.sort(key=lambda f: (f.file, f.line, f.col))
    return findings


def iter_python_files(root: str | os.PathLike, exclude: Iterable[str] = ()) -> Iterable[Path]:
    root = Path(root)
    exclude = list(exclude)
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(name, pat) for pat in exclude):
                continue
            yield path


def scan_path(root: str | os.PathLike, exclude: Iterable[str] = (), disabled: set[str] | None = None,
              errors: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for file in iter_python_files(root, exclude):
        try:
            findings.extend(scan_source(str(file), disabled=disabled))
        except (SyntaxError, UnicodeDecodeError, ValueError) as exc:
            if errors is not None:
                errors.append(f"{file}: {exc}")
    return findings


def sort_by_severity(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line))
