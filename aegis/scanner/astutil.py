"""Small helpers for working with Python ASTs and source positions."""
from __future__ import annotations

import ast
import re

ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete"}


def dotted(node: ast.AST | None) -> str | None:
    """Return 'a.b.c' for Name/Attribute chains, else None."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def call_name(call: ast.Call) -> str | None:
    return dotted(call.func)


def is_constant_str(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def is_dynamic_string(node: ast.AST | None) -> bool:
    """True for strings assembled at runtime: f-strings, %, +, .format()."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return is_constant_str(node.left)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        parts = flatten_concat(node)
        return any(is_constant_str(p) for p in parts) and any(not is_constant_str(p) for p in parts)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return is_constant_str(node.func.value)
    return False


def flatten_concat(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return flatten_concat(node.left) + flatten_concat(node.right)
    return [node]


def route_info(func: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, list[str]] | None:
    """If `func` is a Flask/FastAPI-style route handler, return (path, methods)."""
    for deco in func.decorator_list:
        if not isinstance(deco, ast.Call):
            continue
        name = dotted(deco.func) or ""
        verb = name.rsplit(".", 1)[-1]
        if verb in ROUTE_DECORATORS and deco.args and is_constant_str(deco.args[0]):
            methods = ["GET"] if verb == "route" else [verb.upper()]
            for kw in deco.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    methods = [e.value for e in kw.value.elts if is_constant_str(e)]
            return deco.args[0].value, methods
    return None


def build_parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def enclosing_function(node: ast.AST, parents: dict[ast.AST, ast.AST]):
    cur = parents.get(node)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur
        cur = parents.get(cur)
    return None


_LINE = re.compile(r"[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+$")


def source_lines(source: str) -> list[str]:
    """Lines as Python's tokenizer counts them (keeping endings).

    str.splitlines() also breaks on form feeds, U+2028 and other characters that are not line
    breaks in Python source, which would shift every position after them.
    """
    return _LINE.findall(source)


class SourceMap:
    """Converts AST (line, utf-8 byte col) positions into string offsets."""

    def __init__(self, source: str):
        self.source = source
        self.lines = source_lines(source)
        self._starts = [0]
        for line in self.lines:
            self._starts.append(self._starts[-1] + len(line))

    def offset(self, line: int, byte_col: int) -> int:
        text = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
        char_col = len(text.encode("utf-8")[:byte_col].decode("utf-8", errors="ignore"))
        return self._starts[line - 1] + char_col

    def span(self, node: ast.AST) -> tuple[int, int]:
        return (
            self.offset(node.lineno, node.col_offset),
            self.offset(node.end_lineno, node.end_col_offset),
        )

    def segment(self, node: ast.AST) -> str:
        start, end = self.span(node)
        return self.source[start:end]

    def line(self, lineno: int) -> str:
        if 0 < lineno <= len(self.lines):
            return self.lines[lineno - 1].rstrip("\n")
        return ""
