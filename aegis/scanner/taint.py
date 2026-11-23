"""Lightweight intra-procedural taint tracking.

A value is *tainted* when it can be controlled by a remote attacker: HTTP
request data (query, form, JSON, cookies, headers, files) and route path
parameters. Local CLI input is the operator's own input and is not a source. Taint flows through assignments,
f-strings, concatenation and calls, and is removed by known sanitizers.
"""
from __future__ import annotations

import ast
from typing import Iterable

from .astutil import call_name

REQUEST_ATTRS = {
    "args", "form", "values", "json", "cookies", "headers",
    "data", "files", "get_json", "get_data", "query_params", "path_params",
    # Django
    "GET", "POST", "body", "META", "FILES", "COOKIES",
}

SANITIZERS = {
    "int", "float", "bool", "len",
    "html.escape", "escape", "markupsafe.escape",
    "shlex.quote", "quote",
    "os.path.basename", "basename", "posixpath.basename", "ntpath.basename",
    "secure_filename", "werkzeug.utils.secure_filename",
    "safe_join", "werkzeug.utils.safe_join", "werkzeug.security.safe_join", "flask.safe_join",
    "ast.literal_eval", "slugify", "django.utils.text.slugify", "uuid.UUID",
}


# Reading rows back from a database ends *reflected* taint: the value now comes
# from storage, not from this request. (Stored XSS is out of scope for now.)
DB_READS = {"fetchone", "fetchall", "fetchmany", "first", "one", "one_or_none", "scalar", "scalars"}


class Taint:
    """Taint state for one function (or for module-level code)."""

    def __init__(self, body: Iterable[ast.stmt], params: Iterable[str] = (), self_sources: Iterable[str] = ()):
        self.tainted: set[str] = set(params)
        self.self_sources = set(self_sources)  # http.server handlers: self.path, self.headers, self.rfile
        self.assignments: dict[str, ast.AST] = {}
        self._body = list(body)
        self.bindings = self._count_bindings()
        self._propagate()

    # -- public -----------------------------------------------------------
    def expr(self, node: ast.AST | None) -> bool:
        """Is this expression (possibly) attacker-controlled?"""
        if node is None:
            return False
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in DB_READS:
                return False
            name = call_name(node)
            if name in SANITIZERS:
                return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "request"
            and node.attr in REQUEST_ATTRS
        ):
            return True
        if (self.self_sources and isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                and node.value.id == "self" and node.attr in self.self_sources):
            return True
        return any(self.expr(child) for child in ast.iter_child_nodes(node))

    def resolve(self, node: ast.AST, strict: bool = False) -> ast.AST | None:
        """Follow `x = <expr>; use(x)` one step so rules can see the real value.

        Detection may over-approximate, so by default the last assignment is used. Fixers pass
        strict=True: if the name is bound more than once (if/else branches, `sql += f"..."`,
        a loop), editing one assignment would leave another path open, so None is returned.
        Appending a constant (`sql += " ORDER BY id"`) does not count.
        """
        if isinstance(node, ast.Name) and node.id in self.assignments:
            if strict and self.bindings.get(node.id, 0) != 1:
                return None
            return self.assignments[node.id]
        return node

    # -- internals --------------------------------------------------------
    def _count_bindings(self) -> dict[str, int]:
        harmless = {
            id(node.target) for node in self._statements()
            if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name)
            and isinstance(node.op, ast.Add) and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        }
        counts: dict[str, int] = {}
        for node in self._statements():
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and id(node) not in harmless:
                counts[node.id] = counts.get(node.id, 0) + 1
        return counts

    def _statements(self) -> Iterable[ast.AST]:
        for stmt in self._body:
            yield from ast.walk(stmt)

    def _propagate(self) -> None:
        # Iterate to a fixed point so taint survives out-of-order assignments.
        for _ in range(4):
            before = len(self.tainted)
            for node in self._statements():
                if isinstance(node, ast.Assign):
                    targets, value = node.targets, node.value
                elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                    targets, value = [node.target], node.value
                elif isinstance(node, (ast.For, ast.AsyncFor)):
                    targets, value = [node.target], node.iter
                elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                    targets, value = [node.optional_vars], node.context_expr
                else:
                    continue
                if value is None:
                    continue
                for target in targets:
                    if isinstance(target, ast.Name) and isinstance(node, ast.Assign):
                        self.assignments[target.id] = value
                    if self.expr(value):
                        for name in ast.walk(target):
                            if isinstance(name, ast.Name):
                                self.tainted.add(name.id)
            if len(self.tainted) == before:
                break
