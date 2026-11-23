"""Inter-procedural taint across a project.

A route handler often passes request data to a helper in another module:

    @mod_user.route("/login", methods=["POST"])          # mod_user.py
    def do_login():
        libuser.login(request.form["username"], ...)

    def login(username, password):                       # libuser.py
        c.execute("... '{}' ...".format(username, password))

Looked at file by file, `login` is ordinary code and its SQL looks low-risk. This pass follows calls
from every handler into project functions (same file, `import mod`, `from mod import f`), marks the
parameters that receive request data as tainted, and repeats for the functions those call, up to a
few levels. The scanner and the fixers then treat those parameters like request input.

Results are kept per absolute file path in EXTRA_TAINT, so per-file scanning picks them up.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Iterable

from .astutil import call_name

# absolute file path -> function name -> tainted parameter names
EXTRA_TAINT: dict[str, dict[str, set[str]]] = {}
_CACHE: dict[str, tuple] = {}


def _top_functions(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    return {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def resolve_call(call: ast.Call, file: Path, aliases: dict[str, str], local: set[str],
                 root: Path) -> tuple[str, str] | None:
    """(file, function) a call goes to, if it is a top-level function of this project."""
    name = call_name(call) or ""
    if not name:
        return None
    module, _, attr = name.rpartition(".")
    if not module:
        if name in local:
            return str(file), name
        real = aliases.get(name)  # from libuser import login
        if not real or "." not in real:
            return None
        module, _, attr = real.rpartition(".")
    else:
        module = aliases.get(module, module)  # import libuser as lu
    rel = module.replace(".", os.sep) + ".py"
    for base in (file.parent, root):
        candidate = (base / rel)
        if candidate.is_file():
            try:
                candidate.resolve().relative_to(root.resolve())
            except ValueError:
                continue  # never follow outside the project
            return str(candidate.resolve()), attr
    return None


def analyze_project(root: str | os.PathLike, files: Iterable[Path] | None = None, max_rounds: int = 4) -> dict:
    """Fill EXTRA_TAINT for every file under root. Cached until a file changes."""
    from .engine import FileAnalysis, iter_python_files

    root = Path(root).resolve()
    if root.is_file():
        root = root.parent
    paths = sorted(Path(p).resolve() for p in (files if files is not None else iter_python_files(root)))
    signature = tuple((str(p), p.stat().st_mtime_ns) for p in paths if p.exists())
    if _CACHE.get(str(root), (None,))[0] == signature:
        return _CACHE[str(root)][1]
    analyses: dict[str, FileAnalysis] = {}
    for p in paths:
        try:
            analyses[str(p)] = FileAnalysis(p)
        except (SyntaxError, UnicodeDecodeError, ValueError, OSError):
            continue
    for path in analyses:
        EXTRA_TAINT.pop(path, None)

    found: dict[str, dict[str, set[str]]] = {}
    work: list[tuple[str, ast.AST]] = []
    for path, analysis in analyses.items():  # start from every function that already sees request data
        for node in ast.walk(analysis.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body_node = node.body[0] if node.body else None
                if body_node is not None and analysis.context(body_node).route is not None:
                    work.append((path, node))
    for _ in range(max_rounds):
        nxt: list[tuple[str, ast.AST]] = []
        for path, func in work:
            analysis = analyses[path]
            taint = analysis.context(func.body[0]).taint if func.body else None
            if taint is None:
                continue
            local = set(_top_functions(analysis.tree))
            for call in (n for n in ast.walk(func) if isinstance(n, ast.Call)):
                target = resolve_call(call, Path(path), analysis.aliases, local, root)
                if target is None or target[0] not in analyses:
                    continue
                callee = _top_functions(analyses[target[0]].tree).get(target[1])
                if callee is None or callee is func:
                    continue
                params = [a.arg for a in callee.args.posonlyargs + callee.args.args]
                hit = {params[i] for i, a in enumerate(call.args)
                       if i < len(params) and not isinstance(a, ast.Starred) and taint.expr(a)}
                kwnames = {a.arg for a in callee.args.args + callee.args.kwonlyargs}
                hit |= {k.arg for k in call.keywords if k.arg in kwnames and taint.expr(k.value)}
                if not hit:
                    continue
                known = found.setdefault(target[0], {}).setdefault(target[1], set())
                if hit - known:
                    known |= hit
                    EXTRA_TAINT.setdefault(target[0], {})[target[1]] = set(known)
                    analyses[target[0]].reset_context(callee)
                    nxt.append((target[0], callee))
        if not nxt:
            break
        work = nxt
    _CACHE[str(root)] = (signature, found)
    return found
