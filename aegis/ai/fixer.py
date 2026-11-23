"""AI patch engine: Claude proposes, the Aegis verifier decides.

Claude never writes to disk directly. Each proposal is spliced into an
in-memory copy of the file and must pass the same gates as a rule-based
patch (syntax, vulnerability gone, nothing new introduced, optional tests).
Rejected proposals are sent back with the verifier's feedback.
"""
from __future__ import annotations

import ast
import textwrap
from dataclasses import dataclass, field
from typing import Callable

from ..models import Finding
from ..patcher.engine import Verification, ensure_imports
from ..scanner.astutil import build_parents, enclosing_function, source_lines
from .client import LLM, AIError, parse_json_reply
from .prompts import FEEDBACK, FIX_SYSTEM, FIX_USER


@dataclass
class Region:
    start: int      # 1-based first line (includes decorators)
    end: int        # 1-based last line
    indent: str
    code: str       # dedented
    func_name: str | None
    func_args: list[str] | None
    decorators: list[str] | None = None


@dataclass
class AIOutcome:
    accepted: bool
    source: str = ""
    explanation: str = ""
    verification: Verification = field(default_factory=lambda: Verification({}))
    attempts: int = 0
    reason: str = ""


def extract_region(source: str, finding: Finding) -> Region:
    tree = ast.parse(source)
    parents = build_parents(tree)
    target = None
    for node in ast.walk(tree):
        if getattr(node, "lineno", None) == finding.line and getattr(node, "col_offset", None) == finding.col:
            target = node
            break
    lines = source_lines(source)
    func = enclosing_function(target, parents) if target is not None else None
    if func is not None:
        start = min([func.lineno] + [d.lineno for d in func.decorator_list])
        end = func.end_lineno
        args = [a.arg for a in func.args.posonlyargs + func.args.args + func.args.kwonlyargs]
        name = func.name
        decorators = [ast.dump(d) for d in func.decorator_list]
    else:
        stmt = target
        while stmt is not None and not isinstance(parents.get(stmt), ast.Module):
            stmt = parents.get(stmt)
        stmt = stmt or target
        start, end = stmt.lineno, stmt.end_lineno
        name, args, decorators = None, None, None
    raw = "".join(lines[start - 1:end])
    first = lines[start - 1]
    indent = first[: len(first) - len(first.lstrip())]
    return Region(start, end, indent, textwrap.dedent(raw), name, args, decorators)


def splice(source: str, region: Region, new_code: str) -> str:
    lines = source_lines(source)
    body = textwrap.indent(textwrap.dedent(new_code).strip("\n") + "\n", region.indent)
    return "".join(lines[: region.start - 1]) + body + "".join(lines[region.end:])


def _top_imports(source: str) -> list[str]:
    names = []
    for node in ast.parse(source).body:
        if isinstance(node, ast.Import):
            names += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


# Modules a security fix may need. Anything else must already be imported by the file.
SAFE_MODULES = {
    "html", "ast", "shlex", "subprocess", "os", "os.path", "posixpath", "secrets", "hashlib", "hmac",
    "ipaddress", "urllib.parse", "pathlib", "json", "re", "string", "functools", "typing", "uuid",
    "bcrypt", "argon2", "werkzeug.security", "werkzeug.utils", "markupsafe", "defusedxml", "yaml",
    "flask", "django.utils.html", "bleach",
}
BUILTIN_NAMES = set(dir(__import__("builtins")))


def _import_problem(node: ast.AST, allowed: set[str]) -> str | None:
    if isinstance(node, ast.ImportFrom):
        module = node.module or ""
        if node.level or any(a.name == "*" for a in node.names):
            return "relative and star imports are not allowed"
        names = [(module, a.asname or a.name) for a in node.names]
    else:
        names = [(a.name, a.asname or a.name.split(".")[0]) for a in node.names]
    for module, bound in names:
        if module == "builtins" or bound in BUILTIN_NAMES:
            return f"the import `{ast.unparse(node)}` would shadow a Python builtin"
        if module not in allowed and module.split(".")[0] not in allowed:
            return f"`{module}` is not needed for a security fix; use the standard library or modules already imported"
    return None


def _valid_imports(lines: list, source: str) -> tuple[list[str], str | None]:
    """Import lines Claude asked for, if they are plain, safe and do not shadow anything."""
    allowed = SAFE_MODULES | set(_top_imports(source))
    ok = []
    for line in lines or []:
        if not isinstance(line, str):
            continue
        try:
            tree = ast.parse(line.strip())
        except SyntaxError:
            continue
        if len(tree.body) != 1 or not isinstance(tree.body[0], (ast.Import, ast.ImportFrom)):
            return [], "each entry in imports must be a single import statement"
        problem = _import_problem(tree.body[0], allowed)
        if problem:
            return [], problem
        ok.append(line.strip())
    return ok, None


# Capabilities a fix never needs. A proposal that adds one of them is rejected, even if the
# scanner cannot see a vulnerability in it (a backdoor route, a network call, dynamic code).
DANGEROUS = {
    "exec", "eval", "compile", "__import__", "globals", "locals", "setattr", "delattr", "vars",
    "os.system", "os.popen", "os.environ", "socket", "ctypes", "importlib", "pickle", "marshal",
    "urllib.request", "requests", "httpx", "add_url_rule", "route", "builtins", "sys.modules",
}


def _capabilities(tree: ast.AST) -> set[str]:
    found = set()
    for node in ast.walk(tree):
        name = None
        if isinstance(node, ast.Name):
            name = node.id
        elif isinstance(node, ast.Attribute):
            from ..scanner.astutil import dotted
            name = dotted(node) or node.attr
        if not name:
            continue
        for danger in DANGEROUS:
            if name == danger or name.startswith(danger + ".") or name.endswith("." + danger):
                found.add(danger)
    return found


def _shape_problem(region: Region, code: str, source: str = "") -> str | None:
    """Guardrails on the proposal itself, before the verifier runs.

    The proposal may only replace the region it was given: one function with the same name,
    signature and decorators (or one statement of the same kind at module level). It may not add
    module-level code, imports that shadow builtins, or capabilities the original did not use.
    """
    try:
        tree = ast.parse(textwrap.dedent(code))
        original = ast.parse(region.code)
    except SyntaxError as exc:
        return f"patched_code is not valid Python: {exc.msg}"
    allowed = SAFE_MODULES | set(_top_imports(source)) if source else SAFE_MODULES
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            problem = _import_problem(node, allowed)
            if problem:
                return problem
    added = _capabilities(tree) - _capabilities(original)
    if added:
        return "the patch adds capabilities a security fix does not need: " + ", ".join(sorted(added))
    if region.func_name is None:
        if len(tree.body) != 1 or len(original.body) != 1 or type(tree.body[0]) is not type(original.body[0]):
            return "patched_code must be exactly one statement replacing the original one"
        targets = lambda n: [ast.dump(t) for t in getattr(n, "targets", [getattr(n, "target", None)])]
        if targets(tree.body[0]) != targets(original.body[0]):
            return "keep the same assignment target"
        return None
    if len(tree.body) != 1:
        return f"patched_code must contain only the function {region.func_name}, with nothing before or after it"
    funcs = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if len(funcs) != 1 or funcs[0].name != region.func_name:
        return f"patched_code must contain exactly one function named {region.func_name}"
    args = [a.arg for a in funcs[0].args.posonlyargs + funcs[0].args.args + funcs[0].args.kwonlyargs]
    if args != region.func_args:
        return f"do not change the function signature; expected parameters {region.func_args}"
    if region.decorators is not None and [ast.dump(d) for d in funcs[0].decorator_list] != region.decorators:
        return "keep the decorators exactly as they were (they register the route)"
    return None


def _code_block_reply(text: str) -> dict | None:
    """Fallback when the model answers with a ```python block instead of JSON."""
    import re

    m = re.search(r"```(?:python|py)?\s*\n(.*?)```", text, re.S)
    if not m:
        return None
    return {"patched_code": m.group(1), "imports": [], "explanation": "AI patch (verified)."}


class AIFixer:
    def __init__(self, client: LLM, max_attempts: int = 3):
        self.client = client
        self.max_attempts = max_attempts
        self.log: list[dict] = []

    def fix(self, path: str, source: str, finding: Finding,
            verify_fn: Callable[[str], Verification]) -> AIOutcome:
        region = extract_region(source, finding)
        feedback = ""
        last_reason = "AI engine could not produce a verified patch."
        for attempt in range(1, self.max_attempts + 1):
            prompt = FIX_USER.format(
                file=path, title=finding.title, cwe=finding.cwe, severity=finding.severity,
                line=finding.line, snippet=finding.snippet, message=finding.message,
                imports=", ".join(_top_imports(source)) or "none",
                start=region.start, end=region.end, region=region.code.rstrip(),
                feedback=FEEDBACK.format(feedback=feedback) if feedback else "",
            )
            try:
                raw = self.client.complete(FIX_SYSTEM, prompt)
            except AIError as exc:
                self.log.append({"finding": finding.rule_id, "attempt": attempt, "error": str(exc)})
                return AIOutcome(False, attempts=attempt, reason=f"AI engine error: {exc}")
            try:
                reply = parse_json_reply(raw)
            except AIError:
                reply = None
            if not isinstance(reply, dict) or not ("patched_code" in reply or "needs_human" in reply):
                reply = _code_block_reply(raw)
                if reply is None:
                    feedback = "Reply with the JSON object described in the instructions."
                    continue
            if reply.get("needs_human"):
                why = str(reply.get("explanation") or "the fix needs changes outside this code")
                self.log.append({"finding": finding.rule_id, "attempt": attempt, "needs_human": why})
                return AIOutcome(False, attempts=attempt, reason=f"AI reviewed it and asks for a human: {why}")
            code = reply.get("patched_code")
            if not isinstance(code, str) or not code.strip():
                feedback = "patched_code is missing."
                continue
            problem = _shape_problem(region, code, source)
            imports, import_problem = _valid_imports(reply.get("imports"), source)
            problem = problem or import_problem
            if problem:
                feedback = problem
                last_reason = f"AI proposal rejected: {problem}"
                self.log.append({"finding": finding.rule_id, "attempt": attempt, "rejected": problem})
                continue
            candidate = splice(source, region, code)
            try:
                candidate = ensure_imports(candidate, imports)
            except SyntaxError:
                feedback = "The patched file does not parse."
                continue
            result = verify_fn(candidate)
            self.log.append({"finding": finding.rule_id, "attempt": attempt, "checks": result.checks})
            if result.ok:
                return AIOutcome(True, candidate, str(reply.get("explanation", "")).strip()
                                 or "AI patch (verified).", result, attempt)
            feedback = result.feedback or "verification failed"
            last_reason = f"AI patch failed verification after {attempt} attempt(s): {feedback}"
        return AIOutcome(False, attempts=self.max_attempts, reason=last_reason)
