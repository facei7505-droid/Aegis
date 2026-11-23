"""Detection rules. Each rule looks at one AST node inside its context.

Rules only *detect*. Fixes live in `aegis.patcher.fixes` and are keyed by rule id.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Callable, Optional

from .astutil import call_name, dotted, is_constant_str, is_dynamic_string

SQL_METHODS = {"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query"}
SQL_TEXT = {"sqlalchemy.text", "sqlalchemy.sql.text", "sqlalchemy.sql.expression.text", "sa.text", "db.text"}
SHELL_FUNCS = {"os.system", "os.popen", "commands.getoutput"}
SUBPROCESS_FUNCS = {
    "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.Popen",
}
FILE_FUNCS = {"open", "send_file", "flask.send_file", "os.remove", "os.unlink", "shutil.rmtree", "pathlib.Path", "Path",
              "io.open", "FileResponse", "fastapi.responses.FileResponse", "starlette.responses.FileResponse",
              "django.http.FileResponse"}
HTML_RESPONSES = {"make_response", "flask.make_response", "Response", "flask.Response", "HttpResponse",
                  "django.http.HttpResponse", "HTMLResponse", "fastapi.responses.HTMLResponse",
                  "starlette.responses.HTMLResponse"}
SSRF_FUNCS = {
    "requests.get", "requests.post", "requests.put", "requests.delete", "requests.request",
    "urllib.request.urlopen", "urlopen", "httpx.get", "httpx.post",
}
SECRET_NAME = re.compile(
    r"(?i)(^|_)(secret(_key)?|client_secret|passw(or)?d|pwd|api_?key|access_?key|private_?key|"
    r"auth_?token|access_?token|refresh_?token|bot_?token|token|secret_?token)$"
)
NOT_SECRET_SUFFIX = re.compile(
    r"(?i)_(type|name|names|url|uri|path|file|field|length|len|prefix|label|header|param|pattern|regex|re|"
    r"endpoint|id|count|expiry|expires|ttl|timeout|min|max|hint|policy|format|kind)$"
)
SECRET_PLACEHOLDERS = {"", "changeme", "change-me", "change_me", "todo", "xxx", "none", "secret", "password",
                       "your-secret-key", "your_api_key", "dummy", "example", "test", "testing"}
KNOWN_KEY = re.compile(
    r"(sk_(live|test)_[0-9a-zA-Z]{10,}|ghp_[0-9A-Za-z]{20,}|github_pat_[0-9A-Za-z_]{20,}|AKIA[0-9A-Z]{16}|"
    r"xox[abpr]-[0-9A-Za-z-]{10,}|AIza[0-9A-Za-z_\-]{30,}|sk-ant-[0-9A-Za-z_\-]{20,}|"
    r"\d{8,10}:[0-9A-Za-z_-]{35}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)"
)


@dataclass
class Match:
    message: str
    tainted: bool
    severity: str | None = None  # overrides the rule default when set


@dataclass
class Rule:
    id: str
    title: str
    cwe: str
    severity: str           # severity when attacker-controlled data reaches the sink
    severity_untainted: str  # severity when the value is dynamic but not proven tainted
    check: Callable[[ast.AST, "object"], Optional[Match]]


# ---------------------------------------------------------------- checks ----

def names(node: ast.AST, ctx) -> set[str]:
    """The call's name as written and as imported (`sp.run` is also `subprocess.run`)."""
    raw = call_name(node) if isinstance(node, ast.Call) else None
    if not raw:
        return set()
    out = {raw}
    head, _, rest = raw.partition(".")
    real = (getattr(ctx, "aliases", None) or {}).get(head)
    if real:
        out.add(real + ("." + rest if rest else ""))
    return out


def _sql_injection(node, ctx):
    if not isinstance(node, ast.Call) or not node.args:
        return None
    method = isinstance(node.func, ast.Attribute) and node.func.attr in SQL_METHODS
    if not (method or names(node, ctx) & SQL_TEXT):
        return None
    arg = node.args[0]
    query = ctx.taint.resolve(arg)
    # `sql += f"... {q}"` leaves the first assignment constant: a tainted query variable is enough.
    tainted_name = isinstance(arg, ast.Name) and ctx.taint.expr(arg)
    if not (is_dynamic_string(query) or tainted_name):
        return None
    tainted = ctx.taint.expr(query) or tainted_name
    return Match(
        "SQL query is built with string formatting"
        + (" from user input" if tainted else "")
        + "; an attacker can change the query logic.",
        tainted,
    )


def _command_injection(node, ctx):
    if not isinstance(node, ast.Call):
        return None
    called = names(node, ctx)
    if called & SHELL_FUNCS and node.args and not is_constant_str(node.args[0]):
        arg = node.args[0]
    elif called & SUBPROCESS_FUNCS and node.args and _kw_true(node, "shell") and not is_constant_str(node.args[0]):
        arg = node.args[0]
    else:
        return None
    resolved = ctx.taint.resolve(arg)
    tainted = ctx.taint.expr(resolved)
    if tainted or is_dynamic_string(resolved):
        return Match(
            "Shell command is assembled from a dynamic string"
            + (" containing user input" if tainted else "")
            + "; shell metacharacters (; && |) let an attacker run any command.",
            tainted,
        )
    return Match(
        "A command held in a variable is run through the shell; if it can ever contain user input, "
        "an attacker can run any command. Prefer an argument list without shell=True.",
        False,
        "medium",
    )


def _code_injection(node, ctx):
    if not (isinstance(node, ast.Call) and names(node, ctx) & {"eval", "exec", "builtins.eval", "builtins.exec"}
            and node.args):
        return None
    if is_constant_str(node.args[0]):
        return None
    tainted = ctx.taint.expr(node.args[0])
    return Match(f"{call_name(node)}() runs arbitrary Python code from a dynamic value.", tainted)


def _deserialization(node, ctx):
    if not isinstance(node, ast.Call):
        return None
    called = names(node, ctx)
    if called & {"pickle.loads", "pickle.load", "marshal.loads", "dill.loads", "cPickle.loads"}:
        tainted = any(ctx.taint.expr(a) for a in node.args)
        return Match("Unpickling data can execute code; never unpickle untrusted input.", tainted)
    if called & {"yaml.unsafe_load", "yaml.unsafe_load_all"}:
        tainted = any(ctx.taint.expr(a) for a in node.args)
        return Match("yaml.unsafe_load can construct arbitrary Python objects.", tainted)
    if "yaml.load" in called:
        loader = next((kw.value for kw in node.keywords if kw.arg == "Loader"), None)
        if loader is None and len(node.args) > 1:
            loader = node.args[1]
        if loader is None or (dotted(loader) or "").split(".")[-1] in {"Loader", "UnsafeLoader", "FullLoader"}:
            tainted = any(ctx.taint.expr(a) for a in node.args)
            return Match("yaml.load without SafeLoader can construct arbitrary objects.", tainted)
    return None


def _path_traversal(node, ctx):
    if not (isinstance(node, ast.Call) and names(node, ctx) & FILE_FUNCS and node.args):
        return None
    arg = ctx.taint.resolve(node.args[0])
    if isinstance(arg, ast.Call) and (call_name(arg) or "").split(".")[-1] in {"BytesIO", "StringIO"}:
        return None  # an in-memory file object, not a path
    if not ctx.taint.expr(arg):
        return None
    return Match("File path comes from user input; '../' sequences can escape the intended folder.", True)


def _entropy(value: str) -> float:
    from collections import Counter
    from math import log2

    counts = Counter(value)
    return -sum(c / len(value) * log2(c / len(value)) for c in counts.values())


def _looks_like_secret(value: str) -> bool:
    if KNOWN_KEY.search(value):
        return True
    if len(value) < 8 or any(ch.isspace() for ch in value) or value.strip().lower() in SECRET_PLACEHOLDERS:
        return False
    if any(ch in value for ch in "[]{}()|^\\<>") or value.startswith(("http://", "https://", "/", "./")):
        return False  # regexes, templates, URLs and paths are not credentials
    has_digit = any(ch.isdigit() for ch in value)
    has_alpha = any(ch.isalpha() for ch in value)
    return (has_digit and has_alpha) or _entropy(value) >= 3.2


def _hardcoded_secret(node, ctx):
    if not isinstance(node, (ast.Assign, ast.AnnAssign)) or not is_constant_str(node.value):
        return None
    value = node.value.value
    if KNOWN_KEY.search(value):
        return Match("A credential with a known key format (cloud/API/bot token) is hardcoded in source code.", False)
    for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
        name = _target_name(target)
        if name and SECRET_NAME.search(name) and not NOT_SECRET_SUFFIX.search(name) and _looks_like_secret(value):
            return Match(f"Secret '{name}' is hardcoded in source code and leaks with the repository.", False)
    return None


def _debug_mode(node, ctx):
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "run"):
        return None
    for kw in node.keywords:
        if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return Match("Debug mode exposes an interactive debugger that allows remote code execution.", False)
    return None


def _xss(node, ctx):
    # No route check: taint only exists inside request handling (routes, views, MethodView methods).
    value = None
    if isinstance(node, ast.Return):
        value = node.value
        if isinstance(value, ast.Tuple) and value.elts:  # return body, 200
            value = value.elts[0]
    elif isinstance(node, ast.Call) and names(node, ctx) & HTML_RESPONSES and node.args:
        value = node.args[0]
    value = ctx.taint.resolve(value) if value is not None else None
    if value is None or not is_dynamic_string(value) or not ctx.taint.expr(value):
        return None
    literal = "".join(
        p.value for p in ast.walk(value) if isinstance(p, ast.Constant) and isinstance(p.value, str)
    )
    if "<" not in literal:
        return None
    return Match("User input is inserted into HTML without escaping (reflected XSS).", True)


def _ssti(node, ctx):
    if not (isinstance(node, ast.Call) and any(n.endswith("render_template_string") for n in names(node, ctx))
            and node.args):
        return None
    template = ctx.taint.resolve(node.args[0])
    if not ctx.taint.expr(template):
        return None
    return Match(
        "User input becomes part of a Jinja template; '{{ ... }}' lets an attacker execute code on the server.",
        True,
    )


def _weak_hash(node, ctx):
    if isinstance(node, ast.Call) and names(node, ctx) & {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}:
        if any(kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant) and kw.value.value is False
               for kw in node.keywords):
            return None  # the code says this is a checksum, not security
        return Match("MD5/SHA-1 are broken for security use; passwords need bcrypt/argon2/scrypt.", False)
    return None


def _ssrf(node, ctx):
    if not (isinstance(node, ast.Call) and names(node, ctx) & SSRF_FUNCS and node.args):
        return None
    if not ctx.taint.expr(ctx.taint.resolve(node.args[0])):
        return None
    return Match("Server fetches a URL chosen by the user (SSRF); internal services become reachable.", True)


# --------------------------------------------------------------- helpers ----

def _kw_true(call: ast.Call, name: str) -> bool:
    return any(
        kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is True
        for kw in call.keywords
    )


def _target_name(target: ast.AST) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript) and is_constant_str(target.slice):
        return target.slice.value
    return None


RULES: list[Rule] = [
    Rule("AEG001", "SQL injection", "CWE-89", "critical", "medium", _sql_injection),
    Rule("AEG002", "OS command injection", "CWE-78", "critical", "high", _command_injection),
    Rule("AEG003", "Code injection (eval/exec)", "CWE-95", "critical", "medium", _code_injection),
    Rule("AEG004", "Insecure deserialization", "CWE-502", "critical", "medium", _deserialization),
    Rule("AEG005", "Path traversal", "CWE-22", "high", "high", _path_traversal),
    Rule("AEG006", "Hardcoded secret", "CWE-798", "high", "high", _hardcoded_secret),
    Rule("AEG007", "Debug mode enabled", "CWE-489", "medium", "medium", _debug_mode),
    Rule("AEG008", "Reflected XSS", "CWE-79", "high", "high", _xss),
    Rule("AEG009", "Server-side template injection", "CWE-1336", "critical", "critical", _ssti),
    Rule("AEG010", "Weak hash function", "CWE-328", "medium", "medium", _weak_hash),
    Rule("AEG011", "Server-side request forgery", "CWE-918", "high", "high", _ssrf),
]

RULES_BY_ID = {r.id: r for r in RULES}
