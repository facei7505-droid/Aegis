"""Deterministic fixers: turn a vulnerable AST node into safe code.

Each fixer returns a FixPlan (text edits + imports to add) or None when the
pattern is too unusual to fix safely. A None means "escalate to a human" —
Aegis never guesses.
"""
from __future__ import annotations

import ast
import copy
import re
from dataclasses import dataclass, field

from ..scanner.astutil import call_name, flatten_concat, is_constant_str

SHELL_META = set("|;&<>$`'\"\\")
GLOB_CHARS = set("*?[]~{}")
QMARK_DRIVERS = {"sqlite3", "aiosqlite", "pyodbc", "duckdb"}
PYFORMAT_DRIVERS = ("psycopg", "pymysql", "MySQLdb", "mysql", "pg8000", "django.db", "aiomysql")


@dataclass
class FixPlan:
    description: str
    edits: list[tuple[int, int, str]]
    imports: set[str] = field(default_factory=set)


# ---------------------------------------------------------- string pieces ---

def string_pieces(expr: ast.AST) -> list[tuple[str, str]] | None:
    """Split a dynamic string into [('lit', text) | ('expr', source)] pieces."""
    if isinstance(expr, ast.JoinedStr):
        out = []
        for v in expr.values:
            if isinstance(v, ast.Constant):
                out.append(("lit", v.value))
            elif isinstance(v, ast.FormattedValue):
                if v.format_spec is not None:
                    return None  # {x:>10} formats the value; a bind parameter would drop that
                out.append(("expr", ast.unparse(v.value)))
        return out
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        out = []
        for part in flatten_concat(expr):
            if is_constant_str(part):
                out.append(("lit", part.value))
            else:
                out.append(("expr", ast.unparse(part)))
        return out
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod) and is_constant_str(expr.left):
        fmt = expr.left.value
        values = expr.right.elts if isinstance(expr.right, ast.Tuple) else [expr.right]
        specs = re.findall(r"%.", fmt)
        if any(s not in ("%s", "%d", "%r", "%i", "%f") for s in specs) or len(specs) != len(values):
            return None
        lits = re.split(r"%[sdrif]", fmt)
        out = []
        for i, lit in enumerate(lits):
            out.append(("lit", lit))
            if i < len(values):
                out.append(("expr", ast.unparse(values[i])))
        return out
    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr == "format"
        and is_constant_str(expr.func.value)
        and not expr.keywords
    ):
        fmt = expr.func.value.value
        if re.search(r"\{[^}\d]|\}\}", fmt) or any(isinstance(a, ast.Starred) for a in expr.args):
            return None  # {name}, {{ escapes, {0:>5} specs, *args: not a plain positional mapping
        holes = re.findall(r"\{(\d*)\}", fmt)
        if all(h == "" for h in holes):
            order = list(range(len(holes)))
        elif all(h != "" for h in holes):
            order = [int(h) for h in holes]  # '{1} ... {0}': values follow the numbers, not the order
        else:
            return None
        if any(i >= len(expr.args) for i in order) or (not holes and expr.args):
            return None
        lits = re.split(r"\{\d*\}", fmt)
        out = []
        for i, lit in enumerate(lits):
            out.append(("lit", lit))
            if i < len(order):
                out.append(("expr", ast.unparse(expr.args[order[i]])))
        return out
    return None


def _fstring(parts: list[tuple[str, str]]) -> str:
    values: list[ast.AST] = []
    for kind, text in parts:
        if kind == "lit":
            values.append(ast.Constant(text))
        else:
            values.append(ast.FormattedValue(ast.parse(text, mode="eval").body, -1, None))
    return ast.unparse(ast.JoinedStr(values))


# ------------------------------------------------------------- SQL (089) ---

VALUE_CONTEXT = re.compile(
    r"(=|<>|!=|<=|>=|<|>|\blike|\bilike|\bglob|\bbetween|\blimit|\boffset|\bthen|\belse)$", re.I
)


def _value_position(prefix: str, quoted: bool = False) -> bool:
    """Can a bind parameter stand here? Placeholders replace values, never table/column names."""
    text = prefix.rstrip()
    low = text.lower()
    if re.search(r"\band$", low):
        return bool(re.search(r"\bbetween\s+\S+\s+and$", low))
    if text.endswith((",", "(")):
        # VALUES (...) always; IN (...) only for a quoted literal: an unquoted {ids} may hold "1,2,3"
        list_start = low.rfind("values")
        if quoted:
            list_start = max(list_start, low.rfind(" in ("), low.rfind(" in("))
        clause_start = max(low.rfind("select "), low.rfind("order by"), low.rfind("group by"), low.rfind(" from "))
        return list_start != -1 and list_start > clause_start
    return bool(VALUE_CONTEXT.search(text))


def _open_string(text: str) -> tuple[str | None, int]:
    """(quote, index where it opened) for a SQL string still open at the end of `text`.

    Doubled quotes ('it''s') are escapes inside a string and do not close it.
    """
    state, start, i = None, -1, 0
    while i < len(text):
        ch = text[i]
        if state is None:
            if ch in ("'", '"'):
                state, start = ch, i
        elif ch == state:
            if i + 1 < len(text) and text[i + 1] == state:
                i += 2
                continue
            state, start = None, -1
        i += 1
    return state, start


def _closing_quote(text: str, quote: str) -> int:
    """Index of the quote that closes an open SQL string inside `text`, skipping doubled quotes."""
    i = 0
    while i < len(text):
        if text[i] == quote:
            if i + 1 < len(text) and text[i + 1] == quote:
                i += 2
                continue
            return i
        i += 1
    return -1


def parameterize(expr: ast.AST, placeholder: str) -> tuple[str, list[str]] | None:
    """Turn a formatted SQL string into (template with placeholders, parameter expressions).

    Values inside a quoted SQL literal become ONE parameter holding the whole literal:
    "name LIKE '%{q}%'" -> "name LIKE ?" with f"%{q}%". Identifiers, keywords and
    double-quoted names are refused, because a placeholder cannot stand there.
    """
    pieces = string_pieces(expr)
    if pieces is None:
        return None
    template = ""
    params: list[str] = []
    i = 0
    while i < len(pieces):
        kind, text = pieces[i]
        if kind == "lit":
            template += text
            i += 1
            continue
        state, open_at = _open_string(template)
        if state == '"':
            return None  # "{x}" is a quoted identifier in standard SQL
        if state is None:
            if not _value_position(template):
                return None  # identifier or keyword position: needs an allow-list, not a placeholder
            template += placeholder
            params.append(text)
            i += 1
            continue
        # Inside a '...' literal: everything up to the closing quote becomes one parameter.
        before, head = template[:open_at], template[open_at + 1:]
        if not _value_position(before, quoted=True):
            return None
        parts: list[tuple[str, str]] = [("lit", head.replace("''", "'"))] if head else []
        j, rest = i, None
        while j < len(pieces):
            k, t = pieces[j]
            j += 1
            if k == "expr":
                parts.append(("expr", t))
                continue
            close = _closing_quote(t, "'")
            if close == -1:
                parts.append(("lit", t.replace("''", "'")))
                continue
            if close:
                parts.append(("lit", t[:close].replace("''", "'")))
            rest = t[close + 1:]
            break
        if rest is None:
            return None  # the SQL string never closes: we do not understand this query
        template = before + placeholder + rest
        params.append(parts[0][1] if len(parts) == 1 and parts[0][0] == "expr" else _fstring(parts))
        i = j
    if placeholder == "%s" and "%" in template.replace("%s", ""):
        return None  # literal % would be misread by pyformat drivers
    if not params:
        return None
    return template, params


def _placeholder(tree: ast.Module) -> str | None:
    """'?' for qmark drivers (sqlite3), '%s' for pyformat drivers (psycopg, PyMySQL, Django).

    None when the file imports neither or both: a wrong placeholder breaks every query, so the
    finding goes to Claude or a human instead of a guess.
    """
    pyformat = qmark = False
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] + ([node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
            pyformat |= any(n and n.startswith(PYFORMAT_DRIVERS) for n in names)
            qmark |= any(n and n.split(".")[0] in QMARK_DRIVERS for n in names)
    if pyformat == qmark:
        return None
    return "%s" if pyformat else "?"


def _sql_literal(template: str, original: str) -> str:
    """Keep a multi-line query readable: reuse triple quotes when the original had them."""
    m = re.match(r"\s*[rRbBuUfF]{0,2}('\'\'|\"\"\")", original)
    if m and "\\" not in template and m.group(1) not in template and not template.endswith(m.group(1)[0]):
        return m.group(1) + template + m.group(1)
    return repr(template)


# Calls whose second positional argument is not the parameters (pandas: con), or that take none.
NO_PARAMS = {"text", "executescript", "read_sql", "read_sql_query", "read_sql_table"}


def fix_sql(node: ast.AST, ctx) -> FixPlan | None:
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or len(node.args) != 1:
        return None
    if node.func.attr in NO_PARAMS or any(kw.arg in ("params", "parameters", "args", None) for kw in node.keywords):
        return None
    arg = node.args[0]
    query = ctx.taint.resolve(arg, strict=True)
    placeholder = _placeholder(ctx.tree)
    if query is None or placeholder is None:
        return None
    result = parameterize(query, placeholder)
    if result is None:
        return None
    template, params = result
    if not params:
        return None
    params_src = "(" + ", ".join(params) + ("," if len(params) == 1 else "") + ")"
    edits = []
    literal = _sql_literal(template, ctx.sm.segment(query))
    # Only the query argument is replaced, so keyword arguments (timeout=, etc.) stay as they were.
    if query is arg:
        edits.append((*ctx.sm.span(arg), f"{literal}, {params_src}"))
    else:
        edits.append((*ctx.sm.span(query), literal))
        edits.append((*ctx.sm.span(arg), f"{ctx.sm.segment(arg)}, {params_src}"))
    return FixPlan(
        f"Parameterized the SQL query: {len(params)} value(s) are now sent separately from the SQL text, "
        "so input can never change the query structure.",
        edits,
    )


# --------------------------------------------------------- command (078) ---

def build_argv(pieces: list[tuple[str, str]]) -> str | None:
    """Turn a shell command string into a Python argv list, or None if unsafe.

    Simple quoting ("path with spaces") is understood; pipes, redirects,
    variables and escapes are not, because their meaning would change.
    """
    pieces = [p for p in pieces if p != ("lit", "")]  # '{}{}'.format(a, b) leaves empty literals between values
    tokens: list[list[tuple[str, str]]] = []
    current: list[tuple[str, str]] = []
    quote: str | None = None
    opened = False  # an empty quoted token ("") still counts as an argument
    for i, (kind, text) in enumerate(pieces):
        if kind == "expr":
            if i > 0 and pieces[i - 1][0] == "expr":
                return None  # two values glued together: we cannot know where one argument ends
            current.append(("expr", text))
            continue
        buf = ""
        for ch in text:
            if quote:
                if ch == quote:
                    quote = None
                elif quote == '"' and ch in "$`\\":
                    return None  # expansions still happen inside double quotes
                else:
                    buf += ch
                continue
            if ch in ("'", '"'):
                quote, opened = ch, True
            elif ch in SHELL_META or ch in GLOB_CHARS:
                return None  # *.conf, ~/x, {a,b}: the shell expands these, an argument list would not
            elif ch.isspace():
                if buf:
                    current.append(("lit", buf))
                    buf = ""
                if current or opened:
                    tokens.append(current or [("lit", "")])
                    current, opened = [], False
            else:
                buf += ch
        if buf:
            current.append(("lit", buf))
    if quote:
        return None  # unbalanced quotes
    if current or opened:
        tokens.append(current or [("lit", "")])
    elements = []
    for tok in tokens:
        merged: list[tuple[str, str]] = []
        for kind, text in tok:
            if merged and kind == "lit" and merged[-1][0] == "lit":
                merged[-1] = ("lit", merged[-1][1] + text)
            else:
                merged.append((kind, text))
        if len(merged) == 1 and merged[0][0] == "lit":
            elements.append(repr(merged[0][1]))
        elif len(merged) == 1:
            expr = merged[0][1]
            # str() keeps the argv valid for ints and Path objects (PORT = 8080, BASE / "x").
            elements.append(expr if expr == "sys.executable" else f"str({expr})")
        else:
            elements.append(_fstring(merged))
    if not elements:
        return None
    return "[" + ", ".join(elements) + "]"


def _loads(function: ast.AST | None, name: str) -> int:
    """How many times a variable is read in a function."""
    if function is None:
        return 0
    return sum(1 for n in ast.walk(function) if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load))


TRUSTED_EXPR = re.compile(r"[A-Z_][A-Z0-9_]*|sys\.executable")


def program_is_fixed(pieces: list[tuple[str, str]]) -> bool:
    """Is the program (first word) of a command chosen by the code rather than by input?

    If input picks the program, an argument list still runs whatever the attacker names, so the
    command is not fixed by dropping the shell and has to go to a human.
    """
    quote, started = None, False
    for kind, text in pieces:
        if kind == "expr":
            if not TRUSTED_EXPR.fullmatch(text):
                return False
            started = True
            continue
        for ch in text:
            if quote:
                quote = None if ch == quote else quote
            elif ch in ("'", '"'):
                quote, started = ch, True
            elif ch.isspace():
                if started:
                    return True
            else:
                started = True
    return started


def fix_command(node: ast.AST, ctx) -> FixPlan | None:
    if not isinstance(node, ast.Call) or not node.args:
        return None
    name = call_name(node)
    arg = node.args[0]
    imports = {"subprocess"}
    # Rewriting a command changes how it is parsed. That trade is only automatic when an attacker
    # controls part of it; internal commands (EDITOR="code --wait", Windows .cmd shims) need a human.
    if not ctx.taint.expr(ctx.taint.resolve(arg)):
        return None
    if isinstance(arg, (ast.List, ast.Tuple)):
        if not (name or "").startswith("subprocess.") or not arg.elts:
            return None
        program = arg.elts[0]
        if not isinstance(program, ast.Constant) and ctx.taint.expr(ctx.taint.resolve(program)):
            return None
        argv = ctx.sm.segment(arg)  # already an argument list: only the shell has to go
    else:
        pieces = string_pieces(arg)
        if pieces is not None:
            argv = build_argv(pieces) if program_is_fixed(pieces) else None
            if argv is None:
                return None
        else:
            # A variable holding the command: split it at run time, but only when we can see that
            # the code (not the request) chose the program.
            # A variable holding the command. Splitting it at run time (shlex.split) would let a value
            # with spaces add arguments (`url="x -o /tmp/f"`), so the argument list is built where the
            # command is assigned, and only when nothing else uses the string.
            command = ctx.taint.resolve(arg, strict=True)
            built = string_pieces(command) if command is not None else None
            if built is None or not program_is_fixed(built) or not isinstance(arg, ast.Name):
                return None
            argv = build_argv(built)
            if argv is None or _loads(ctx.function, arg.id) != 1:
                return None
            if name == "os.system":
                return None
            shell_kw = next(kw for kw in node.keywords if kw.arg == "shell")
            return FixPlan(
                "Built the command as an argument list with shell=False, so user input can no longer inject "
                "shell commands or extra arguments.",
                [(*ctx.sm.span(command), argv), (*ctx.sm.span(shell_kw.value), "False")],
                imports,
            )
    if name == "os.system":
        return FixPlan(
            "Replaced os.system() with subprocess.run() and an argument list: no shell is started, "
            "so ; && | are passed as plain text.",
            [(*ctx.sm.span(node), f"subprocess.run({argv}).returncode")],
            imports,
        )
    if name and name.startswith("subprocess."):
        shell_kw = next(kw for kw in node.keywords if kw.arg == "shell")
        return FixPlan(
            "Switched to shell=False with an argument list, so user input can no longer inject shell commands.",
            [(*ctx.sm.span(arg), argv), (*ctx.sm.span(shell_kw.value), "False")],
            imports,
        )
    return None


# ------------------------------------------------------------ eval (095) ---

def fix_eval(node: ast.AST, ctx) -> FixPlan | None:
    # literal_eval takes exactly one argument, and replacing eval() only makes sense where the
    # input comes from a user (internal code generation legitimately needs eval).
    if not isinstance(node, ast.Call) or call_name(node) != "eval" or len(node.args) != 1 or node.keywords:
        return None
    if not ctx.taint.expr(node.args[0]):
        return None
    return FixPlan(
        "Replaced eval() with ast.literal_eval(), which only accepts plain Python literals and cannot run code.",
        [(*ctx.sm.span(node.func), "ast.literal_eval")],
        {"ast"},
    )


# ------------------------------------------------------------ yaml (502) ---

def fix_deserialization(node: ast.AST, ctx) -> FixPlan | None:
    if not isinstance(node, ast.Call) or call_name(node) != "yaml.load" or not node.args:
        return None
    explicit_loader = len(node.args) > 1 or any(kw.arg == "Loader" for kw in node.keywords)
    if explicit_loader and not ctx.taint.expr(node.args[0]):
        return None  # someone chose an unsafe loader on purpose for trusted data: ask a human
    return FixPlan(
        "Replaced yaml.load() with yaml.safe_load(), which only builds plain data types.",
        [(*ctx.sm.span(node), f"yaml.safe_load({ctx.sm.segment(node.args[0])})")],
    )


# -------------------------------------------------------- traversal (022) ---

def wrap_tainted(expr: ast.AST, taint, wrapper: str, coerce_str: bool = False) -> tuple[ast.AST, int]:
    """Wrap only the attacker-controlled leaves of a string or path expression.

    `UP / name` becomes `UP / basename(name)` (the base folder stays), and `f"{amount:.2f}"` becomes
    `f"{escape(format(amount, '.2f'))}"`, so formatting happens before escaping.
    """
    expr = copy.deepcopy(expr)
    count = 0

    def wrap(value: ast.AST) -> ast.AST:
        nonlocal count
        count += 1
        if coerce_str:
            value = ast.Call(ast.Name("str"), [value], [])
        return ast.Call(ast.parse(wrapper, mode="eval").body, [value], [])

    def visit(node: ast.AST) -> ast.AST:
        if not taint.expr(node):
            return node
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue) and taint.expr(v.value):
                    inner = v.value
                    if v.conversion != -1:
                        inner = ast.Call(ast.Name({114: "repr", 97: "ascii"}.get(v.conversion, "str")), [inner], [])
                    if v.format_spec is not None:
                        inner = ast.Call(ast.Name("format"), [inner, v.format_spec], [])
                    v.value, v.conversion, v.format_spec = wrap(inner), -1, None
            return node
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
            node.left, node.right = visit(node.left), visit(node.right)
            return node
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and is_constant_str(node.left):
            if isinstance(node.right, ast.Tuple):
                node.right.elts = [wrap(v) if taint.expr(v) else v for v in node.right.elts]
            else:
                node.right = wrap(node.right)
            return node
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"
                and is_constant_str(node.func.value) and not node.keywords):
            node.args = [wrap(a) if taint.expr(a) else a for a in node.args]
            return node
        if isinstance(node, ast.Call) and call_name(node) in ("os.path.join", "posixpath.join", "ntpath.join"):
            node.args = [wrap(a) if taint.expr(a) else a for a in node.args]
            return node
        return wrap(node)

    return visit(expr), count


def fix_path(node: ast.AST, ctx) -> FixPlan | None:
    if not isinstance(node, ast.Call) or not node.args:
        return None
    arg = node.args[0]
    target = ctx.taint.resolve(arg, strict=True)
    if target is None:
        return None
    new, count = wrap_tainted(target, ctx.taint, "os.path.basename")
    if not count:
        return None
    return FixPlan(
        "Reduced the user-supplied part of the path to a bare file name with os.path.basename(), "
        "so '../' can no longer leave the intended folder.",
        [(*ctx.sm.span(target), ast.unparse(new))],
        {"os"},
    )


# ---------------------------------------------------------- secrets (798) ---

def _env_name(target: ast.AST) -> str | None:
    if isinstance(target, ast.Name):
        raw = target.id
    elif isinstance(target, ast.Attribute):
        raw = target.attr
    elif isinstance(target, ast.Subscript) and is_constant_str(target.slice):
        raw = target.slice.value
    else:
        return None
    return re.sub(r"[^A-Za-z0-9]+", "_", raw).upper()


def fix_secret(node: ast.AST, ctx) -> FixPlan | None:
    if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
        return None
    env = _env_name(node.targets[0] if isinstance(node, ast.Assign) else node.target)
    if not env:
        return None
    return FixPlan(
        f"Moved the secret out of the code: it is now read from the {env} environment variable. Set {env} "
        "before the next start (the app stops with KeyError instead of running with a missing secret), "
        "and rotate the old value: it is already in git history.",
        [(*ctx.sm.span(node.value), f'os.environ["{env}"]')],
        {"os"},
    )


# ------------------------------------------------------------ debug (489) ---

def fix_debug(node: ast.AST, ctx) -> FixPlan | None:
    if not isinstance(node, ast.Call):
        return None
    kw = next((k for k in node.keywords if k.arg == "debug"), None)
    if kw is None:
        return None
    return FixPlan("Turned off debug mode for production.", [(*ctx.sm.span(kw.value), "False")])


# -------------------------------------------------------------- xss (079) ---

def fix_xss(node: ast.AST, ctx) -> FixPlan | None:
    value = node.value if isinstance(node, ast.Return) else (node.args[0] if isinstance(node, ast.Call) and node.args else None)
    if isinstance(value, ast.Tuple) and value.elts:  # return body, 200
        value = value.elts[0]
    if value is None:
        return None
    target = ctx.taint.resolve(value, strict=True)
    if target is None:
        return None
    new, count = wrap_tainted(target, ctx.taint, "html.escape", coerce_str=True)
    if not count:
        return None
    return FixPlan(
        f"HTML-escaped {count} user-controlled value(s) with html.escape(), so <script> becomes harmless text.",
        [(*ctx.sm.span(target), ast.unparse(new))],
        {"html"},
    )


# ------------------------------------------------------------- ssti (1336) --

SSTI_RESERVED = {
    "source", "template_name_or_list", "context", "self", "super", "loop", "caller", "varargs", "kwargs",
    "range", "dict", "lipsum", "cycler", "joiner", "namespace", "true", "false", "none",
    "request", "session", "g", "config", "url_for", "get_flashed_messages",
}


def fix_ssti(node: ast.AST, ctx) -> FixPlan | None:
    if not isinstance(node, ast.Call) or not node.args:
        return None
    arg = node.args[0]
    template = ctx.taint.resolve(arg, strict=True)
    if template is None:
        return None
    pieces = string_pieces(template)
    if pieces is None:
        return None
    parts: list[str] = []
    kwargs: list[str] = []
    n = 0
    # Names that are render_template_string's own parameters or that templates already rely on.
    used: set[str] = {k.arg for k in node.keywords if k.arg} | SSTI_RESERVED
    for kind, text in pieces:
        if kind == "lit":
            parts.append(text)
            continue
        var = text if text.isidentifier() and text not in used else f"v{n}"
        while var in used:
            n += 1
            var = f"v{n}"
        used.add(var)
        # Input becomes an auto-escaped variable. Values the code itself supplies (a menu, a
        # snippet of HTML) keep rendering as HTML, as they did before, but are no longer compiled.
        trusted = not ctx.taint.expr(ast.parse(text, mode="eval").body)
        parts.append("{{ %s|safe }}" % var if trusted else "{{ %s }}" % var)
        kwargs.append(f"{var}={text}")
        n += 1
    if not kwargs:
        return None
    existing = [ctx.sm.segment(k) for k in node.keywords]
    func_src = ctx.sm.segment(node.func)
    call_src = f"{func_src}({{tpl}}, {', '.join(existing + kwargs)})"
    tpl = repr("".join(parts))
    edits = []
    if template is arg:
        edits.append((*ctx.sm.span(node), call_src.replace("{tpl}", tpl)))
    else:
        edits.append((*ctx.sm.span(template), tpl))
        edits.append((*ctx.sm.span(node), call_src.replace("{tpl}", ctx.sm.segment(arg))))
    return FixPlan(
        "User input is now passed to the template as data (Jinja variables, auto-escaped) instead of being "
        "compiled as template code.",
        edits,
    )


FIXERS = {
    "AEG001": fix_sql,
    "AEG002": fix_command,
    "AEG003": fix_eval,
    "AEG004": fix_deserialization,
    "AEG005": fix_path,
    "AEG006": fix_secret,
    "AEG007": fix_debug,
    "AEG008": fix_xss,
    "AEG009": fix_ssti,
}
