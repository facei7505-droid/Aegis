"""Property test for the SQL fixer, on 300 generated queries:

  * the patched query returns exactly the same rows as the original for ordinary input, and
  * an injection payload can no longer change what the query returns.
Queries the fixer refuses (identifiers, ORDER BY ...) are fine; wrong patches are not.
"""
import random
import sqlite3
import textwrap

import pytest

from aegis.patcher import fix_file

ROWS = [(1, "Laptop", "fast"), (2, "Phone", "it's new"), (3, "Lamp", "50% off"), (4, "Desk", "oak")]

TEMPLATES = [
    ("SELECT id FROM t WHERE name = '{a}'", "s"),
    ("SELECT id FROM t WHERE id = {a}", "n"),
    ("SELECT id FROM t WHERE name LIKE '%{a}%'", "s"),
    ("SELECT id FROM t WHERE name LIKE '{a}%' ORDER BY id", "s"),
    ("SELECT id FROM t WHERE name = '{a}' OR note = '{b}'", "ss"),
    ("SELECT id FROM t WHERE id BETWEEN {a} AND {b}", "nn"),
    ("SELECT id FROM t WHERE name IN ('{a}', '{b}')", "ss"),
    ("SELECT id FROM t WHERE note = 'it''s {a}'", "s"),
    ("SELECT id FROM t WHERE id > {a} LIMIT {b}", "nn"),
    ("SELECT id FROM t WHERE name = '{a}' AND id <> {b}", "sn"),
    ("SELECT id FROM t ORDER BY {a}", "c"),          # identifier: must be refused
    ("SELECT {a} FROM t", "c"),                       # identifier: must be refused
]
STYLES = ["fstring", "format", "percent", "concat", "variable"]
WORDS = ["Laptop", "Phone", "Lam", "new", "50", "oak", "Desk", "zzz"]


def build(template, kinds, style):
    names = ["a", "b"][: len(kinds)]
    if style in ("fstring", "variable"):
        expr = "f" + repr(template)
    elif style == "format":
        expr = repr(template.replace("{a}", "{}").replace("{b}", "{}")) + f".format({', '.join(names)})"
    elif style == "percent":
        if "%" in template.replace("{a}", "").replace("{b}", ""):
            expr = "f" + repr(template)
        else:
            tpl = template.replace("{a}", "%s").replace("{b}", "%s")
            expr = repr(tpl) + " % (" + ", ".join(names) + ("," if len(names) == 1 else "") + ")"
    else:  # concat
        parts, rest = [], template
        for n in names:
            before, rest = rest.split("{%s}" % n, 1)
            parts += [repr(before), f"str({n})"]
        parts.append(repr(rest))
        expr = " + ".join(p for p in parts if p != "''")
    params = ", ".join(["request", "conn"] + names)
    body = f"    q = {expr}\n    return conn.execute(q).fetchall()\n" if style == "variable" else \
           f"    return conn.execute({expr}).fetchall()\n"
    return f"import sqlite3\n\n\ndef handler({params}):\n    request.GET\n{body}"


def value(kind, rnd):
    return rnd.choice(WORDS) if kind == "s" else rnd.choice([1, 2, 3]) if kind == "n" else "name"


class Req:
    GET = {}


def load(src):
    ns = {}
    exec(compile(src, "q.py", "exec"), ns)
    return ns["handler"]


@pytest.fixture(scope="module")
def conn():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE t (id INT, name TEXT, note TEXT)")
    c.executemany("INSERT INTO t VALUES (?, ?, ?)", ROWS)
    return c


def test_sql_fixer_properties(tmp_path, conn):
    rnd = random.Random(1337)
    fixed = refused = 0
    for case in range(300):
        template, kinds = rnd.choice(TEMPLATES)
        style = rnd.choice(STYLES)
        src = build(template, kinds, style)
        path = tmp_path / f"q{case}.py"
        path.write_text(src)
        report = fix_file(str(path), write=False)
        if not report.patches:
            refused += 1
            continue
        if "c" in kinds:
            pytest.fail(f"identifier was parameterized:\n{src}\n---\n{report.patched}")
        fixed += 1
        original, patched = load(src), load(report.patched)
        for _ in range(4):
            args = [value(k, rnd) for k in kinds]
            assert patched(Req, conn, *args) == original(Req, conn, *args), textwrap.dedent(f"""
                behaviour changed for {args}
                {src}
                ---
                {report.patched}""")
        if "s" in kinds:
            evil = ["x' OR '1'='1"] + [value(k, rnd) for k in kinds[1:]]
            leaked = patched(Req, conn, *evil)
            assert len(leaked) < len(ROWS), f"injection still works:\n{report.patched}"
    assert fixed > 150 and refused > 20   # both paths are exercised
