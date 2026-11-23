"""Property test for the command-injection fixer, on 200 generated commands.

For every command the fixer rewrites:
  * ordinary input produces exactly the same output as before, and
  * shell payloads ( ; && | $( ) ` ) are passed as text and never run.
Commands it must refuse (input picks the program, pipes, glued values) must stay untouched.
"""
import random
import subprocess
import sys

import pytest

from aegis.patcher import fix_file

TEMPLATES = [
    ("echo hello {a}", "fix"),
    ("echo '{a}' done", "fix"),
    ('echo "{a}" "{b}"', "fix"),
    ("echo --{a}-- {b}", "fix"),
    ("printf %s- {a}", "fix"),
    ("ls /etc/*.conf {a}", "refuse"),     # glob: an argument list would not expand it
    ("{a} --version", "refuse"),        # input chooses the program
    ("echo {a} | tr a-z A-Z", "refuse"),  # pipe: meaning would change
    ("echo {a}{b}", "refuse"),          # two values glued: argument boundary unknown
]
STYLES = ["fstring", "format", "concat", "variable", "check_output"]
WORDS = ["Laptop", "42", "a.txt", "x-y", "dir/file", "N0de"]
EVIL = ["x; touch {c}", "x && touch {c}", "$(touch {c})", "`touch {c}`", "x | touch {c}"]


def build(template, style):
    names = [n for n in ("a", "b") if "{%s}" % n in template]
    if style == "format" and "%" not in template:
        expr = repr(template.replace("{a}", "{}").replace("{b}", "{}")) + f".format({', '.join(names)})"
    elif style == "concat":
        parts, rest = [], template
        for n in names:
            before, rest = rest.split("{%s}" % n, 1)
            parts += [repr(before), n]
        parts.append(repr(rest))
        expr = " + ".join(p for p in parts if p != "''")
    else:
        expr = "f" + repr(template)
    call = (f"subprocess.check_output({{q}}, shell=True, text=True)" if style == "check_output"
            else "subprocess.run({q}, shell=True, capture_output=True, text=True).stdout")
    if style == "variable":
        body = f"    cmd = {expr}\n    return {call.format(q='cmd')}\n"
    else:
        body = f"    return {call.format(q=expr)}\n"
    return f"import subprocess\n\n\ndef handler(request, a='', b=''):\n    request.GET\n{body}"


class Req:
    GET = {}


def load(src):
    ns = {}
    exec(compile(src, "cmd.py", "exec"), ns)
    return ns["handler"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell semantics")
def test_command_fixer_properties(tmp_path):
    rnd = random.Random(7)
    fixed = refused = 0
    for case in range(200):
        template, expect = rnd.choice(TEMPLATES)
        style = rnd.choice(STYLES)
        src = build(template, style)
        path = tmp_path / f"c{case}.py"
        path.write_text(src)
        report = fix_file(str(path), write=False)
        if expect == "refuse":
            assert not report.patches, f"unsafe rewrite:\n{src}\n---\n{report.patched}"
            refused += 1
            continue
        assert report.patches, f"expected a fix:\n{src}"
        fixed += 1
        original, patched = load(src), load(report.patched)
        for _ in range(3):
            a, b = rnd.choice(WORDS), rnd.choice(WORDS)
            assert patched(Req, a, b) == original(Req, a, b), f"behaviour changed for {a!r}, {b!r}\n{report.patched}"
        canary = tmp_path / f"pwned{case}"
        try:
            patched(Req, rnd.choice(EVIL).format(c=canary), "y")
        except subprocess.CalledProcessError:
            pass
        assert not canary.exists(), f"payload executed after the fix:\n{report.patched}"
    assert fixed > 80 and refused > 30
