"""Every automatic fix must produce valid code that removes the vulnerability without breaking behaviour."""
import sqlite3
import subprocess
import sys
import textwrap

import pytest

from aegis.patcher import ensure_imports, fix_file
from aegis.patcher.fixes import build_argv, parameterize
from aegis.scanner import scan_source

FLASK = "from flask import Flask, request, render_template_string\napp = Flask(__name__)\n"


def fix(tmp_path, code, **kwargs):
    path = tmp_path / "app.py"
    path.write_text(textwrap.dedent(code), encoding="utf-8")
    report = fix_file(str(path), **kwargs)
    return report, path.read_text(encoding="utf-8")


def compile_ok(src):
    compile(src, "patched.py", "exec")
    return True


# ---------------------------------------------------------------------- SQL --

def test_sql_fstring_with_quotes(tmp_path):
    _, out = fix(tmp_path, "import sqlite3\n" + FLASK + "@app.route('/a')\ndef a():\n    u = request.args['u']\n"
                                   "    return db.execute(f\"SELECT * FROM users WHERE name = '{u}'\").fetchone()\n")
    assert 'db.execute("SELECT * FROM users WHERE name = ?", (u,))' in out
    assert compile_ok(out)


def test_sql_like_pattern_keeps_wildcards(tmp_path):
    _, out = fix(tmp_path, "import sqlite3\n" + FLASK + "@app.route('/a')\ndef a():\n    q = request.args['q']\n"
                                   "    return db.execute(f\"SELECT * FROM p WHERE name LIKE '%{q}%'\").fetchall()\n")
    assert '"SELECT * FROM p WHERE name LIKE ?", (f"%{q}%",)' in out


def test_sql_percent_and_format_and_concat():
    import ast
    for expr in ["\"SELECT * FROM t WHERE a = '%s' AND b = %d\" % (x, y)",
                 "\"SELECT * FROM t WHERE a = '{}' AND b = {}\".format(x, y)",
                 "\"SELECT * FROM t WHERE a = '\" + x + \"' AND b = \" + y"]:
        template, params = parameterize(ast.parse(expr, mode="eval").body, "?")
        assert template == "SELECT * FROM t WHERE a = ? AND b = ?"
        assert params == ["x", "y"]


def test_sql_via_variable(tmp_path):
    _, out = fix(tmp_path, "import sqlite3\n" + FLASK + "@app.route('/a')\ndef a():\n    u = request.form['u']\n"
                                   "    sql = f\"DELETE FROM s WHERE user = '{u}'\"\n    db.execute(sql)\n")
    assert 'sql = "DELETE FROM s WHERE user = ?"' in out and "db.execute(sql, (u,))" in out


def test_sql_psycopg_uses_pyformat(tmp_path):
    _, out = fix(tmp_path, "import psycopg2\n" + FLASK + "@app.route('/a')\ndef a():\n    u = request.args['u']\n"
                 "    cur.execute(f\"SELECT * FROM t WHERE u = '{u}'\")\n")
    assert 'cur.execute("SELECT * FROM t WHERE u = %s", (u,))' in out


def test_sql_patch_really_stops_injection(tmp_path):
    code = textwrap.dedent("""
        import sqlite3
        def login(conn, name, pw):
            return conn.execute(f"SELECT * FROM u WHERE name = '{name}' AND pw = '{pw}'").fetchone()
    """)
    # make the function look like a request handler so the input counts as tainted
    code = code.replace("def login(conn, name, pw):", "def login(request, conn, name, pw):")
    report, out = fix(tmp_path, code)
    ns = {}
    exec(compile(out, "patched", "exec"), ns)
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE u (name TEXT, pw TEXT)")
    conn.execute("INSERT INTO u VALUES ('admin', 'secret')")
    assert ns["login"](None, conn, "admin' --", "x") is None          # bypass no longer works
    assert ns["login"](None, conn, "admin", "secret") is not None      # real login still works


# ------------------------------------------------------------------ command --

@pytest.mark.parametrize("expr", [
    'f"SELECT {cols} FROM {table}"', 'f"DROP TABLE {t}"', 'f"SELECT * FROM t ORDER BY {c}"',
    'f"SELECT * FROM t WHERE a = 1 AND {cond}"', 'f"SELECT * FROM t WHERE id IN ({ids})"',
])
def test_sql_identifiers_are_never_parameterized(expr):
    import ast
    assert parameterize(ast.parse(expr, mode="eval").body, "?") is None


def test_sql_value_positions():
    import ast
    t, p = parameterize(ast.parse('f"SELECT * FROM t WHERE a = {x} AND b BETWEEN {lo} AND {hi} LIMIT {n}"',
                                  mode="eval").body, "?")
    assert t == "SELECT * FROM t WHERE a = ? AND b BETWEEN ? AND ? LIMIT ?" and p == ["x", "lo", "hi", "n"]


def test_untainted_eval_is_left_for_a_human(tmp_path):
    report, out = fix(tmp_path, "def compile_rule(code, ns):\n    return eval(code, ns)\n")
    assert not report.patches and "eval(code, ns)" in out


def test_list_with_shell_true_only_drops_shell(tmp_path):
    _, out = fix(tmp_path, "import subprocess\n" + FLASK + "@app.route('/a')\ndef a():\n"
                 "    return subprocess.run(['git', request.args['ref']], shell=True).returncode\n")
    assert "subprocess.run(['git', request.args['ref']], shell=False)" in out


def test_command_argv_tokenisation():
    assert build_argv([("lit", "ping -c 1 "), ("expr", "host")]) == "['ping', '-c', '1', str(host)]"
    assert build_argv([("lit", "tool --name="), ("expr", "n"), ("lit", " -v")]) == "['tool', f'--name={n}', '-v']"
    assert build_argv([("lit", '"'), ("expr", "TOOL"), ("lit", '" '), ("expr", "x")]) == "[str(TOOL), str(x)]"
    assert build_argv([("lit", "ls "), ("expr", "d"), ("lit", " | grep x")]) is None   # pipes need a human
    assert build_argv([("lit", "echo 'unterminated "), ("expr", "x")]) is None


def test_os_system_becomes_subprocess(tmp_path):
    report, out = fix(tmp_path, "import os\n" + FLASK + "@app.route('/a')\ndef a():\n"
                      "    return str(os.system(f\"ping -c 1 {request.args['h']}\"))\n")
    assert "subprocess.run([\"ping\", \"-c\", \"1\", str(request.args[\"h\"])]).returncode" in out \
        or "subprocess.run(['ping', '-c', '1', str(request.args['h'])]).returncode" in out
    assert "import subprocess" in out
    assert report.patches[0].verified


def test_quoted_arguments_keep_their_meaning():
    # inside quotes ; is literal text for the shell, so it must stay one argument
    argv = build_argv([("lit", 'python -c "import sys; print(1)" '), ("expr", "h")])
    assert argv == "['python', '-c', 'import sys; print(1)', str(h)]"
    # but $VAR and backticks still expand inside double quotes -> refuse
    assert build_argv([("lit", 'echo "$HOME" '), ("expr", "h")]) is None
    assert build_argv([("lit", "echo '$HOME' "), ("expr", "h")]) == "['echo', '$HOME', str(h)]"


def test_shell_true_simple_is_fixed_and_safe(tmp_path):
    tool = tmp_path / "echo_arg.py"
    tool.write_text("import sys\nprint(sys.argv[1])\n")
    code = ("import subprocess, sys\nTOOL = %r\n" % str(tool) + FLASK +
            "@app.route('/a')\ndef a():\n    h = request.args['h']\n"
            "    return subprocess.run(f'\"{sys.executable}\" \"{TOOL}\" {h}', shell=True, capture_output=True, text=True).stdout\n")
    _, out = fix(tmp_path, code)
    assert "shell=False" in out
    ns = {"__name__": "patched"}
    exec(compile(out, "patched", "exec"), ns)
    with ns["app"].test_request_context("/a?h=x;echo PWNED"):
        assert ns["a"]().strip() == "x;echo PWNED"


# ----------------------------------------------------------- other fixers ---

def test_eval_becomes_literal_eval(tmp_path):
    _, out = fix(tmp_path, FLASK + "@app.route('/a')\ndef a():\n    return str(eval(request.args['x']))\n")
    assert "ast.literal_eval(request.args" in out and "import ast" in out


def test_yaml_safe_load(tmp_path):
    _, out = fix(tmp_path, "import yaml\ndef load(s):\n    return yaml.load(s)\n")
    assert "yaml.safe_load(s)" in out


def test_path_traversal_join(tmp_path):
    _, out = fix(tmp_path, "import os\n" + FLASK + "@app.route('/f/<name>')\ndef f(name):\n"
                 "    return open(os.path.join(BASE, name)).read()\n")
    assert "os.path.join(BASE, os.path.basename(name))" in out


def test_secret_moves_to_environment(tmp_path):
    _, out = fix(tmp_path, "app.config['SECRET_KEY'] = 'super-secret-value'\n")
    assert 'app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]' in out or \
           "app.config['SECRET_KEY'] = os.environ[\"SECRET_KEY\"]" in out
    assert out.startswith("import os\n")


def test_xss_escapes_only_user_values(tmp_path):
    _, out = fix(tmp_path, FLASK + "@app.route('/a')\ndef a():\n    q = request.args['q']\n"
                 "    return f\"<h1>{q}</h1><p>{TITLE}</p>\"\n")
    assert "{html.escape(str(q))}" in out and "{TITLE}" in out


def test_ssti_passes_data_not_code(tmp_path):
    _, out = fix(tmp_path, FLASK + "@app.route('/a')\ndef a():\n    name = request.args['n']\n"
                 "    return render_template_string(f\"<p>Hi {name}</p>\")\n")
    assert 'render_template_string("<p>Hi {{ name }}</p>", name=name)' in out
    ns = {"__name__": "patched"}
    exec(compile(out, "patched", "exec"), ns)
    with ns["app"].test_request_context("/a?n={{7*7}}"):
        assert "49" not in ns["a"]()


# ------------------------------------------------------------------- engine --

def test_imports_land_in_the_right_place():
    src = '"""doc"""\nfrom __future__ import annotations\nimport os\nimport sys\nfrom flask import Flask\n\nx = 1\n'
    out = ensure_imports(src, {"html", "ast", "subprocess"})
    assert out.splitlines()[:7] == ['"""doc"""', "from __future__ import annotations", "import ast", "import html",
                                    "import os", "import subprocess", "import sys"]


def test_unfixable_findings_are_escalated_with_reason(tmp_path):
    report, out = fix(tmp_path, "import pickle\ndef load(b):\n    return pickle.loads(b)\n")
    assert not report.patches and report.escalated
    assert "No built-in rule" in report.escalated[0].reason
    assert "pickle.loads" in out


def test_dry_run_does_not_write(tmp_path):
    path = tmp_path / "app.py"
    original = "API_KEY = 'sk_live_abcdef123456'\n"
    path.write_text(original)
    report = fix_file(str(path), write=False)
    assert report.changed and path.read_text(encoding="utf-8") == original


def test_test_gate_rejects_breaking_patch(tmp_path):
    # the "test suite" fails whenever the file reads its secret from the environment
    (tmp_path / "check.py").write_text("import sys\nsys.exit(1 if 'os.environ' in open('app.py').read() else 0)\n")
    report, out = fix(tmp_path, "API_KEY = 'sk_live_abcdef123456'\n",
                      test_cmd=f"{sys.executable} check.py", cwd=str(tmp_path))
    assert not report.patches and report.escalated
    assert "test suite failed" in report.escalated[0].reason
    assert out == "API_KEY = 'sk_live_abcdef123456'\n"


def test_full_demo_app_patched_code_is_clean(tmp_path):
    from pathlib import Path
    import shutil
    src = Path(__file__).parents[1] / "aegis" / "demo_app" / "vulnshop"
    shutil.copytree(src, tmp_path / "shop")
    report = fix_file(str(tmp_path / "shop" / "app.py"))
    remaining = {f.rule_id for f in scan_source(str(tmp_path / "shop" / "app.py"))}
    assert remaining == {"AEG004", "AEG010"}   # pickle + MD5 need a human (or Claude)
    assert all(p.verified for p in report.patches) and len(report.patches) == 10
    compile((tmp_path / "shop" / "app.py").read_text(encoding="utf-8"), "app.py", "exec")


def test_fix_refused_when_module_name_is_shadowed(tmp_path):
    report, out = fix(tmp_path, FLASK + "@app.route('/a')\ndef a():\n    html = '<p>'\n    q = request.args['q']\n"
                      "    return f\"{html}{q}</p>\"\n")
    assert not report.patches and "html.escape" not in out


def test_format_spec_is_not_parameterized():
    import ast
    assert parameterize(ast.parse('f"SELECT * FROM t WHERE code = {x:>10}"', mode="eval").body, "?") is None


def test_xss_in_class_based_view(tmp_path):
    code = ("from flask import request\nfrom flask.views import MethodView\nclass Hello(MethodView):\n"
            "    def get(self):\n        return f\"<h1>{request.args['n']}</h1>\"\n")
    report, out = fix(tmp_path, code)
    assert report.patches and "html.escape(str(request.args" in out


@pytest.mark.parametrize("expr,template,params", [
    ('f"SELECT * FROM t WHERE full = \'{first} {last}\' AND n = {n}"',
     "SELECT * FROM t WHERE full = ? AND n = ?", ["f'{first} {last}'", "n"]),
    ('f"SELECT * FROM t WHERE note = \'it\'\'s {x}\'"', "SELECT * FROM t WHERE note = ?", ["f\"it's {x}\""]),
    ('f"SELECT * FROM t WHERE p = \'C:\\\\temp\\\\{q}\'"', "SELECT * FROM t WHERE p = ?", ["f'C:\\\\temp\\\\{q}'"]),
])
def test_values_inside_sql_literals(expr, template, params):
    import ast
    assert parameterize(ast.parse(expr, mode="eval").body, "?") == (template, params)


def test_unclosed_or_identifier_quotes_are_refused():
    import ast
    for expr in ['f"SELECT * FROM t WHERE a = \'{x}"', 'f"SELECT * FROM \\"{tbl}\\" WHERE a = 1"']:
        assert parameterize(ast.parse(expr, mode="eval").body, "?") is None


def test_parameterized_literal_keeps_exact_value(tmp_path):
    import sqlite3
    code = ("def find(request, conn, first, last):\n"
            "    return conn.execute(f\"SELECT id FROM u WHERE full = '{first} {last}' AND note LIKE 'it''s%'\").fetchone()\n")
    code = code.replace("def find(request, conn, first, last):", "def find(request, conn, first, last):\n    request.GET")
    _, out = fix(tmp_path, code)
    ns = {}
    exec(compile(out, "p", "exec"), ns)
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE u (id INT, full TEXT, note TEXT)")
    conn.execute("INSERT INTO u VALUES (1, 'Magzhan K', 'it''s fine')")
    class R:
        GET = {}
    assert ns["find"](R, conn, "Magzhan", "K") == (1,)
    assert ns["find"](R, conn, "x' OR '1'='1", "y") is None


@pytest.mark.parametrize("line", [
    "subprocess.run(request.args['cmd'], shell=True)",
    "subprocess.run(f\"{request.args['tool']} --version\", shell=True)",
    "os.system(request.args['cmd'])",
    "subprocess.run([request.args['prog'], '-v'], shell=True)",
])
def test_command_chosen_by_input_is_left_to_a_human(tmp_path, line):
    """Dropping the shell does not help when the attacker picks the program itself."""
    code = f"import os\nimport subprocess\nfrom flask import request\n\n\ndef run():\n    {line}\n"
    report, out = fix(tmp_path, code)
    assert out == code and not report.patches


# ----------------------------------------- correctness cases from the independent review --

def run_route(src, url, tmp_path, name="m"):
    import importlib.util
    path = tmp_path / f"{name}.py"
    path.write_text(src, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.app.test_client().get(url)


DB = ("import sqlite3\n" + FLASK +
      "def mk():\n    c = sqlite3.connect(':memory:')\n    c.execute('CREATE TABLE t (a, b)')\n"
      "    c.execute(\"INSERT INTO t VALUES ('x', 'y')\")\n    return c\n")


def test_sql_variable_reassigned_is_left_to_a_human(tmp_path):
    code = DB + ("@app.route('/p')\ndef p():\n    a = request.args['a']\n"
                 "    sql = f\"SELECT * FROM t WHERE a = '{a}'\"\n    one = mk().execute(sql).fetchall()\n"
                 "    sql = f\"SELECT * FROM t WHERE b = '{a}'\"\n    two = mk().execute(sql).fetchall()\n"
                 "    return str(len(one) + len(two))\n")
    report, out = fix(tmp_path, code)
    assert out == code and len(report.escalated) == 2


def test_sql_tainted_append_is_not_called_fixed(tmp_path):
    code = DB + ("@app.route('/p')\ndef p():\n    a = request.args['a']\n    sql = \"SELECT * FROM t WHERE 1=1\"\n"
                 "    sql += f\" AND a = '{a}'\"\n    return str(mk().execute(sql).fetchall())\n")
    report, out = fix(tmp_path, code)
    assert out == code and report.escalated


def test_sql_numbered_format_holes_keep_their_values(tmp_path):
    code = DB + ("@app.route('/p')\ndef p():\n    a, b = request.args['a'], request.args['b']\n"
                 "    return str(mk().execute(\"SELECT * FROM t WHERE a = '{1}' AND b = '{0}'\".format(b, a)).fetchall())\n")
    _, out = fix(tmp_path, code)
    assert "(a, b)" in out
    assert run_route(out, "/p?a=x&b=y", tmp_path).get_data(as_text=True) == "[('x', 'y')]"


@pytest.mark.parametrize("call", [
    "mk().executescript(f\"UPDATE t SET a = '{a}'\")",
    "pd.read_sql(f\"SELECT * FROM t WHERE a = '{a}'\", con=engine)",
    "mk().execute(f\"SELECT * FROM t WHERE a = '{a}'\", params=None)",
])
def test_sql_calls_without_a_params_slot_are_refused(tmp_path, call):
    code = DB + f"@app.route('/p')\ndef p():\n    a = request.args['a']\n    return str({call})\n"
    report, out = fix(tmp_path, code)
    assert out == code


def test_sql_keywords_are_kept(tmp_path):
    code = DB + ("@app.route('/p')\ndef p():\n    a = request.args['a']\n"
                 "    return str(mk().execute(f\"SELECT * FROM t WHERE a = '{a}'\").fetchall())\n")
    code = code.replace("execute(f\"SELECT * FROM t WHERE a = '{a}'\")", "execute(f\"SELECT * FROM t WHERE a = '{a}'\", )")
    _, out = fix(tmp_path, code)
    assert 'execute("SELECT * FROM t WHERE a = ?", (a,), )' in out and compile_ok(out)


def test_sql_placeholder_needs_a_known_driver(tmp_path):
    unknown = FLASK + ("@app.route('/p')\ndef p(cur):\n    a = request.args['a']\n"
                       "    cur.execute(f\"SELECT * FROM t WHERE a = '{a}'\")\n")
    report, out = fix(tmp_path, unknown)
    assert out == unknown and report.escalated
    django = "from django.db import connection\n" + unknown
    _, out = fix(tmp_path, django)
    assert 'cur.execute("SELECT * FROM t WHERE a = %s", (a,))' in out
    both = "import sqlite3\nimport psycopg2\n" + unknown
    _, out = fix(tmp_path, both)
    assert out == both


def test_path_fix_keeps_the_base_folder(tmp_path):
    (tmp_path / "uploads").mkdir()
    (tmp_path / "uploads" / "readme.txt").write_text("public")
    (tmp_path / ".env").write_text("SECRET=1")
    code = ("import os\nfrom pathlib import Path\n" + FLASK + f"UP = Path({str(tmp_path / 'uploads')!r})\n"
            "@app.route('/f')\ndef f():\n    name = request.args['f']\n    return open(UP / name).read()\n")
    _, out = fix(tmp_path, code)
    assert "open(UP / os.path.basename(name))" in out
    assert run_route(out, "/f?f=readme.txt", tmp_path, "p1").get_data(as_text=True) == "public"
    assert run_route(out, "/f?f=../.env", tmp_path, "p2").status_code == 500  # FileNotFoundError inside uploads/


def test_xss_fix_formats_before_escaping(tmp_path):
    code = FLASK + "@app.route('/t')\ndef t():\n    amount = request.args.get('a', type=float)\n    return f'<p>{amount:.2f} {amount!r}</p>'\n"
    _, out = fix(tmp_path, code)
    assert run_route(out, "/t?a=3.5", tmp_path).get_data(as_text=True) == "<p>3.50 3.5</p>"


def test_ssti_fix_avoids_parameter_names_and_keeps_trusted_html(tmp_path):
    code = (FLASK + "MENU = '<nav>Home</nav>'\n@app.route('/g')\ndef g():\n    source = request.args['s']\n"
            "    return render_template_string(f'{MENU}<p>{source}</p>')\n")
    _, out = fix(tmp_path, code)
    body = run_route(out, "/g?s={{7*7}}<b>", tmp_path).get_data(as_text=True)
    assert body == "<nav>Home</nav><p>{{7*7}}&lt;b&gt;</p>"


def test_command_in_variable_becomes_an_argument_list(tmp_path):
    code = ("import subprocess\n" + FLASK + "@app.route('/c')\ndef c():\n    url = request.args['u']\n"
            "    cmd = f'echo -n {url}'\n    return subprocess.check_output(cmd, shell=True, text=True)\n")
    _, out = fix(tmp_path, code)
    assert "cmd = ['echo', '-n', str(url)]" in out and "shell=False" in out
    assert run_route(out, "/c?u=a b -o /tmp/x", tmp_path).get_data(as_text=True) == "a b -o /tmp/x"
    reused = code.replace("    return subprocess", "    print(cmd)\n    return subprocess")
    _, out = fix(tmp_path, reused)
    assert out == reused  # the string is used elsewhere: a list there would break it
