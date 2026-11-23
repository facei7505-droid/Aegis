"""Detection precision: every rule must fire on the bad pattern and stay quiet on the safe one."""
import textwrap

import pytest

from aegis.scanner import scan_source


def scan(code: str):
    return scan_source("app.py", textwrap.dedent(code))


def rules(code: str):
    return sorted(f.rule_id for f in scan(code))


FLASK = "from flask import Flask, request, render_template, render_template_string\napp = Flask(__name__)\n"


# ---------------------------------------------------------------- positives --

@pytest.mark.parametrize("code,rule", [
    # SQL injection: f-string, %, +, .format, via variable
    (FLASK + "@app.route('/a')\ndef a():\n    db.execute(f\"SELECT * FROM t WHERE id = {request.args['id']}\")\n", "AEG001"),
    (FLASK + "@app.route('/a')\ndef a():\n    q = request.args.get('q')\n    cur.execute(\"SELECT * FROM t WHERE n = '%s'\" % q)\n", "AEG001"),
    (FLASK + "@app.route('/a')\ndef a():\n    q = request.args.get('q')\n    cur.execute(\"SELECT * FROM t WHERE n = '\" + q + \"'\")\n", "AEG001"),
    (FLASK + "@app.route('/a')\ndef a():\n    q = request.args.get('q')\n    cur.execute(\"SELECT * FROM t WHERE n = '{}'\".format(q))\n", "AEG001"),
    (FLASK + "@app.route('/a')\ndef a():\n    q = request.args.get('q')\n    sql = f\"DELETE FROM t WHERE n = '{q}'\"\n    cur.execute(sql)\n", "AEG001"),
    # command injection
    (FLASK + "@app.route('/a')\ndef a():\n    os.system('ping ' + request.args['h'])\n", "AEG002"),
    (FLASK + "@app.route('/a')\ndef a():\n    h = request.args['h']\n    subprocess.run(f'ping {h}', shell=True)\n", "AEG002"),
    # code injection
    (FLASK + "@app.route('/a')\ndef a():\n    return str(eval(request.args['x']))\n", "AEG003"),
    # deserialization
    ("import pickle\ndef load(blob):\n    return pickle.loads(blob)\n", "AEG004"),
    ("import yaml\ndef load(s):\n    return yaml.load(s)\n", "AEG004"),
    ("import yaml\ndef load(s):\n    return yaml.load(s, Loader=yaml.Loader)\n", "AEG004"),
    # path traversal
    (FLASK + "@app.route('/a')\ndef a():\n    return open('files/' + request.args['f']).read()\n", "AEG005"),
    (FLASK + "@app.route('/a/<name>')\ndef a(name):\n    return send_file(os.path.join(BASE, name))\n", "AEG005"),
    # secrets
    ("API_KEY = 'sk_live_abcdef123456'\n", "AEG006"),
    ("app.config['SECRET_KEY'] = 'super-secret-value'\n", "AEG006"),
    # debug
    (FLASK + "app.run(debug=True)\n", "AEG007"),
    # xss
    (FLASK + "@app.route('/a')\ndef a():\n    return f\"<b>{request.args['q']}</b>\"\n", "AEG008"),
    # ssti
    (FLASK + "@app.route('/a')\ndef a():\n    return render_template_string('<p>' + request.args['n'] + '</p>')\n", "AEG009"),
    # weak hash
    ("import hashlib\nh = hashlib.md5(b'x').hexdigest()\n", "AEG010"),
    # ssrf
    (FLASK + "@app.route('/a')\ndef a():\n    return requests.get(request.args['url']).text\n", "AEG011"),
])
def test_rule_fires(code, rule):
    assert rule in rules(code)


# ---------------------------------------------------------------- negatives --

@pytest.mark.parametrize("code", [
    FLASK + "@app.route('/a')\ndef a():\n    db.execute('SELECT * FROM t WHERE id = ?', (request.args['id'],))\n",
    FLASK + "@app.route('/a')\ndef a():\n    db.execute('SELECT * FROM t')\n",
    FLASK + "@app.route('/a')\ndef a():\n    subprocess.run(['ping', '-c', '1', request.args['h']])\n",
    "import os\nos.system('ls -la')\n",
    "x = eval('1 + 1')\n",
    FLASK + "@app.route('/a')\ndef a():\n    return open('files/' + os.path.basename(request.args['f'])).read()\n",
    "PASSWORD = ''\nTOKEN = os.environ['TOKEN']\nSECRET = 'changeme'\n",
    FLASK + "app.run(debug=False)\n",
    FLASK + "@app.route('/a')\ndef a():\n    return render_template('a.html', q=request.args['q'])\n",
    FLASK + "@app.route('/a')\ndef a():\n    return f\"<b>{html.escape(request.args['q'])}</b>\"\n",
    FLASK + "@app.route('/a')\ndef a():\n    return f\"Hello {request.args['q']}\"\n",
    FLASK + "@app.route('/a')\ndef a():\n    return render_template_string('<p>{{ n }}</p>', n=request.args['n'])\n",
    "import yaml\ndef load(s):\n    return yaml.load(s, Loader=yaml.SafeLoader)\n",
    FLASK + "@app.route('/a')\ndef a():\n    return requests.get('https://api.example.com/rates').text\n",
])
def test_safe_code_is_quiet(code):
    assert rules(code) == []


def test_sanitized_input_lowers_severity():
    code = FLASK + "@app.route('/a')\ndef a():\n    n = int(request.args['n'])\n    db.execute(f'SELECT * FROM t LIMIT {n}')\n"
    [f] = scan(code)
    assert f.rule_id == "AEG001" and f.severity == "medium" and not f.tainted


def test_untainted_dynamic_sql_is_medium():
    findings = scan("def report(table):\n    db.execute(f'SELECT * FROM {table}')\n")
    assert findings[0].rule_id == "AEG001" and findings[0].severity == "medium" and not findings[0].tainted


def test_route_parameters_are_tainted():
    code = FLASK + "@app.route('/u/<name>')\ndef user(name):\n    db.execute(f\"SELECT * FROM u WHERE n = '{name}'\")\n"
    f = scan(code)[0]
    assert f.tainted and f.severity == "critical" and f.function == "user"


def test_fastapi_parameters_are_tainted():
    code = ("from fastapi import FastAPI\napp = FastAPI()\n@app.get('/items')\n"
            "def items(q: str):\n    db.execute(f\"SELECT * FROM i WHERE n = '{q}'\")\n")
    assert scan(code)[0].severity == "critical"


def test_django_views_are_understood():
    code = ("def search(request):\n    q = request.GET.get('q', '')\n"
            "    cursor.execute(f\"SELECT * FROM p WHERE name = '{q}'\")\n")
    f = scan(code)[0]
    assert f.rule_id == "AEG001" and f.tainted


def test_taint_stops_at_database_reads():
    code = FLASK + ("@app.route('/a')\ndef a():\n    rows = db.execute('SELECT name FROM p WHERE id = ?', (request.args['id'],)).fetchall()\n"
                    "    names = ''.join(f\"<li>{r['name']}</li>\" for r in rows)\n    return f\"<ul>{names}</ul>\"\n")
    assert "AEG008" not in rules(code)


def test_inline_suppression():
    code = "API_KEY = 'sk_live_abcdef123456'  # aegis: ignore[AEG006]\nTOKEN = 'tok_8f2b9c1d7e6a5f40'\n"
    assert [f.snippet for f in scan(code)] == ["TOKEN = 'tok_8f2b9c1d7e6a5f40'"]


def test_suppression_comment_above_only_on_own_line():
    code = "# aegis: ignore\nAPI_KEY = 'sk_live_abcdef123456'\nX = 1  # aegis: ignore\nTOKEN = 'tok_8f2b9c1d7e6a5f40'\n"
    assert [f.snippet for f in scan(code)] == ["TOKEN = 'tok_8f2b9c1d7e6a5f40'"]


@pytest.mark.parametrize("code", [
    "token_type = 'operator'\n",
    "PASSWORD_RESET_URL = 'https://example.com/reset'\n",
    "password_field = 'password1'\n",
    "SECRET_KEY = 'changeme'\n",
    "api_key = 'please set me'\n",
])
def test_secret_false_positives(code):
    assert rules(code) == []


# Fake credentials are assembled at run time so the repository itself never contains a
# string that looks like a real token (secret scanners and push protection stay quiet).
@pytest.mark.parametrize("code", [
    "SLACK = '" + "xoxb" + "-1234567890-abcdefghij'\n",
    "cfg = {}\nAWS_KEY = '" + "AKIA" + "IOSFODNN7EXAMPLE'\n",
    "bot_token = '7012345678" + ":AAHkL9xq2v_ZpX8oQwErTyUiOpAsDfGhJkL'\n",
    "DB_PASSWORD = 'Sup3rS3cret!'\n",
])
def test_secret_true_positives(code):
    assert rules(code) == ["AEG006"]


def test_pytest_request_fixture_is_not_a_view():
    code = "def test_x(request, tmp):\n    p = request.param\n    open(tmp + p)\n"
    assert rules(code) == []


def test_yaml_positional_safe_loader():
    assert rules("import yaml\ndef f(s):\n    return yaml.load(s, SafeLoader)\n") == []


def test_unicode_source_positions():
    code = "import sqlite3\n" + FLASK + ("@app.route('/a')\ndef a():\n    заметка = 'привет'\n"
                    "    db.execute(f\"SELECT * FROM t WHERE n = '{request.args['q']}' -- ✓\")\n")
    f = scan(code)[0]
    assert f.rule_id == "AEG001" and f.fixable


def test_review_false_negatives_are_found():
    code = '''import subprocess as sp
from os import system
from pickle import loads
import yaml
from flask import Flask, request
from sqlalchemy import text
from django.http import HttpResponse
app = Flask(__name__)
@app.route("/f1")
def f1():
    q = "SELECT * FROM users WHERE 1=1"
    q += f" AND name = '{request.args['n']}'"
    return str(db.execute(q).fetchall())
@app.route("/f2")
def f2():
    return str(db.session.execute(text(f"SELECT * FROM u WHERE n = '{request.args['n']}'")).all())
@app.route("/f3")
def f3():
    sp.run(f"ping {request.args['h']}", shell=True); system("ping " + request.args["h"]); return "ok"
@app.route("/f4")
def f4():
    return loads(request.data), yaml.unsafe_load(request.data)
@app.route("/f5")
def f5():
    return f"<h1>{request.args['q']}</h1>", 200
def dj(request):
    return HttpResponse(f"<h1>{request.GET['q']}</h1>")
class Settings:
    secret_key: str = "f9a8b7c6d5e4f3a2b1c0d9e8"
'''
    found = {(f.rule_id, f.function) for f in scan(code)}
    expected = {("AEG001", "f1"), ("AEG001", "f2"), ("AEG002", "f3"), ("AEG004", "f4"), ("AEG008", "f5"),
                ("AEG008", "dj"), ("AEG006", None)}
    assert expected <= found


def test_review_false_positives_are_quiet():
    code = FLASK + '''import hashlib
import streamlit as st
@app.route("/a")
def a():
    name = request.args["n"]
    st.text(f"Hello {name}")
    return hashlib.md5(name.encode(), usedforsecurity=False).hexdigest()
'''
    assert scan(code) == []


def test_form_feed_and_line_separator_do_not_shift_positions(tmp_path):
    from aegis.patcher import fix_file
    code = ("import sqlite3\n" + FLASK + "# section\x0c break   in a comment\n@app.route('/a')\ndef a():\n"
            "    q = request.args['q']\n    return db.execute(f\"SELECT * FROM t WHERE n = '{q}'\").fetchall()\n")
    f = scan(code)[0]
    assert f.line == 8 and "db.execute" in f.snippet
    path = tmp_path / "app.py"
    path.write_text(code, encoding="utf-8")
    fix_file(str(path))
    assert 'db.execute("SELECT * FROM t WHERE n = ?", (q,))' in path.read_text(encoding="utf-8")
