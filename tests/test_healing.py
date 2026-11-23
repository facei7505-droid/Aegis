"""The self-healing loop, end to end."""
import shutil
from pathlib import Path

import pytest

from aegis.demo import ATTACKS, CHECKS, run_demo
from aegis.healer import Healer, _route_regex
from aegis.models import Incident
from aegis.scanner import scan_source

DEMO = Path(__file__).parents[1] / "aegis" / "demo_app" / "vulnshop"


def incident(path, param, payload, attack, method="GET"):
    return Incident("t" + attack[:5], 0.0, "1.1.1.1", method, path, "query", param, payload, attack, 0.9, True, 0.1,
                    classes={attack: 0.9})


@pytest.fixture
def shop(tmp_path):
    shutil.copytree(DEMO, tmp_path / "shop")
    return tmp_path / "shop"


def test_route_patterns():
    assert _route_regex("/item/<int:item_id>").match("/item/42")
    assert _route_regex("/users/{user_id}/posts").match("/users/7/posts")
    assert not _route_regex("/item/<id>").match("/item/1/edit")
    assert _route_regex("/search").match("/search/")


def test_propose_mode_writes_diff_and_leaves_code(shop):
    healer = Healer(str(shop), mode="propose")
    before = (shop / "app.py").read_text()
    rec = healer.heal(incident("/search", "q", "' OR 1=1 --", "sqli"))
    assert rec.status == "healed" and rec.function == "search" and rec.route == "/search"
    assert (shop / "app.py").read_text() == before
    diffs = list((shop / ".aegis" / "patches").glob("*.diff"))
    assert diffs and "LIKE ?" in diffs[0].read_text()


def test_auto_mode_patches_only_the_attacked_function(shop):
    healer = Healer(str(shop), mode="auto")
    rec = healer.heal(incident("/download", "file", "../secret.txt", "path_traversal"))
    assert rec.status == "healed" and [p.finding.rule_id for p in rec.patches] == ["AEG005"]
    remaining = {(f.rule_id, f.function) for f in scan_source(str(shop / "app.py"))}
    assert ("AEG005", "download") not in remaining and ("AEG001", "login") in remaining


def test_second_attack_on_healed_code(shop):
    healer = Healer(str(shop), mode="auto")
    healer.heal(incident("/greet", "name", "{{7*7}}", "ssti"))
    rec = healer.heal(incident("/greet", "name", "{{8*8}}", "ssti"))
    assert rec.status == "already_healed"


def test_replay_rejects_patch_if_exploit_still_works(shop):
    healer = Healer(str(shop), mode="auto", replay=lambda inc, file: True)
    before = (shop / "app.py").read_text()
    rec = healer.heal(incident("/ping", "host", "1 & echo X", "command_injection"))
    assert rec.status == "needs_human" and (shop / "app.py").read_text() == before
    assert "replayed attack still worked" in rec.escalations[0].reason


def test_unknown_route_has_no_root_cause(shop):
    rec = Healer(str(shop)).heal(incident("/nope", "x", "<script>", "xss"))
    assert rec.status == "no_root_cause"


def test_background_healing(shop):
    healer = Healer(str(shop), mode="propose", background=True)
    healer(incident("/search", "q", "<script>", "xss"))
    healer.wait()
    assert healer.records and healer.records[0].status == "healed"


def test_full_demo(tmp_path):
    result = run_demo(str(tmp_path / "lab"), log=lambda *_: None)
    s = result.summary()
    assert s["exploitable_before"] == len(ATTACKS)          # every hole is real
    assert s["attacks_blocked"] == len(ATTACKS)            # the shield stops all of them
    assert s["incidents_healed"] == len(ATTACKS)           # each one is traced and patched
    assert s["exploitable_after"] == 0                     # replay without the shield: nothing works
    assert s["false_positives"] == 0
    assert s["checks_passing_after"] == len(CHECKS)        # the shop still works...
    assert s["checks_passing_before"] == len(CHECKS) - 1   # ...better than before (O'Brien search was broken)
    assert {f.rule_id for f in result.findings_after} == {"AEG004", "AEG010"}


def test_one_line_protect_proposes_patch(shop, monkeypatch):
    import importlib.util, sys, uuid
    from aegis.integrations import protect

    monkeypatch.setenv("VULNSHOP_DB", str(shop / "shop.db"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    spec = importlib.util.spec_from_file_location("shop_" + uuid.uuid4().hex[:6], shop / "app.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    mod.init_db()
    app = protect(mod.app, source_root=str(shop), mode="block", heal="propose")
    r = app.test_client().get("/greet", query_string={"name": "{{7*7}}"})
    assert r.status_code == 403
    shield = app.extensions["aegis"]
    shield.healer.wait()
    assert shield.healer.records[0].status == "healed"
    assert list((shop / ".aegis" / "patches").glob("*.diff"))
    app.test_client().get("/greet", query_string={"name": "{{8*8}}"})
    shield.healer.wait()
    assert shield.healer.records[1].status == "already_proposed"
    assert len(list((shop / ".aegis" / "patches").glob("*.diff"))) == 1


# ------------------------------------------------- healer cases from the independent review --

BLUEPRINT_APP = '''import sqlite3
from flask import Blueprint, Flask, request

api = Blueprint("api", __name__)
db = sqlite3.connect(":memory:")


@api.route("/search")
def search():
    q = request.args.get("q", "")
    return str(db.execute(f"SELECT * FROM t WHERE name = '{q}'").fetchall())


@api.route("/report")
def report():
    q = request.args.get("q", "")
    return str(db.execute(f"SELECT * FROM r WHERE title = '{q}'").fetchall())
'''


def test_blueprint_prefix_maps_to_the_right_handler(tmp_path):
    (tmp_path / "api.py").write_text(BLUEPRINT_APP)
    healer = Healer(str(tmp_path), mode="auto")
    rec = healer.heal(incident("/api/search", "q", "' OR 1=1--", "sqli"))
    assert rec.status == "healed" and rec.function == "search"
    out = (tmp_path / "api.py").read_text()
    assert "WHERE name = ?" in out and "WHERE title = '{q}'" in out  # report() untouched


def test_ambiguous_request_is_never_guessed(tmp_path):
    (tmp_path / "api.py").write_text(BLUEPRINT_APP.replace('"/report"', '"/v2/search"'))
    healer = Healer(str(tmp_path), mode="auto")
    rec = healer.heal(incident("/api/v2/x", "q", "' OR 1=1--", "sqli"))
    assert rec.status == "no_root_cause" and "{q}" in (tmp_path / "api.py").read_text()


def test_replay_check_only_recorded_when_a_replay_ran(shop):
    healer = Healer(str(shop), mode="auto")
    rec = healer.heal(incident("/search", "q", "' UNION SELECT 1--", "sqli"))
    assert rec.status == "healed" and "exploit_replay" not in rec.patches[0].checks


def test_unfixable_incident_is_not_reanalysed_per_request(tmp_path):
    (tmp_path / "app.py").write_text(BLUEPRINT_APP.replace("import sqlite3\n", ""))  # unknown driver
    calls = []
    healer = Healer(str(tmp_path), mode="auto")
    original = healer._route_table
    healer._route_table = lambda: calls.append(1) or original()
    first = healer.heal(incident("/api/search", "q", "' OR 1=1--", "sqli"))
    assert first.status == "needs_human"
    statuses = {healer.heal(incident("/api/search", "q", "' OR 2=2--", "sqli")).status for _ in range(20)}
    assert statuses == {"already_escalated"}


def test_worker_survives_errors(tmp_path, monkeypatch):
    (tmp_path / "api.py").write_text(BLUEPRINT_APP)
    healer = Healer(str(tmp_path), mode="propose", background=True)
    boom = {"n": 0}
    real = healer.heal

    def flaky(inc):
        boom["n"] += 1
        if boom["n"] == 1:
            raise PermissionError("read-only file system")
        return real(inc)

    monkeypatch.setattr(healer, "heal", flaky)
    healer(incident("/api/search", "q", "' OR 1=1--", "sqli"))
    healer(incident("/api/search", "q", "' OR 1=1--", "sqli"))
    healer.wait()
    assert healer.errors == 1 and [r.status for r in healer.records][-1] == "healed"


def test_demo_refuses_to_delete_a_foreign_folder(tmp_path):
    from aegis.demo import Lab
    (tmp_path / "precious.py").write_text("keep me")
    with pytest.raises(FileExistsError):
        Lab(str(tmp_path))
    assert (tmp_path / "precious.py").exists()


def test_registered_blueprint_prefix_and_helper_sink(tmp_path):
    """vulpy layout: register_blueprint(url_prefix=...) in one file, the SQL sink in a helper module."""
    (tmp_path / "app.py").write_text("from flask import Flask\nfrom mod_user import mod_user\napp = Flask(__name__)\n"
                                     "app.register_blueprint(mod_user, url_prefix='/user')\n\n@app.route('/')\ndef home():\n    return 'hi'\n")
    (tmp_path / "mod_user.py").write_text("from flask import Blueprint, request\nimport libuser\nmod_user = Blueprint('u', __name__)\n\n"
                                          "@mod_user.route('/login', methods=['POST'])\ndef do_login():\n"
                                          "    return str(libuser.login(request.form['u'], request.form['p']))\n")
    (tmp_path / "libuser.py").write_text("import sqlite3\n\n\ndef login(username, password):\n    c = sqlite3.connect(':memory:')\n"
                                         "    return c.execute(\"SELECT * FROM users WHERE u = '{}' AND p = '{}'\".format(username, password))\n")
    rec = Healer(str(tmp_path), mode="auto").heal(incident("/user/login", "u", "admin' --", "sqli", "POST"))
    assert rec.status == "healed" and rec.function == "login" and rec.route == "/user/login"
    assert "WHERE u = ? AND p = ?" in (tmp_path / "libuser.py").read_text()


def test_plain_http_server_handler(tmp_path):
    """DSVW layout: no routes, one BaseHTTPRequestHandler.do_GET reading self.path."""
    (tmp_path / "srv.py").write_text(
        "import http.server, sqlite3, urllib.parse\n\n\nclass H(http.server.BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n        params = dict(urllib.parse.parse_qsl(self.path.split('?', 1)[-1]))\n"
        "        cur = sqlite3.connect(':memory:').cursor()\n"
        "        cur.execute(\"SELECT * FROM users WHERE id=\" + params['id'])\n")
    rec = Healer(str(tmp_path), mode="auto").heal(incident("/", "id", "1 OR 1=1", "sqli"))
    assert rec.status == "healed" and rec.function == "do_GET"
    assert 'WHERE id=?", (params["id"],))' in (tmp_path / "srv.py").read_text()
