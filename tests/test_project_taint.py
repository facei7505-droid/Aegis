"""Request data followed from handlers into helpers in other modules."""
from aegis.scanner import scan_path
from aegis.patcher import fix_file
from aegis.scanner.project import analyze_project

ROUTE = ("from flask import Flask, request\n{imp}\napp = Flask(__name__)\n\n"
         "@app.route('/login', methods=['POST'])\ndef do_login():\n    return str({call}(request.form['u'], 'x'))\n")
HELPER = ("import sqlite3\n\n\ndef login(username, password):\n    c = sqlite3.connect(':memory:')\n"
          "    return c.execute(\"SELECT * FROM users WHERE u = '{}'\".format(username))\n")


def sqli(findings):
    return [(f.file.split("/")[-1], f.function, f.severity) for f in findings if f.rule_id == "AEG001"]


def test_module_import_makes_helper_sink_critical(tmp_path):
    (tmp_path / "app.py").write_text(ROUTE.format(imp="import libuser", call="libuser.login"))
    (tmp_path / "libuser.py").write_text(HELPER)
    assert sqli(scan_path(tmp_path)) == [("libuser.py", "login", "critical")]


def test_from_import_and_two_hops(tmp_path):
    (tmp_path / "app.py").write_text(ROUTE.format(imp="from service import check", call="check"))
    (tmp_path / "service.py").write_text("from libuser import login\n\n\ndef check(name, pw):\n    return login(name, pw)\n")
    (tmp_path / "libuser.py").write_text(HELPER)
    assert sqli(scan_path(tmp_path)) == [("libuser.py", "login", "critical")]


def test_untainted_callers_do_not_taint(tmp_path):
    (tmp_path / "app.py").write_text("import libuser\n\n\ndef job():\n    return libuser.login('admin', 'x')\n")
    (tmp_path / "libuser.py").write_text(HELPER)
    assert sqli(scan_path(tmp_path)) == [("libuser.py", "login", "medium")]


def test_taint_enables_behaviour_changing_fixes_in_helpers(tmp_path):
    (tmp_path / "app.py").write_text(ROUTE.format(imp="import tools", call="tools.ping"))
    (tmp_path / "tools.py").write_text("import subprocess\n\n\ndef ping(host, unused):\n"
                                       "    return subprocess.run(f'ping -c 1 {host}', shell=True)\n")
    analyze_project(tmp_path)
    report = fix_file(str(tmp_path / "tools.py"), write=False)
    assert "['ping', '-c', '1', str(host)]" in report.patched and "shell=False" in report.patched


def test_modules_outside_the_project_are_not_followed(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (tmp_path / "libuser.py").write_text(HELPER)  # sibling of the project, not inside it
    (proj / "app.py").write_text(ROUTE.format(imp="import libuser", call="libuser.login"))
    assert analyze_project(proj) == {}
