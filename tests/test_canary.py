"""Canary: a patch must keep real traffic working before it is accepted."""
import subprocess
import sys
import time

from aegis.canary import Canary, Recorded, TrafficRecorder, worse, _free_port, _wait
from aegis.gateway import AppSpec
from aegis.models import Incident

SERVER = '''import http.server, sys

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = BODY
        self.send_response(STATUS)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
'''


def app(status=200, body=b"<h1>Products</h1><ul><li>Laptop</li></ul>"):
    return SERVER.replace("STATUS", str(status)).replace("BODY", repr(body))


def test_worse_only_when_the_copy_is_worse():
    assert worse((200, b"a"), (500, b"err")) == "200 → 500"
    assert worse((200, b"a"), (404, b"x")) == "200 → 404"
    assert worse((500, b"err"), (200, b"ok")) is None          # the patch repaired something
    assert worse((200, b"Hello Aigerim, 12:31"), (200, b"Hello Aigerim, 12:32")) is None
    assert worse((200, b"<html>" + b"x" * 500), (200, b"totally different")) == "page changed"


def test_recorder_keeps_recent_distinct_safe_requests():
    rec = TrafficRecorder(size=3)
    for target in ["/a", "/b", "/a", "/c", "/d"]:
        rec.add("GET", target, {"Cookie": "s=1", "X-Secret": "no"})
    rec.add("POST", "/buy", {})
    assert [r.target for r in rec.recent(10)] == ["/a", "/c", "/d"]
    assert rec.recent(1)[0].headers == {"Cookie": "s=1"}


def run_live(tmp_path):
    (tmp_path / "srv").mkdir()
    (tmp_path / "srv" / "server.py").write_text(app())
    port = _free_port()
    proc = subprocess.Popen([sys.executable, "server.py", str(port)], cwd=tmp_path / "srv")
    assert _wait(port, 10, proc)
    spec = AppSpec("t", f"http://127.0.0.1:{port}", source=str(tmp_path / "srv"), cwd=str(tmp_path / "srv"),
                   command=[sys.executable, "server.py", "{port}"])
    return proc, spec


def test_canary_rejects_a_patch_that_breaks_pages_and_accepts_a_good_one(tmp_path):
    proc, spec = run_live(tmp_path)
    try:
        rec = TrafficRecorder()
        rec.add("GET", "/", {})
        rec.add("GET", "/products?page=2", {})
        canary = Canary(spec, rec)
        inc = Incident("i1", time.time(), "1.1.1.1", "GET", "/", "query", "q", "x", "sqli", 0.9, True, 0.1)
        bad, notes = canary.check_patch(inc, str(tmp_path / "srv" / "server.py"), app(status=500))
        assert bad and "200 → 500" in notes
        bad, notes = canary.check_patch(inc, str(tmp_path / "srv" / "server.py"), app())
        assert not bad and "2 real request(s) replayed, all as before" in notes
        assert (tmp_path / "srv" / "server.py").read_text() == app()  # the live file is never touched
    finally:
        proc.terminate()


def test_canary_reports_the_attack_answer_without_touching_the_live_app(tmp_path):
    proc, spec = run_live(tmp_path)
    try:
        rec = TrafficRecorder()
        rec.add("GET", "/", {})
        rec.remember_attack("i2", Recorded("GET", "/?q=x'--", {}), 200, b"<h1>Products</h1>admin:hash")
        inc = Incident("i2", time.time(), "1.1.1.1", "GET", "/", "query", "q", "x'--", "sqli", 0.9, False, 0.1)
        bad, notes = Canary(spec, rec).check_patch(inc, str(tmp_path / "srv" / "server.py"), app())
        assert not bad and "the attack now gets a different answer" in notes
    finally:
        proc.terminate()


def test_canary_skips_apps_it_cannot_start(tmp_path):
    spec = AppSpec("x", "http://127.0.0.1:9", source=str(tmp_path))
    bad, notes = Canary(spec, TrafficRecorder()).check_patch(None, str(tmp_path / "a.py"), "")
    assert not bad and "skipped" in notes
