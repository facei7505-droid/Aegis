"""Aegis Gateway: one server, several apps, each with its own shield and healer."""
import json
import shutil
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from wsgiref.simple_server import make_server

import pytest

from aegis.gateway import AppSpec, Gateway, Proxy, serve

DEMO = Path(__file__).parents[1] / "aegis" / "demo_app" / "vulnshop"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def upstream(app):
    port = free_port()
    srv = make_server("127.0.0.1", port, app)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


def echo(environ, start_response):
    if environ["PATH_INFO"] == "/go":
        start_response("302 Found", [("Location", f"http://127.0.0.1:{environ['SERVER_PORT']}/landed")])
        return [b""]
    body = json.dumps({"path": environ["PATH_INFO"], "query": environ["QUERY_STRING"],
                       "host": environ.get("HTTP_HOST"), "xff": environ.get("HTTP_X_FORWARDED_FOR"),
                       "body": environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH") or 0)).decode()}).encode()
    start_response("200 OK", [("Content-Type", "application/json")])
    return [body]


def get(url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers)


@pytest.fixture
def two_apps():
    a_srv, a_port = upstream(echo)
    b_srv, b_port = upstream(echo)
    specs = [AppSpec("a", f"http://127.0.0.1:{a_port}", ["a.localhost"], free_port(), heal="off"),
             AppSpec("b", f"http://127.0.0.1:{b_port}", ["b.localhost"], None, shield="monitor", heal="off")]
    gw = Gateway(specs)
    main = free_port()
    servers = serve(gw, main)
    yield gw, main, specs
    for s in servers + [a_srv, b_srv]:
        s.shutdown()


def test_routes_by_host_and_by_port_and_forwards_exactly(two_apps):
    gw, main, specs = two_apps
    status, body, _ = get(f"http://127.0.0.1:{main}/x%2Fy?q=a%26b", headers={"Host": "a.localhost"})
    data = json.loads(body)
    assert status == 200 and data["query"] == "q=a%26b" and data["xff"] == "127.0.0.1"
    status, body, _ = get(f"http://127.0.0.1:{specs[0].listen}/hello", data=b"x=1")
    assert json.loads(body)["path"] == "/hello" and json.loads(body)["body"] == "x=1"


def test_each_app_has_its_own_shield(two_apps):
    gw, main, specs = two_apps
    attack = "/search?q=%27%20UNION%20SELECT%20password%20FROM%20users--"
    assert get(f"http://127.0.0.1:{main}{attack}", headers={"Host": "a.localhost"})[0] == 403  # block
    assert get(f"http://127.0.0.1:{main}{attack}", headers={"Host": "b.localhost"})[0] == 200  # monitor
    state = gw.snapshot()
    assert {e["app"] for e in state["events"]} == {"a", "b"}
    assert [a["blocked"] for a in state["apps"]] == [1, 0]


def test_redirects_stay_on_the_gateway(two_apps):
    gw, main, specs = two_apps
    req = urllib.request.Request(f"http://127.0.0.1:{main}/go", headers={"Host": "a.localhost"})
    opener = urllib.request.build_opener(type("NoRedirect", (urllib.request.HTTPRedirectHandler,),
                                              {"redirect_request": lambda *a, **k: None}))
    with pytest.raises(urllib.error.HTTPError) as exc:
        opener.open(req, timeout=5)
    assert exc.value.headers["Location"] == "http://a.localhost/landed"


def test_dashboard_and_api(two_apps):
    gw, main, _ = two_apps
    status, body, headers = get(f"http://127.0.0.1:{main}/")
    assert status == 200 and "Aegis Gateway" in body
    status, body, _ = get(f"http://127.0.0.1:{main}/_aegis/api/state")
    assert [a["name"] for a in json.loads(body)["apps"]] == ["a", "b"]


def test_dead_upstream_gives_502():
    port = free_port()
    gw = Gateway([AppSpec("dead", f"http://127.0.0.1:{free_port()}", ["dead.localhost"], heal="off")])
    servers = serve(gw, port)
    try:
        assert get(f"http://127.0.0.1:{port}/", headers={"Host": "dead.localhost"})[0] == 502
    finally:
        for s in servers:
            s.shutdown()


def test_gateway_heals_the_app_behind_it(tmp_path):
    """A real Flask app behind the gateway: the attack works once (monitor), is healed, then fails."""
    import importlib.util
    import os

    shop = tmp_path / "shop"
    shutil.copytree(DEMO, shop)
    os.environ["VULNSHOP_DB"] = str(shop / "shop.db")
    spec = importlib.util.spec_from_file_location("gw_shop", shop / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.init_db()
    srv, port = upstream(module.app)
    healed = []
    gw = Gateway([AppSpec("shop", f"http://127.0.0.1:{port}", ["shop.localhost"], source=str(shop),
                          shield="monitor", heal="auto")], on_healed=lambda s, rec: healed.append(rec.function))
    main = free_port()
    servers = serve(gw, main)
    try:
        attack = "/search?q=zzz%27%20UNION%20SELECT%20username%2C%20password_hash%20FROM%20users%20--"
        status, body, _ = get(f"http://127.0.0.1:{main}{attack}", headers={"Host": "shop.localhost"})
        assert "admin" in body
        end = time.time() + 10
        while not healed and time.time() < end:
            time.sleep(0.1)
        assert healed == ["search"]
        assert "WHERE name LIKE ?" in (shop / "app.py").read_text()
        events = gw.snapshot()["events"]
        assert events[0]["heal"] == "healed" and "search() patched" in events[0]["detail"] and events[0]["diff"]
    finally:
        for s in servers + [srv]:
            s.shutdown()


def test_config_file(tmp_path):
    from aegis.gateway import load_specs
    cfg = tmp_path / "gw.toml"
    cfg.write_text('[[app]]\nname = "x"\nupstream = "http://127.0.0.1:9"\nhosts = ["x.localhost"]\nlisten = 8181\n'
                   'source = "src"\nshield = "monitor"\nheal = "propose"\noptions = { ban_after = 0 }\n')
    spec = load_specs(str(cfg))[0]
    assert spec.name == "x" and spec.listen == 8181 and spec.source == str((tmp_path / "src").resolve())
    assert spec.options == {"ban_after": 0}
