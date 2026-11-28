"""Aegis Gateway: one server in front of many applications.

    browser / attacker ──► Aegis Gateway :8080 ──► shop    (Flask, any port)
                             │  shield per app   ├─► dsvw    (plain http.server)
                             │  healer per app   └─► legacy  (any language: shield only)
                             └─► dashboard  http://localhost:8080/_aegis

Every application gets its own shield (block or monitor) and, when Aegis can read its Python
source, its own healer (propose or auto). Apps in any language can sit behind the gateway; the
code-healing part needs Python source.

Routing is by Host header (`shop.localhost:8080`, `*.localhost` resolves to 127.0.0.1 in modern
browsers and curl) or by a dedicated port per app (`listen = 8081`).

Standard library only: wsgiref + http.client (see proxy.py).
"""
from __future__ import annotations

import hmac
import io
import json
import socketserver
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from wsgiref.simple_server import ServerHandler, WSGIRequestHandler, WSGIServer, make_server

from .canary import Canary, Recorded, TrafficRecorder
from .healer import Healer
from .models import Incident
from .proxy import Origin, Proxy
from .shield import AegisShield, ShieldConfig

_request = threading.local()  # set by the shield callback when the current request is an incident

@dataclass
class AppSpec:
    name: str
    upstream: str                          # http://127.0.0.1:5001
    hosts: list[str] = field(default_factory=list)
    listen: int | None = None              # optional extra port on the gateway for this app
    source: str | None = None              # Python source root, for healing
    shield: str = "block"                  # block | monitor
    heal: str = "propose"                  # auto | propose | off
    command: list[str] | None = None       # how `aegis range` starts it
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    options: dict = field(default_factory=dict)  # extra ShieldConfig settings, e.g. {ban_after = 0}
    preserve_host: bool = False            # customer sites: keep the public Host, TLS to the origin by site name
    tls_verify: bool = True                # check the origin certificate (https:// upstreams)
    sni: str | None = None                 # SNI / certificate name for the origin; default: the public Host
    origin_secret: str | None = None       # origin lock: sign forwarded requests (shield/signing.py)


# ------------------------------------------------------------------ proxy --

def make_proxy(spec: AppSpec, recorder: TrafficRecorder | None = None) -> Proxy:
    """The proxy for one app; with a recorder, clean traffic and attack answers are kept for the canary."""
    origin = Origin(spec.upstream, preserve_host=spec.preserve_host, tls_verify=spec.tls_verify, sni=spec.sni)

    def record(environ, target, headers, body, status, data):
        sent = Recorded(environ.get("REQUEST_METHOD", "GET"), target,
                        {k: v for k, v in headers.items()
                         if k not in ("Host", "Content-Length", "X-Real-Ip") and not k.startswith("X-Forwarded")}, body)
        incident = getattr(_request, "incident", None)
        if incident:  # an attack the shield let through (monitor): keep the answer for the canary
            recorder.remember_attack(incident, sent, status, data or b"")
        elif status < 400:
            recorder.add(sent.method, sent.target, sent.headers)

    return Proxy(origin, spec.name, on_response=record if recorder is not None else None, secret=spec.origin_secret)


# ---------------------------------------------------------------- gateway --

class Gateway:
    """Routes requests to apps; each app is wrapped in its own shield and healer."""

    def __init__(self, apps: list[AppSpec], on_healed: Callable[[AppSpec, object], None] | None = None,
                 log_dir: str | None = None, ai_fixer=None, dashboard_token: str | None = None):
        self.apps = apps
        # The dashboard shows attack payloads and patches of your source code. Without a token it is
        # served to this machine only; with one, to whoever presents the token.
        self.dashboard_token = dashboard_token
        self.by_host: dict[str, tuple[AppSpec, object]] = {}
        self.by_port: dict[int, tuple[AppSpec, object]] = {}
        self.healers: dict[str, Healer] = {}
        self.shields: dict[str, AegisShield] = {}
        self.events: deque = deque(maxlen=500)
        self.on_healed = on_healed
        self._lock = threading.Lock()
        self._seen_records: dict[str, int] = {}
        self.started = time.time()
        self.requests: dict[str, int] = {a.name: 0 for a in apps}
        self.recorders: dict[str, TrafficRecorder] = {}
        self.log_dir, self.ai_fixer = log_dir, ai_fixer
        self.on_incident: list[Callable[[AppSpec, Incident], None]] = []  # e.g. Telegram alerts, stats
        self.tls_names: Callable[[str], bool] | None = None  # answers Caddy's on-demand TLS question
        for spec in apps:
            self._mount(spec)
        threading.Thread(target=self._watch_healers, daemon=True).start()

    def _mount(self, spec: AppSpec) -> None:
        """Build the shield (and healer) for one app and route its hosts and port to it."""
        log_dir, ai_fixer = self.log_dir, self.ai_fixer
        callbacks = [lambda inc, s=spec: self._incident(s, inc)]
        recorder = self.recorders[spec.name] = TrafficRecorder()
        if spec.source and spec.heal in ("auto", "propose"):
            # Apps the gateway can start get a canary: patches must keep real traffic working.
            canary = Canary(spec, recorder) if spec.command and (spec.cwd or spec.source) else None
            healer = Healer(spec.source, mode=spec.heal, ai_fixer=ai_fixer, background=True, replay=canary)
            self.healers[spec.name] = healer
            callbacks.append(healer)
        log = str(Path(log_dir) / f"{spec.name}.incidents.jsonl") if log_dir else None
        options = {k: v for k, v in spec.options.items() if k in ShieldConfig.__dataclass_fields__}
        if options.get("learn") and log_dir and "profile_path" not in options:
            options["profile_path"] = str(Path(log_dir) / f"{spec.name}.profile.json")
        config = ShieldConfig(mode=spec.shield, log_path=log, **options)
        # Only apps that can heal need recorded traffic (the canary); other responses are streamed.
        proxy = make_proxy(spec, recorder if spec.name in self.healers else None)
        shield = AegisShield(proxy, config, on_incident=callbacks)
        self.shields[spec.name] = shield
        self.requests.setdefault(spec.name, 0)
        entry = (spec, shield)
        for host in spec.hosts:
            self.by_host[host.lower()] = entry
        if spec.listen:
            self.by_port[spec.listen] = entry

    def set_apps(self, apps: list[AppSpec]) -> dict[str, list[str]]:
        """Apply a new list of apps without a restart. Unchanged apps keep their shield, bans and
        counters; changed apps get a new shield; removed apps stop being routed.

        Routes are replaced in place, never removed first: a request arriving mid-reload reaches
        either the old shield or the new one, never "unknown host"."""
        with self._lock:
            old = {a.name: a for a in self.apps}
            new = {a.name: a for a in apps}
            added = [n for n in new if n not in old]
            removed = [n for n in old if n not in new]
            changed = [n for n in new if n in old and new[n] != old[n]]
            for name in changed:
                self.healers.pop(name, None)          # _mount adds it back if the app still heals
            for name in added + changed:
                self._mount(new[name])                # overwrites this app's host and port routes
            live_hosts = {h.lower() for a in apps for h in a.hosts}
            for host in [h for h in self.by_host if h not in live_hosts]:
                del self.by_host[host]
            live_ports = {a.listen for a in apps if a.listen}
            for port in [p for p in self.by_port if p not in live_ports]:
                del self.by_port[port]
            for name in removed:
                self.shields.pop(name, None)
                self.healers.pop(name, None)
            self.apps = list(apps)
        return {"added": added, "removed": removed, "changed": changed}

    # -------------------------------------------------------------- WSGI --
    def __call__(self, environ, start_response):
        host = environ.get("HTTP_HOST", "").split(":")[0].lower()
        path = environ.get("PATH_INFO", "/")
        if path in ("/_aegis/tls-ask", "/_aegis/health") and host not in self.by_host \
                and _private(environ.get("REMOTE_ADDR", "")):
            return self._service(path, environ, start_response)
        if path == "/_aegis/ping" and host in self.by_host:  # liveness for the failover watchdog; says nothing else
            start_response("204 No Content", [("X-Aegis-Edge", "alive"), ("Cache-Control", "no-store")])
            return [b""]
        try:
            port = int(environ.get("SERVER_PORT") or 0)
        except ValueError:
            port = 0
        entry = self.by_port.get(port) or self.by_host.get(host)
        if entry is None:
            allowed, set_cookie = self._dashboard_allowed(environ)
            if not allowed:
                body = b"Aegis Gateway: unknown host"
                start_response("404 Not Found", [("Content-Type", "text/plain"), ("Content-Length", str(len(body)))])
                return [body]
            if set_cookie:  # ?token=... once, then a cookie; the token leaves the address bar
                start_response("303 See Other", [("Location", "/"), ("Content-Length", "0"), ("Set-Cookie", set_cookie),
                                                 ("Cache-Control", "no-store")])
                return [b""]
            if environ.get("PATH_INFO", "/").startswith("/_aegis/api"):
                return self._api(environ, start_response)
            return self._dashboard(environ, start_response)
        spec, shield = entry
        with self._lock:
            self.requests[spec.name] += 1
        _request.incident = None
        try:
            return shield(environ, start_response)
        finally:
            _request.incident = None

    def _service(self, path: str, environ, start_response):
        """Local endpoints for the server's own tools: Caddy's on-demand TLS check and a health probe."""
        from urllib.parse import parse_qs
        if path == "/_aegis/health":
            body = json.dumps({"ok": True, "sites": len(self.apps), "uptime": round(time.time() - self.started)}).encode()
            start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
            return [body]
        domain = parse_qs(environ.get("QUERY_STRING", "")).get("domain", [""])[0].lower().rstrip(".")
        known = self.tls_names(domain) if self.tls_names else domain in self.by_host
        status = "200 OK" if known else "404 Not Found"
        start_response(status, [("Content-Type", "text/plain"), ("Content-Length", "0")])
        return [b""]

    def _dashboard_allowed(self, environ) -> tuple[bool, str | None]:
        from http.cookies import SimpleCookie
        from urllib.parse import parse_qs

        if not self.dashboard_token:
            return environ.get("REMOTE_ADDR", "") in ("127.0.0.1", "::1"), None
        given = parse_qs(environ.get("QUERY_STRING", "")).get("token", [""])[0]
        if given and hmac.compare_digest(given, self.dashboard_token):
            return True, f"aegis_dash={self.dashboard_token}; Path=/; HttpOnly; SameSite=Strict"
        jar = SimpleCookie()
        try:
            jar.load(environ.get("HTTP_COOKIE", ""))
        except Exception:
            return False, None
        cookie = jar.get("aegis_dash")
        return bool(cookie and hmac.compare_digest(cookie.value, self.dashboard_token)), None

    # ----------------------------------------------------------- events --
    def _incident(self, spec: AppSpec, inc: Incident) -> None:
        _request.incident = inc.id  # same thread: the proxy records the app's answer to this attack
        for hook in self.on_incident:
            try:
                hook(spec, inc)
            except Exception:  # a broken hook must never break a request
                pass
        with self._lock:
            self.events.appendleft({
                "id": inc.id, "time": inc.timestamp, "app": spec.name, "type": inc.attack_type,
                "method": inc.method, "path": inc.path, "param": inc.param, "payload": inc.payload[:300],
                "blocked": inc.blocked, "score": inc.score, "heal": "queued" if spec.name in self.healers else "shield only",
                "detail": "", "diff": "",
            })

    def _watch_healers(self) -> None:
        while True:
            time.sleep(0.25)
            for name, healer in list(self.healers.items()):
                records = healer.records
                start = self._seen_records.get(name, 0)
                for rec in records[start:]:
                    self._seen_records[name] = self._seen_records.get(name, 0) + 1
                    self._record(name, rec)

    def _record(self, name: str, rec) -> None:
        detail = ""
        if rec.patches:
            detail = f"{rec.function}() patched ({', '.join(sorted({p.finding.rule_id for p in rec.patches}))}) " \
                     f"in {rec.total_ms:.0f} ms"
            if rec.notes:
                detail += f" · {rec.notes}"
        elif rec.escalations:
            detail = rec.escalations[0].reason[:220]
        diff = "\n".join(p.diff for p in rec.patches if getattr(p, "diff", ""))[:6000]
        with self._lock:
            for ev in self.events:
                if ev["id"] == rec.incident.id and ev["app"] == name:
                    ev["heal"], ev["detail"], ev["diff"] = rec.status, detail, diff
                    break
        if rec.status == "healed" and self.on_healed:
            spec = next(a for a in self.apps if a.name == name)
            try:
                self.on_healed(spec, rec)
            except Exception:  # a failed restart must not stop the watcher
                pass

    # -------------------------------------------------------- dashboard --
    def snapshot(self) -> dict:
        with self._lock:
            events = list(self.events)
            requests = dict(self.requests)
        apps = []
        for spec in self.apps:
            shield = self.shields[spec.name]
            apps.append({
                "name": spec.name, "hosts": spec.hosts, "listen": spec.listen, "upstream": spec.upstream,
                "shield": spec.shield, "heal": spec.heal if spec.name in self.healers else "off",
                "requests": requests.get(spec.name, 0), "blocked": shield.core.stats.get("blocked", 0),
                "flagged": shield.core.stats.get("flagged", 0),
                "healed": sum(1 for r in self.healers[spec.name].records if r.status == "healed")
                if spec.name in self.healers else 0,
                "profile": shield.core.profile_state(),
            })
        return {"apps": apps, "events": events[:100], "uptime": round(time.time() - self.started)}

    def _api(self, environ, start_response):
        body = json.dumps(self.snapshot(), ensure_ascii=False).encode()
        start_response("200 OK", [("Content-Type", "application/json; charset=utf-8"),
                                  ("Cache-Control", "no-store"), ("Content-Length", str(len(body)))])
        return [body]

    def _dashboard(self, environ, start_response):
        body = DASHBOARD.encode()
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(body)))])
        return [body]


def _private(address: str) -> bool:
    """This machine or a private network (Caddy in a neighbouring Docker container)."""
    import ipaddress
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


# ------------------------------------------------------------------ server --

class _QuietServerHandler(ServerHandler):
    server_software = ""  # never announce "WSGIServer/0.2 CPython/3.x": the origin's own Server header passes


MAX_CHUNKED = 100 * 1024 * 1024


class _Handler(WSGIRequestHandler):
    server_version = "Aegis"
    sys_version = ""
    timeout = 30  # seconds a client may stay silent mid-request (slow-header and stalled-body clients)

    def handle(self):
        """Same as wsgiref's, with a handler that does not add its own Server header."""
        try:
            self.raw_requestline = self.rfile.readline(65537)
        except (TimeoutError, OSError):
            return
        if len(self.raw_requestline) > 65536:
            self.requestline = self.request_version = self.command = ""
            self.send_error(414)
            return
        if not self.parse_request():
            return
        try:
            environ = self.get_environ()
        except ValueError:  # a malformed or oversized chunked body
            self.send_error(400, "Bad chunked body")
            return
        except (TimeoutError, OSError):
            return
        stdin = environ.pop("aegis.stdin", None) or self.rfile
        handler = _QuietServerHandler(stdin, self.wfile, self.get_stderr(), environ, multithread=False)
        handler.request_handler = self
        handler.run(self.server.get_app())

    def get_environ(self):
        env = super().get_environ()
        env["RAW_URI"] = self.path  # forward the request target byte-for-byte
        if "chunked" in env.get("HTTP_TRANSFER_ENCODING", "").lower():
            # wsgiref does not de-chunk: without this the body would be neither inspected nor forwarded.
            body = _dechunk(self.rfile, MAX_CHUNKED)
            env["aegis.stdin"] = io.BytesIO(body)  # ServerHandler sets wsgi.input from its stdin
            env["CONTENT_LENGTH"] = str(len(body))
            env.pop("HTTP_TRANSFER_ENCODING", None)
        return env

    def log_message(self, *args):  # the dashboard is the log
        pass


def _dechunk(stream, limit: int) -> bytes:
    """Read a chunked request body (RFC 9112 7.1). Raises ValueError on a malformed or oversized body."""
    out = io.BytesIO()
    while True:
        line = stream.readline(1024)
        if not line:
            raise ValueError("chunked body ended early")
        size_text = line.split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            raise ValueError("bad chunk size") from None
        if size < 0 or out.tell() + size > limit:
            raise ValueError("chunked body too large")
        if size == 0:
            while True:  # trailer fields, then the empty line
                trailer = stream.readline(8192)
                if trailer in (b"\r\n", b"\n", b""):
                    return out.getvalue()
        out.write(stream.read(size))
        stream.readline(8)  # CRLF after the chunk


class _ThreadingServer(socketserver.ThreadingMixIn, WSGIServer):
    daemon_threads = True
    allow_reuse_address = True
    max_connections = 1024  # beyond this a new connection is closed at once instead of costing a thread

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(self.max_connections)
        super().__init__(*args, **kwargs)

    def server_bind(self):
        # HTTPServer.server_bind looks the host up with socket.getfqdn(): a reverse DNS query that can
        # take many seconds on a VPS or CI runner with slow DNS, all before the port starts listening.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name, self.server_port = str(host), port
        self.setup_environ()

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def serve(gateway: Gateway, port: int = 8080, host: str = "127.0.0.1") -> list:
    """Start the gateway on its main port and on every per-app port. Returns the servers."""
    servers = []
    for p in [port] + [a.listen for a in gateway.apps if a.listen]:
        srv = make_server(host, p, gateway, server_class=_ThreadingServer, handler_class=_Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
    return servers


def load_specs(path: str) -> list[AppSpec]:
    """Read a gateway config (TOML).

        [[app]]
        name = "shop"
        upstream = "http://127.0.0.1:5001"
        hosts = ["shop.localhost"]
        listen = 8081
        source = "./shop"
        shield = "block"
        heal = "propose"
    """
    from .config import tomllib
    if tomllib is None:
        raise SystemExit("aegis gateway reads TOML: use Python 3.11+ or `pip install tomli`")
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    base = Path(path).resolve().parent
    specs = []
    for raw in data.get("app", []):
        spec = AppSpec(**{k: v for k, v in raw.items() if k in AppSpec.__dataclass_fields__})
        if spec.source:
            spec.source = str((base / spec.source).resolve())
        if spec.cwd:
            spec.cwd = str((base / spec.cwd).resolve())
        specs.append(spec)
    return specs


DASHBOARD = (Path(__file__).parent / "gateway_dashboard.html").read_text(encoding="utf-8") \
    if (Path(__file__).parent / "gateway_dashboard.html").exists() else "<h1>Aegis Gateway</h1>"
