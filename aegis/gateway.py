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

Standard library only: wsgiref + http.client.
"""
from __future__ import annotations

import http.client
import json
import socketserver
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from .healer import Healer
from .models import Incident
from .shield import AegisShield, ShieldConfig

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
              "transfer-encoding", "upgrade", "content-length", "host"}


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


# ------------------------------------------------------------------ proxy --

class Proxy:
    """A small, correct reverse proxy as a WSGI app (one upstream)."""

    def __init__(self, spec: AppSpec, timeout: float = 30.0):
        self.spec = spec
        u = urlsplit(spec.upstream)
        self.host, self.port = u.hostname or "127.0.0.1", u.port or 80
        self.timeout = timeout

    def __call__(self, environ, start_response):
        raw = environ.get("RAW_URI") or (environ.get("PATH_INFO", "/") +
                                         ("?" + environ["QUERY_STRING"] if environ.get("QUERY_STRING") else ""))
        if raw.startswith("http://") or raw.startswith("https://"):  # absolute-form request line
            parts = urlsplit(raw)
            raw = parts.path + ("?" + parts.query if parts.query else "")
        headers = {}
        for key, value in environ.items():
            if key.startswith("HTTP_"):
                name = key[5:].replace("_", "-").title()
                if name.lower() not in HOP_BY_HOP:
                    headers[name] = value
        if environ.get("CONTENT_TYPE"):
            headers["Content-Type"] = environ["CONTENT_TYPE"]
        public_host = environ.get("HTTP_HOST", f"localhost:{environ.get('SERVER_PORT', '')}")
        headers["Host"] = f"{self.host}:{self.port}"
        headers["X-Forwarded-For"] = environ.get("REMOTE_ADDR", "")
        headers["X-Forwarded-Host"] = public_host
        headers["X-Forwarded-Proto"] = environ.get("wsgi.url_scheme", "http")
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        body = environ["wsgi.input"].read(length) if length > 0 else None
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            conn.request(environ.get("REQUEST_METHOD", "GET"), raw, body=body, headers=headers)
            resp = conn.getresponse()
        except OSError as exc:
            conn.close()
            msg = f"Aegis Gateway: {self.spec.name} is not reachable ({exc.__class__.__name__})".encode()
            start_response("502 Bad Gateway", [("Content-Type", "text/plain; charset=utf-8"),
                                               ("Content-Length", str(len(msg)))])
            return [msg]
        out = []
        for name, value in resp.getheaders():
            low = name.lower()
            if low in HOP_BY_HOP:
                continue
            if low == "location":  # keep redirects on the gateway, not on the hidden upstream
                for upstream in (f"http://{self.host}:{self.port}", f"http://localhost:{self.port}"):
                    if value.startswith(upstream):
                        value = f"http://{public_host}" + value[len(upstream):]
            out.append((name, value))
        data = resp.read()  # bodies of these apps are small; buffering keeps Content-Length exact
        conn.close()
        out.append(("Content-Length", str(len(data))))
        start_response(f"{resp.status} {resp.reason}", out)
        return [data]


# ---------------------------------------------------------------- gateway --

class Gateway:
    """Routes requests to apps; each app is wrapped in its own shield and healer."""

    def __init__(self, apps: list[AppSpec], on_healed: Callable[[AppSpec, object], None] | None = None,
                 log_dir: str | None = None, ai_fixer=None):
        self.apps = apps
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
        for spec in apps:
            callbacks = [lambda inc, s=spec: self._incident(s, inc)]
            if spec.source and spec.heal in ("auto", "propose"):
                healer = Healer(spec.source, mode=spec.heal, ai_fixer=ai_fixer, background=True)
                self.healers[spec.name] = healer
                callbacks.append(healer)
            log = str(Path(log_dir) / f"{spec.name}.incidents.jsonl") if log_dir else None
            config = ShieldConfig(mode=spec.shield, log_path=log, **{k: v for k, v in spec.options.items()
                                                                     if k in ShieldConfig.__dataclass_fields__})
            shield = AegisShield(Proxy(spec), config, on_incident=callbacks)
            self.shields[spec.name] = shield
            entry = (spec, shield)
            for host in spec.hosts:
                self.by_host[host.lower()] = entry
            if spec.listen:
                self.by_port[spec.listen] = entry
        threading.Thread(target=self._watch_healers, daemon=True).start()

    # -------------------------------------------------------------- WSGI --
    def __call__(self, environ, start_response):
        host = environ.get("HTTP_HOST", "").split(":")[0].lower()
        try:
            port = int(environ.get("SERVER_PORT") or 0)
        except ValueError:
            port = 0
        entry = self.by_port.get(port) or self.by_host.get(host)
        if entry is None:
            if environ.get("PATH_INFO", "/").startswith("/_aegis/api"):
                return self._api(environ, start_response)
            return self._dashboard(environ, start_response)
        spec, shield = entry
        with self._lock:
            self.requests[spec.name] += 1
        return shield(environ, start_response)

    # ----------------------------------------------------------- events --
    def _incident(self, spec: AppSpec, inc: Incident) -> None:
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
        elif rec.escalations:
            detail = rec.escalations[0].reason[:160]
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


# ------------------------------------------------------------------ server --

class _Handler(WSGIRequestHandler):
    def get_environ(self):
        env = super().get_environ()
        env["RAW_URI"] = self.path  # forward the request target byte-for-byte
        return env

    def log_message(self, *args):  # the dashboard is the log
        pass


class _ThreadingServer(socketserver.ThreadingMixIn, WSGIServer):
    daemon_threads = True
    allow_reuse_address = True


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
    import tomllib

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
