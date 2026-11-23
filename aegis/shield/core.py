"""Framework-independent shield logic shared by the WSGI and ASGI adapters."""
from __future__ import annotations

import email.parser
import email.policy
import io
import json
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import parse_qsl

from ..models import Incident
from .detectors import Detection, analyze

MAX_BODY = 1024 * 1024
RELAXED_PARAMS = {"password", "passwd", "pwd", "pass", "new_password", "current_password", "csrf_token", "token"}
SCANNED_HEADERS = {"user-agent", "referer", "x-forwarded-host", "x-original-url", "x-rewrite-url"}


@dataclass
class ShieldConfig:
    mode: str = "block"                 # "block" | "monitor"
    threshold: float = 0.8
    relaxed_params: set[str] = field(default_factory=lambda: set(RELAXED_PARAMS))
    relaxed_threshold: float = 0.97
    skip_paths: tuple[str, ...] = ("/health", "/healthz", "/metrics")
    ban_after: int = 3                  # incidents from one client inside ban_window -> ban
    ban_window: float = 600.0
    ban_seconds: float = 900.0
    trust_proxy: bool = False           # honour X-Forwarded-For (only behind your own proxy)
    proxy_hops: int = 1                 # proxies you run in front of the app; the client is that many from the right
    log_path: str | None = None         # JSON Lines incident log
    block_oversized: bool = True        # bodies above the inspection limit cannot hide payloads
    max_upload: int = 100 * 1024 * 1024  # multipart forms are inspected in full up to this size
    fail_open: bool = True              # on an internal shield error: serve (True) or refuse (False) the request
    max_incidents: int = 1000           # incidents kept in memory (the log file keeps all)


@dataclass
class Verdict:
    blocked: bool
    incident: Incident | None = None
    banned: bool = False
    error: bool = False  # the shield itself failed (see ShieldConfig.fail_open)


class ShieldCore:
    def __init__(self, config: ShieldConfig | None = None,
                 on_incident: Iterable[Callable[[Incident], None]] = (),
                 alerters: Iterable = ()):
        self.config = config or ShieldConfig()
        self.callbacks = list(on_incident)
        self.alerters = list(alerters)
        self.incidents: list[Incident] = []
        self.stats = {"requests": 0, "blocked": 0, "flagged": 0, "banned_hits": 0}
        self._strikes: dict[str, deque] = defaultdict(deque)
        self._banned: dict[str, float] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------- inputs --
    @staticmethod
    def collect_inputs(path: str, query: str, headers: dict[str, str], body: bytes,
                       content_type: str, form_fields: list[tuple[str, str, str]] | None = None
                       ) -> list[tuple[str, str, str]]:
        """Every value the application might read. Parsing never raises: input the shield cannot
        parse is inspected as raw text instead, so a malformed body cannot switch inspection off."""
        inputs: list[tuple[str, str, str]] = [("path", "path", path)]
        for k, v in parse_qsl(query, keep_blank_values=True):
            inputs.append(("query", k, v))
        for name, value in headers.items():
            low = name.lower()
            if low == "cookie":
                try:
                    jar = SimpleCookie()
                    jar.load(value)
                    cookies = [("cookie", key, morsel.value) for key, morsel in jar.items()]
                except Exception:
                    cookies = []
                inputs.extend(cookies or [("header", "cookie", value)])
            elif low in SCANNED_HEADERS:
                inputs.append(("header", low, value))
        if form_fields is not None:
            inputs.extend(form_fields)
        elif body:
            try:
                inputs.extend(_body_inputs(body, content_type))
            except Exception:
                inputs.append(("body", "body", body.decode("utf-8", errors="replace")))
        return inputs

    # ------------------------------------------------------------ verdict --
    def inspect(self, client: str, method: str, path: str, inputs: list[tuple[str, str, str]],
                oversized: bool = False) -> Verdict:
        cfg = self.config
        with self._lock:
            self.stats["requests"] += 1
        if any(path == p or path.startswith(p.rstrip("/") + "/") for p in cfg.skip_paths):
            return Verdict(False)
        now = time.time()
        with self._lock:
            until = self._banned.get(client)
            if until and until > now:
                self.stats["banned_hits"] += 1
                return Verdict(cfg.mode == "block", banned=True)
            if until:
                del self._banned[client]

        t0 = time.perf_counter()
        det = analyze(inputs, cfg.threshold, cfg.relaxed_params, cfg.relaxed_threshold)
        if det is None and oversized and cfg.block_oversized:
            det = Detection("oversized_body", 0.9, ["body larger than the inspection limit"],
                            "", "body", "body", {"oversized_body": 0.9})
        detect_ms = (time.perf_counter() - t0) * 1000
        if det is None:
            return Verdict(False)

        blocked = cfg.mode == "block"
        incident = Incident(
            id=uuid.uuid4().hex[:12], timestamp=now, client=client, method=method, path=path,
            location=det.location, param=det.param, payload=det.value[:500], attack_type=det.attack_type,
            score=det.score, blocked=blocked, detect_ms=round(detect_ms, 3), signals=det.signals,
            classes=det.classes,
        )
        with self._lock:
            self.incidents.append(incident)
            if len(self.incidents) > cfg.max_incidents:
                del self.incidents[: len(self.incidents) - cfg.max_incidents]
            self.stats["blocked" if blocked else "flagged"] += 1
            if len(self._strikes) > 10_000:  # forget clients with no recent strikes
                for key in [k for k, v in self._strikes.items() if not v or now - v[-1] > cfg.ban_window]:
                    del self._strikes[key]
                for key in [k for k, until in self._banned.items() if until <= now]:
                    del self._banned[key]
            strikes = self._strikes[client]
            strikes.append(now)
            while strikes and now - strikes[0] > cfg.ban_window:
                strikes.popleft()
            if cfg.ban_after and len(strikes) >= cfg.ban_after:
                self._banned[client] = now + cfg.ban_seconds
                strikes.clear()
        self._log(incident)
        for alerter in self.alerters:
            try:
                alerter.send(incident)
            except Exception:
                pass
        for callback in self.callbacks:
            try:
                callback(incident)
            except Exception:
                pass
        return Verdict(blocked, incident)

    def client_ip(self, peer: str, forwarded_for: str | None) -> str:
        """The address to judge. X-Forwarded-For is a list the client can prepend to, so only the
        entry added by our own proxy (proxy_hops from the right) can be trusted."""
        if not (self.config.trust_proxy and forwarded_for):
            return peer
        hops = [h.strip() for h in forwarded_for.split(",") if h.strip()]
        n = max(1, self.config.proxy_hops)
        return hops[-n] if len(hops) >= n else (hops[0] if hops else peer)

    def is_banned(self, client: str) -> bool:
        until = self._banned.get(client)
        return bool(until and until > time.time())

    def _log(self, incident: Incident) -> None:
        if not self.config.log_path:
            return
        path = Path(self.config.log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(incident.to_dict(), ensure_ascii=False) + "\n")


INSPECTED_TYPES = ("application/x-www-form-urlencoded", "json", "text/", "xml")


def is_inspected_type(content_type: str) -> bool:
    """Bodies whose every byte is application input (an oversized one is suspicious)."""
    ctype = (content_type or "").lower()
    return any(t in ctype for t in INSPECTED_TYPES)


def is_multipart(content_type: str) -> bool:
    """Forms with uploads: text fields are inspected, file contents are not, large is normal."""
    return "multipart/form-data" in (content_type or "").lower()


def block_body(verdict: Verdict) -> bytes:
    if verdict.banned:
        payload = {"error": "blocked by Aegis", "reason": "client temporarily banned after repeated attacks"}
    elif verdict.error:
        payload = {"error": "blocked by Aegis", "reason": "request could not be inspected"}
    else:
        inc = verdict.incident
        payload = {"error": "blocked by Aegis", "reason": inc.attack_type if inc else "attack", "incident": inc.id if inc else None}
    return json.dumps(payload).encode("utf-8")


def _body_inputs(body: bytes, content_type: str) -> list[tuple[str, str, str]]:
    ctype = (content_type or "").lower()
    text = body.decode("utf-8", errors="replace")
    if "application/x-www-form-urlencoded" in ctype:
        return [("form", k, v) for k, v in parse_qsl(text, keep_blank_values=True)]
    if "json" in ctype:
        try:
            return [("json", k, v) for k, v in _flatten_json(json.loads(text))]
        except (ValueError, RecursionError):
            return [("body", "body", text)]
    if "multipart/form-data" in ctype:
        return multipart_fields(io.BytesIO(body), content_type)
    return [("body", "body", text)]


def _flatten_json(data, max_values: int = 10_000):
    """Leaf values of a JSON document with their paths. Iterative, so deep nesting cannot crash it."""
    out, stack = [], [("", data)]
    while stack and len(out) < max_values:
        prefix, node = stack.pop()
        if isinstance(node, dict):
            stack.extend((f"{prefix}.{k}" if prefix else str(k), v) for k, v in reversed(list(node.items())))
        elif isinstance(node, list):
            stack.extend((f"{prefix}[{i}]", v) for i, v in reversed(list(enumerate(node))))
        elif node is not None:
            out.append((prefix or "value", str(node)))
    return out


_BOUNDARY = re.compile(r'boundary=(?:"([^"]+)"|([^;\s]+))', re.I)
FIELD_LIMIT = 256 * 1024  # bytes of one text field that are inspected


def multipart_fields(stream, content_type: str) -> list[tuple[str, str, str]]:
    """Text fields and upload file names of a multipart form, read from a file-like object.

    Streams through the whole body, so a large upload placed before a text field cannot hide it.
    File contents are skipped: they are data, not input to the application. Values are decoded as
    UTF-8, the way Werkzeug, Django and Starlette read them, plus the declared charset if different.
    """
    m = _BOUNDARY.search(content_type or "")
    if not m:
        data = stream.read(MAX_BODY)
        return [("body", "body", data.decode("utf-8", errors="replace"))]
    delim = b"--" + (m.group(1) or m.group(2)).encode("latin-1")
    keep = len(delim) + 4
    fields: list[tuple[str, str, str]] = []
    buf, state, value = b"", "preamble", bytearray()
    name, charset = "field", None

    def finish(raw: bytes) -> None:
        raw = raw[:-2] if raw.endswith(b"\r\n") else raw
        fields.append(("form", name, raw.decode("utf-8", errors="replace")))
        if charset and charset.lower().replace("-", "") not in ("utf8", "usascii", "ascii"):
            try:
                fields.append(("form", name, raw.decode(charset, errors="replace")))
            except LookupError:
                pass

    while True:
        chunk = stream.read(64 * 1024)
        buf += chunk
        while True:
            if state in ("preamble", "skip", "value"):
                idx = buf.find(delim)
                if idx == -1:
                    cut = max(0, len(buf) - keep)
                    if state == "value" and len(value) < FIELD_LIMIT:
                        value += buf[:cut][: FIELD_LIMIT - len(value)]
                    buf = buf[cut:]
                    break
                if state == "value":
                    value += buf[:idx][: max(0, FIELD_LIMIT - len(value))]
                    finish(bytes(value))
                buf, state = buf[idx + len(delim):], "headers"
            if state == "headers":
                if buf.startswith(b"--"):
                    return fields
                end = buf.find(b"\r\n\r\n")
                if end == -1:
                    if len(buf) > 16 * 1024:  # absurd part headers: skip the part
                        buf, state = buf[-keep:], "skip"
                        continue
                    break
                raw_headers = buf[:end].decode("utf-8", errors="replace")
                buf = buf[end + 4:]
                part = email.parser.Parser(policy=email.policy.HTTP).parsestr(raw_headers.lstrip("\r\n") + "\r\n\r\n")
                name = part.get_param("name", header="content-disposition") or "field"
                filename = part.get_filename()
                charset = part.get_content_charset()
                if filename is not None:
                    fields.append(("form", f"{name}.filename", filename))
                    state = "skip"
                else:
                    value, state = bytearray(), "value"
        if not chunk:
            if state == "value":
                finish(bytes(value) + buf)
            return fields
