"""Reverse proxy to one origin, as a WSGI app. Standard library only.

Two ways to sit in front of a site:

* **Lab / local apps** (`preserve_host = false`, the default): the origin is a hidden local server
  (`http://127.0.0.1:5101`). The request goes there with the origin's own Host, and redirects that
  point at the hidden address are rewritten back to the public one.
* **Customer sites** (`preserve_host = true`): the origin is the site's real server, often shared
  hosting that picks the site by its Host header (`https://203.0.113.5` serving `shop.kz`). The
  public Host is kept, TLS to the origin uses the site's name for SNI and certificate checks, and
  the origin sees an ordinary HTTPS request, so the CMS needs no proxy settings.

Responses are streamed in 64 KB chunks, so large downloads do not sit in memory. When a recorder
is attached (the canary in `aegis range`), small responses are kept for replay.
"""
from __future__ import annotations

import http.client
import socket
import ssl
import threading
from dataclasses import dataclass
from typing import Callable, Iterator
from urllib.parse import urlsplit

from .shield.signing import ORIGIN_HEADER, origin_auth

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection",
              "te", "trailer", "trailers", "transfer-encoding", "upgrade", "host"}
CHUNK = 64 * 1024
KEEP_FOR_REPLAY = 512 * 1024  # bodies above this are streamed and not recorded
TAP_BYTES = 256 * 1024        # start of a streamed answer the response guard reads
TEXT_TYPES = ("text/html", "text/plain", "application/json", "text/xml", "application/xml", "application/xhtml")


def _textual(content_type: str | None, encoding: str) -> bool:
    ctype = (content_type or "").lower()
    return ctype.startswith(TEXT_TYPES) and encoding.strip().lower() in ("", "identity", "gzip", "x-gzip", "deflate")

ERROR_PAGE = """<!DOCTYPE html><html lang="ru"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>
<body style="font:16px/1.5 system-ui,sans-serif;max-width:34em;margin:12vh auto;padding:0 1.2em;color:#1d2b24">
<h1 style="font-size:26px;margin:0 0 .4em">{title}</h1><p>{text}</p>
<p style="color:#5b6b63;font-size:14px">{english}</p></body></html>"""


def error_page(status: str, title: str, text: str, english: str) -> tuple[str, list[tuple[str, str]], bytes]:
    body = ERROR_PAGE.format(title=title, text=text, english=english).encode("utf-8")
    return status, [("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(body))),
                    ("Cache-Control", "no-store")], body


@dataclass
class Origin:
    url: str                       # http://127.0.0.1:5001 or https://203.0.113.5
    preserve_host: bool = False    # send the public Host (customer sites) instead of the origin's
    tls_verify: bool = True        # check the origin's certificate against the site name
    sni: str | None = None         # name for SNI and the certificate check; default: the public Host
    connect_timeout: float = 10.0
    read_timeout: float = 60.0

    def __post_init__(self):
        u = urlsplit(self.url)
        self.scheme = (u.scheme or "http").lower()
        if self.scheme not in ("http", "https"):
            raise ValueError(f"origin must be http:// or https://, not {self.url!r}")
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if self.scheme == "https" else 80)


class _TLSConnection(http.client.HTTPSConnection):
    """HTTPS to an address with a separately chosen SNI name (connect to an IP, verify the domain)."""

    def __init__(self, host: str, port: int, server_name: str, context: ssl.SSLContext, timeout: float):
        super().__init__(host, port, timeout=timeout, context=context)
        self._server_name = server_name
        self._ctx = context

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._ctx.wrap_socket(sock, server_hostname=self._server_name)


class Proxy:
    """Forwards one request to the origin and streams the answer back."""

    def __init__(self, origin: Origin, name: str = "site",
                 on_response: Callable[[dict, str, dict, bytes | None, int, bytes | None], None] | None = None,
                 secret: str | None = None, guard: Callable | None = None):
        self.origin = origin
        self.name = name
        self.secret = secret  # origin lock: sign every request so the site's connector can refuse the rest
        # guard(environ, target, request headers, request body, status, body or its start, content encoding,
        #       complete) -> replacement (status line, headers, body) or None. See shield/response.py.
        self.guard = guard
        self.on_response = on_response  # (environ, target, headers, body, status, small response body)
        self._verified = ssl.create_default_context()
        self._unverified = ssl.create_default_context()
        self._unverified.check_hostname = False
        self._unverified.verify_mode = ssl.CERT_NONE
        self._local = threading.local()

    # ---------------------------------------------------------------- request --
    @staticmethod
    def target(environ) -> str:
        raw = environ.get("RAW_URI") or (environ.get("PATH_INFO", "/") +
                                         ("?" + environ["QUERY_STRING"] if environ.get("QUERY_STRING") else ""))
        if raw.startswith(("http://", "https://")):  # absolute-form request line
            parts = urlsplit(raw)
            raw = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        return raw or "/"

    def request_headers(self, environ) -> dict[str, str]:
        listed = {h.strip().lower() for h in environ.get("HTTP_CONNECTION", "").split(",") if h.strip()}
        headers: dict[str, str] = {}
        for key, value in environ.items():
            if key.startswith("HTTP_"):
                name = key[5:].replace("_", "-").title()
                low = name.lower()
                if low in HOP_BY_HOP or low in listed or low in ("x-forwarded-for", "x-real-ip") \
                        or low.startswith("x-aegis-"):  # only Aegis itself may speak for Aegis
                    continue
                headers[name] = value
        if environ.get("CONTENT_TYPE"):
            headers["Content-Type"] = environ["CONTENT_TYPE"]
        public_host = environ.get("HTTP_HOST") or f"{environ.get('SERVER_NAME', 'localhost')}:{environ.get('SERVER_PORT', '')}"
        o = self.origin
        default_port = (o.scheme == "https" and o.port == 443) or (o.scheme == "http" and o.port == 80)
        headers["Host"] = public_host if o.preserve_host else (o.host if default_port else f"{o.host}:{o.port}")
        client = environ.get("aegis.client_ip") or environ.get("REMOTE_ADDR", "")
        chain = environ.get("HTTP_X_FORWARDED_FOR", "")
        headers["X-Forwarded-For"] = f"{chain}, {environ.get('REMOTE_ADDR', '')}" if chain else environ.get("REMOTE_ADDR", "")
        headers["X-Real-Ip"] = client
        headers["X-Forwarded-Host"] = public_host
        headers["X-Forwarded-Proto"] = environ.get("HTTP_X_FORWARDED_PROTO") or environ.get("wsgi.url_scheme", "http")
        if self.secret:
            headers[ORIGIN_HEADER] = origin_auth(self.secret, public_host, client)
        if self.guard is not None and headers.get("Accept-Encoding"):
            # Answers are read for leaks: ask only for encodings Python can read (Caddy compresses for visitors).
            readable = [t for t in headers["Accept-Encoding"].split(",")
                        if t.split(";")[0].strip().lower() in ("gzip", "deflate", "identity")]
            headers["Accept-Encoding"] = ", ".join(t.strip() for t in readable) or "identity"
        return headers

    def _connection(self, environ) -> http.client.HTTPConnection:
        o = self.origin
        if o.scheme == "http":
            return http.client.HTTPConnection(o.host, o.port, timeout=o.connect_timeout)
        name = o.sni or (environ.get("HTTP_HOST", "").split(":")[0] if o.preserve_host else o.host) or o.host
        ctx = self._verified if o.tls_verify else self._unverified
        return _TLSConnection(o.host, o.port, name, ctx, o.connect_timeout)

    # --------------------------------------------------------------- response --
    def __call__(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET")
        target = self.target(environ)
        if environ.get("HTTP_UPGRADE"):
            status, headers, body = error_page(
                "501 Not Implemented", "WebSocket не поддерживается",
                "Этот адрес использует WebSocket, а защита сайта пока пропускает только обычные HTTP-запросы.",
                "WebSocket connections are not proxied.")
            start_response(status, headers)
            return [body]
        headers = self.request_headers(environ)
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        body = environ["wsgi.input"].read(length) if length > 0 else None
        if body is not None:
            headers["Content-Length"] = str(len(body))
        conn = self._connection(environ)
        try:
            conn.request(method, target, body=body, headers=headers)
            if conn.sock is not None:
                conn.sock.settimeout(self.origin.read_timeout)
            resp = conn.getresponse()
        except (OSError, http.client.HTTPException) as exc:
            conn.close()
            status, headers_out, page = error_page(
                "502 Bad Gateway", "Сайт временно недоступен",
                "Сервер сайта не ответил защите. Обычно это проходит за минуту: попробуйте обновить страницу.",
                f"The origin server did not answer ({exc.__class__.__name__}).")
            start_response(status, headers_out)
            return [page]

        listed = {h.strip().lower() for h in (resp.getheader("Connection") or "").split(",") if h.strip()}
        out: list[tuple[str, str]] = []
        public_host = headers.get("X-Forwarded-Host", "")
        for name, value in resp.getheaders():
            low = name.lower()
            if low in HOP_BY_HOP or low in listed or low == "content-length" or low.startswith("x-aegis-"):
                continue  # X-Aegis-Connector is for Aegis, not for visitors
            if low == "location" and not self.origin.preserve_host:
                value = self._public_location(value, public_host, environ)
            out.append((name, value))
        size = resp.getheader("Content-Length")
        no_body = method == "HEAD" or resp.status in (204, 304) or 100 <= resp.status < 200
        if no_body:
            out.append(("Content-Length", "0") if size is None else ("Content-Length", size))
            start_response(f"{resp.status} {resp.reason}", out)
            conn.close()
            self._report(environ, target, headers, body, resp.status, b"")
            return [b""]

        known = size is not None and size.isdigit()
        encoding = resp.getheader("Content-Encoding") or ""
        textual = self.guard is not None and _textual(resp.getheader("Content-Type"), encoding)
        if (self.on_response is not None or textual) and known and int(size) <= KEEP_FOR_REPLAY:
            data = resp.read()
            conn.close()
            self._report(environ, target, headers, body, resp.status, data)
            if textual:
                replacement = self._guard(environ, target, headers, body, resp.status, data, encoding, True)
                if replacement is not None:
                    status_line, replaced_headers, page = replacement
                    start_response(status_line, replaced_headers)
                    return [page]
            out.append(("Content-Length", str(len(data))))
            start_response(f"{resp.status} {resp.reason}", out)
            return [data]
        if known:
            out.append(("Content-Length", size))
        self._report(environ, target, headers, body, resp.status, None)
        start_response(f"{resp.status} {resp.reason}", out)
        tap = None
        if textual:  # too big or streamed: read its start on the way through (alerts only, it is already sent)
            def tap(prefix: bytes):
                self._guard(environ, target, headers, body, resp.status, prefix, encoding, False)
        return _Stream(resp, conn, tap)

    def _guard(self, *args):
        try:
            return self.guard(*args)
        except Exception:  # inspection must never break the response
            return None

    def _report(self, environ, target, headers, body, status, data):
        if self.on_response is not None:
            try:
                self.on_response(environ, target, headers, body, status, data)
            except Exception:  # recording must never break the response
                pass

    def _public_location(self, value: str, public_host: str, environ) -> str:
        o = self.origin
        scheme = environ.get("HTTP_X_FORWARDED_PROTO") or environ.get("wsgi.url_scheme", "http")
        for hidden in (f"{o.scheme}://{o.host}:{o.port}", f"{o.scheme}://localhost:{o.port}",
                       f"{o.scheme}://{o.host}" if o.port in (80, 443) else None):
            if hidden and (value == hidden or value.startswith(hidden + "/") or value.startswith(hidden + "?")):
                return f"{scheme}://{public_host}" + value[len(hidden):]
        return value


class _Stream:
    """WSGI response iterable: chunks from the origin, connection closed when done or abandoned."""

    def __init__(self, resp: http.client.HTTPResponse, conn: http.client.HTTPConnection,
                 tap: Callable[[bytes], None] | None = None):
        self.resp, self.conn, self.tap = resp, conn, tap

    def __iter__(self) -> Iterator[bytes]:
        seen = bytearray()
        try:
            while True:
                chunk = self.resp.read1(CHUNK) if hasattr(self.resp, "read1") else self.resp.read(CHUNK)
                if not chunk:
                    break
                if self.tap is not None and len(seen) < TAP_BYTES:
                    seen += chunk[:TAP_BYTES - len(seen)]
                yield chunk
        finally:
            self.close()
            if self.tap is not None and seen:
                tap, self.tap = self.tap, None
                tap(bytes(seen))

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass
