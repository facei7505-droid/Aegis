"""Drop-in middleware: WSGI (Flask, Django) and ASGI (FastAPI, Starlette).

    app.wsgi_app = AegisShield(app.wsgi_app)                 # Flask
    application = AegisShield(get_wsgi_application())       # Django (wsgi.py)
    app = AegisShieldASGI(app)                              # FastAPI / Starlette
"""
from __future__ import annotations

import io
import tempfile
from typing import Callable, Iterable

from ..models import Incident
from .core import (MAX_BODY, ShieldConfig, ShieldCore, Verdict, block_body, is_multipart, oversize_is_suspicious,
                   multipart_fields)


class _ChainedInput:
    """wsgi.input replacement: bytes already read for inspection, then the rest of the stream."""

    def __init__(self, head, stream):
        self._head = io.BytesIO(head) if isinstance(head, (bytes, bytearray)) else head
        self._stream = stream

    def read(self, size: int = -1) -> bytes:
        data = self._head.read(size if size is not None and size >= 0 else -1)
        if size is None or size < 0:
            return data + self._stream.read()
        if len(data) < size:
            data += self._stream.read(size - len(data))
        return data

    def readline(self, size: int = -1) -> bytes:
        line = self._head.readline(size)
        if line.endswith(b"\n") or (size is not None and 0 <= size <= len(line)):
            return line
        rest = self._stream.readline(-1 if size is None or size < 0 else size - len(line))
        return line + rest

    def readlines(self, hint: int = -1) -> list[bytes]:
        return list(iter(self.readline, b""))

    def __iter__(self):
        return iter(self.readline, b"")


class AegisShield:
    """WSGI middleware."""

    def __init__(self, app, config: ShieldConfig | None = None,
                 on_incident: Iterable[Callable[[Incident], None]] = (), alerters: Iterable = (),
                 core: ShieldCore | None = None, **options):
        self.app = app
        self.core = core or ShieldCore(config or ShieldConfig(**options), on_incident, alerters)
        self.errors = 0

    @property
    def incidents(self) -> list[Incident]:
        return self.core.incidents

    def _read_body(self, environ, ctype: str):
        """(body to inspect, multipart fields or None, oversized). The app still gets every byte."""
        stream = environ.get("wsgi.input")
        if stream is None:
            return b"", None, False
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        chunked = "chunked" in environ.get("HTTP_TRANSFER_ENCODING", "").lower()
        if length <= 0 and not (chunked and environ.get("wsgi.input_terminated")):
            return b"", None, False
        if is_multipart(ctype):
            # Uploads can be large: spool to disk and stream through every text field.
            limit = self.core.config.max_upload
            spool = tempfile.SpooledTemporaryFile(max_size=MAX_BODY)
            remaining = length if length > 0 else limit + 1
            while remaining > 0 and spool.tell() <= limit:
                chunk = stream.read(min(64 * 1024, remaining))
                if not chunk:
                    break
                spool.write(chunk)
                remaining -= len(chunk)
            oversized = spool.tell() > limit
            spool.seek(0)
            fields = multipart_fields(spool, ctype)
            spool.seek(0)
            environ["wsgi.input"] = _ChainedInput(spool, stream) if oversized or chunked else spool
            return b"", fields, oversized
        if length > 0:
            if length <= MAX_BODY:
                body = stream.read(length)
                environ["wsgi.input"] = io.BytesIO(body)
                return body, None, False
            head = stream.read(MAX_BODY)
            environ["wsgi.input"] = _ChainedInput(head, stream)
            return head, None, True
        data = stream.read(MAX_BODY + 1)
        if len(data) > MAX_BODY:
            environ["wsgi.input"] = _ChainedInput(data, stream)
            return data[:MAX_BODY], None, True
        environ["wsgi.input"] = io.BytesIO(data)
        return data, None, False

    def __call__(self, environ, start_response):
        try:
            ctype = environ.get("CONTENT_TYPE", "")
            body, fields, oversized = self._read_body(environ, ctype)
            headers = {
                key[5:].replace("_", "-").lower(): value
                for key, value in environ.items() if key.startswith("HTTP_")
            }
            client = self.core.client_ip(environ.get("REMOTE_ADDR", "unknown"), headers.get("x-forwarded-for"))
            path = environ.get("PATH_INFO", "/")
            inputs = self.core.collect_inputs(path, environ.get("QUERY_STRING", ""), headers, body, ctype, fields)
            verdict = self.core.inspect(client, environ.get("REQUEST_METHOD", "GET"), path, inputs,
                                        oversized and oversize_is_suspicious(ctype, self.core.config))
        except Exception:  # a bug in the shield: count it, then follow the fail_open policy
            self.errors += 1
            if self.core.config.fail_open:
                return self.app(environ, start_response)
            verdict = Verdict(True, error=True)
        if verdict.blocked:
            return _wsgi_block(start_response, verdict)
        return self.app(environ, start_response)


def _wsgi_block(start_response, verdict: Verdict):
    payload = block_body(verdict)
    start_response("403 Forbidden", [
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(payload))),
        ("X-Aegis-Incident", verdict.incident.id if verdict.incident else ("error" if verdict.error else "ban")),
    ])
    return [payload]


class AegisShieldASGI:
    """ASGI middleware (HTTP scope only; websockets pass through)."""

    def __init__(self, app, config: ShieldConfig | None = None,
                 on_incident: Iterable[Callable[[Incident], None]] = (), alerters: Iterable = (),
                 core: ShieldCore | None = None, **options):
        self.app = app
        self.core = core or ShieldCore(config or ShieldConfig(**options), on_incident, alerters)
        self.errors = 0

    @property
    def incidents(self) -> list[Incident]:
        return self.core.incidents

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        headers = {}
        for raw_key, raw_value in scope.get("headers", []):
            key = raw_key.decode("latin-1").lower()
            value = raw_value.decode("latin-1")
            headers[key] = f"{headers[key]}; {value}" if key == "cookie" and key in headers else value

        ctype = headers.get("content-type", "")
        multipart = is_multipart(ctype)
        limit = self.core.config.max_upload if multipart else MAX_BODY
        head = bytearray()
        size = 0
        more = True
        messages = []
        while more:
            message = await receive()
            messages.append(message)
            if message["type"] != "http.request":
                break
            chunk = message.get("body", b"")
            size += len(chunk)
            if len(head) < limit:  # the head of every body is inspected, as in the WSGI shield
                head += chunk[: limit - len(head)]
            more = message.get("more_body", False)
        body = bytes(head)

        try:
            client = self.core.client_ip((scope.get("client") or ("unknown", 0))[0], headers.get("x-forwarded-for"))
            path = scope.get("path", "/")
            query = scope.get("query_string", b"").decode("latin-1")
            fields = multipart_fields(io.BytesIO(body), ctype) if multipart else None
            inputs = self.core.collect_inputs(path, query, headers, body, ctype, fields)
            verdict = self.core.inspect(client, scope.get("method", "GET"), path, inputs,
                                        size > limit and oversize_is_suspicious(ctype, self.core.config))
        except Exception:  # a bug in the shield: count it, then follow the fail_open policy
            self.errors += 1
            verdict = Verdict(not self.core.config.fail_open, error=True)
        if verdict.blocked:
            payload = block_body(verdict)
            await send({"type": "http.response.start", "status": 403, "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode()),
                (b"x-aegis-incident", (verdict.incident.id if verdict.incident else ("error" if verdict.error else "ban")).encode()),
            ]})
            await send({"type": "http.response.body", "body": payload})
            return

        replay = list(messages)

        async def replay_receive():
            if replay:
                return replay.pop(0)
            return await receive()

        return await self.app(scope, replay_receive, send)
