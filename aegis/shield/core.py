"""Framework-independent shield logic shared by the WSGI and ASGI adapters."""
from __future__ import annotations

import email.parser
import ipaddress
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
CHARGE_MS = 10.0  # inspection time worth one page view in the rate limit
_WARM = threading.Event()


def _warm_up() -> None:
    """Compile the big patterns (CRS tries) and load libinjection when the shield starts, not on the first
    visitor's request."""
    if not _WARM.is_set():
        _WARM.set()
        analyze([("query", "q", "x' or 1=1 -- /etc/passwd ;/bin/ls <a onclick=x>")], 1.0)
        from . import crs
        crs.restricted_path("/.env")
PHP_NAMED = ("query", "form", "multipart", "cookie")  # PHP renames these fields; JSON keys stay as sent
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
    trusted_proxies: tuple[str, ...] = ("127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                        "fc00::/7")  # ...and only from these addresses (your Caddy/nginx)
    proxy_hops: int = 1                 # proxies you run in front of the app; the client is that many from the right
    log_path: str | None = None         # JSON Lines incident log
    block_oversized: bool = True        # bodies above the inspection limit cannot hide payloads
    binary_uploads: bool = True         # ...except binary media (images, archives, octet-stream); set False
                                        # for apps that parse every body as a form whatever its type
    max_upload: int = 100 * 1024 * 1024  # multipart forms are inspected in full up to this size
    fail_open: bool = True              # on an internal shield error: serve (True) or refuse (False) the request
    max_incidents: int = 1000           # incidents kept in memory (the log file keeps all)
    learn: int = 0                      # learn this many clean requests, then flag what is unusual (0 = off)
    profile_path: str | None = None     # keep the learned traffic profile here (JSON) across restarts
    strict_paths: bool = False          # once learned, also flag paths never seen (good for closed apps and APIs)
    preset: str | None = None           # site policy: generic | wordpress | bitrix | opencart (see policy.py)
    rate_limit: int = 0                 # page requests per minute per client (files only when they 404; 0 = off)
    login_limit: int = 0                # login attempts per client inside login_window (0 = off)
    login_window: float = 600.0
    login_lockout: float = 1800.0       # login is refused this long; the rest of the site stays open
    editor_secret: str | None = None    # the site's connector signs editors (signing.py): forged "signed in"
                                        # cookies then relax nothing
    inspect_responses: bool = True      # read the origin's answers (response.py): leaks, confirmed attacks
    learned_path: str | None = None     # keep fields proven injectable here (JSON) across restarts


@dataclass
class Verdict:
    blocked: bool
    incident: Incident | None = None
    banned: bool = False
    error: bool = False  # the shield itself failed (see ShieldConfig.fail_open)
    status: int = 403    # 429 for rate limits
    retry_after: int = 0  # seconds, sent as Retry-After when set
    reason: str = ""     # why, when there is no incident (repeat hits of a lockout)


class ShieldCore:
    def __init__(self, config: ShieldConfig | None = None,
                 on_incident: Iterable[Callable[[Incident], None]] = (),
                 alerters: Iterable = (), shared=None, name: str = ""):
        self.config = config or ShieldConfig()
        self.shared = shared          # immunity.SharedBans: bans from the other sites on this server
        self.name = name
        self._pardoned: dict[str, float] = {}  # address -> shared ban this site's owner lifted for this site
        self.callbacks = list(on_incident)
        self.alerters = list(alerters)
        self.incidents: list[Incident] = []
        self.stats = {"requests": 0, "blocked": 0, "flagged": 0, "banned_hits": 0}
        self._strikes: dict[str, deque] = defaultdict(deque)
        self._banned: dict[str, float] = {}
        self._lock = threading.Lock()
        from .policy import preset as _preset
        self.policy = _preset(self.config.preset)
        self._proxy_nets = [ipaddress.ip_network(n, strict=False) for n in self.config.trusted_proxies]
        self._rate: dict[str, list] = {}               # client -> [window start, count]
        self._logins: dict[str, deque] = defaultdict(deque)
        self._locked: dict[str, float] = {}             # client -> login lockout end
        from .response import LearnedPatches
        self.learned = LearnedPatches(self.config.learned_path)
        _warm_up()
        self.profile = None
        if self.config.learn or self.config.profile_path:
            from .profile import TrafficProfile
            path = self.config.profile_path
            if path and Path(path).is_file():
                self.profile = TrafficProfile.load(path)
            else:
                self.profile = TrafficProfile(strict_paths=self.config.strict_paths)

    @property
    def learning(self) -> bool:
        return self.profile is not None and self.profile.learned < self.config.learn

    def profile_state(self) -> dict | None:
        if self.profile is None:
            return None
        return {"mode": "learning" if self.learning else "enforcing", "learned": self.profile.learned,
                "target": self.config.learn, "endpoints": len(self.profile.endpoints)}

    def _profile(self, path: str, inputs) -> Detection | None:
        """Learn from clean traffic until the target is reached, then flag what is unusual."""
        cfg = self.config
        if self.learning:
            self.profile.learn(path, inputs)
            done = self.profile.learned
            if cfg.profile_path and (done % 500 == 0 or done == cfg.learn):
                try:
                    self.profile.save(cfg.profile_path)
                except OSError:
                    pass
            return None
        found = self.profile.check(path, inputs)
        if found is None:
            return None
        limit = cfg.relaxed_threshold if found.param.lower() in cfg.relaxed_params else cfg.threshold
        if found.score < limit:
            return None
        return Detection("anomaly", found.score, found.reasons, found.value, found.location, found.param,
                         {"anomaly": found.score})

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
        from .policy import normalize_path
        served = normalize_path(path)  # /health/../admin is /admin to the origin, so it is /admin here
        if any(served == p.rstrip("/") or served.startswith(p.rstrip("/") + "/") for p in cfg.skip_paths) \
                and ".." not in path and "%" not in path:
            return Verdict(False)
        now = time.time()
        with self._lock:
            until = self._banned.get(client)
            if until and until > now:
                self.stats["banned_hits"] += 1
                return Verdict(cfg.mode == "block", banned=True)
            if until:
                del self._banned[client]
            if self.shared is not None:
                shared_until = self.shared.until(client, now)
                if shared_until and self._pardoned.get(client, 0) < shared_until:
                    self.stats["banned_hits"] += 1
                    return Verdict(cfg.mode == "block", banned=True)

        t0 = time.perf_counter()
        cpu0 = time.thread_time()  # this thread's CPU: waiting for other threads (GIL) is not the client's cost
        req = None
        if cfg.preset:  # a PHP site: judge fields under the names PHP gives them
            from .policy import php_name
            inputs = [(loc, php_name(n) if loc in PHP_NAMED else n, v) for loc, n, v in inputs]
        if self.policy is not None or cfg.rate_limit or cfg.login_limit:
            from .policy import Request, is_static
            req = Request.build(method, path, inputs, last=bool(cfg.preset))
            if cfg.editor_secret:
                from .signing import EDITOR_COOKIE, verify_editor
                value = next((v for loc, n, v in inputs if loc == "cookie" and n == EDITOR_COOKIE), "")
                req.editor = verify_editor(cfg.editor_secret, value)
            limited = self._limits(req, client, now, is_static)
            if limited is not None:
                return limited
            patch = self.policy.patch(req) if self.policy else None
            if patch is not None:
                det = Detection("virtual_patch", 1.0, [patch.name, patch.reason], req.route, "path", patch.name,
                                {"virtual_patch": 1.0})
                return self._incident(det, client, method, path, now, (time.perf_counter() - t0) * 1000)
        if len(self.learned):
            from .policy import normalize_path as _norm
            fields = {n: v for loc, n, v in inputs if loc in ("query", "form", "json", "multipart")}
            learned = self.learned.check(req.route if req is not None else _norm(path), fields)
            if learned is not None:
                det = Detection("injection_point", 1.0, ["confirmed injection point", learned["field"]],
                                fields.get(learned["field"], ""), "query", learned["field"], {"injection_point": 1.0})
                return self._incident(det, client, method, path, now, (time.perf_counter() - t0) * 1000)
        ignore = self.policy.ignored(req) if (self.policy is not None and req is not None) else None
        det = analyze(inputs, cfg.threshold, cfg.relaxed_params, cfg.relaxed_threshold, ignore)
        if det is None and oversized and cfg.block_oversized:
            det = Detection("oversized_body", 0.9, ["body larger than the inspection limit"],
                            "", "body", "body", {"oversized_body": 0.9})
        if det is None and self.profile is not None:
            det = self._profile(path, inputs)
        detect_ms = (time.perf_counter() - t0) * 1000
        cpu_ms = (time.thread_time() - cpu0) * 1000
        if cfg.rate_limit and cpu_ms > CHARGE_MS:
            self._charge(client, now, cpu_ms)
        if det is None:
            return Verdict(False)
        return self._incident(det, client, method, path, now, detect_ms)

    # ----------------------------------------------------------- limits --
    def _charge(self, client: str, now: float, detect_ms: float) -> None:
        """Expensive inspection counts toward the rate limit: every CHARGE_MS of it is one more page. A page
        takes well under a millisecond; 64 KB built to be slow takes a few hundred, so such requests run
        into the limit after a handful instead of costing a CPU core per attacker."""
        self.charge(client, detect_ms / CHARGE_MS, now)

    def charge(self, client: str, pages: float, now: float | None = None) -> None:
        """Count extra page views against a client's rate window (expensive inspection, fake files)."""
        if not self.config.rate_limit:
            return
        now = now if now is not None else time.time()
        with self._lock:
            window = self._rate.get(client)
            if window is None or now - window[0] >= 60:
                window = self._rate[client] = [now, 0.0, False]
            window[1] += pages
    def _limits(self, req, client: str, now: float, static) -> Verdict | None:
        """Login lockouts and request-rate limits. Both answer 429 and never ban the whole address."""
        cfg = self.config
        block = cfg.mode == "block"
        if cfg.rate_limit and not static(req.route):
            # Files are free here (the block editor alone pulls in a hundred scripts); the gateway charges the
            # ones the site answers with 404, since a CMS renders those as full pages (charge()).
            weight = 1.0
            with self._lock:
                window = self._rate.get(client)
                if window is None or now - window[0] >= 60:
                    if len(self._rate) > 50_000:
                        self._rate = {k: v for k, v in self._rate.items() if now - v[0] < 60}
                    window = self._rate[client] = [now, 0.0, False]
                window[1] += weight
                count, started = window[1], window[0]
                first = count > cfg.rate_limit and not window[2]
                if first:
                    window[2] = True
            if count > cfg.rate_limit:
                retry = max(1, int(60 - (now - started)))
                if first:  # one incident per window, not one per request
                    det = Detection("rate_limit", 1.0, [f"more than {cfg.rate_limit} page requests a minute"],
                                    req.route, "path", "rate", {"rate_limit": 1.0})
                    verdict = self._incident(det, client, req.method, req.path, now, 0.0, strike=False)
                    return Verdict(verdict.blocked, verdict.incident, status=429, retry_after=retry) if block else None
                return Verdict(True, status=429, retry_after=retry, reason="rate_limit") if block else None

        if cfg.login_limit and self.policy is not None and self.policy.is_login(req):
            with self._lock:
                until = self._locked.get(client, 0)
                if until > now:
                    locked_for = int(until - now)
                else:
                    locked_for = 0
                    attempts = self._logins[client]
                    attempts.append(now)
                    while attempts and now - attempts[0] > cfg.login_window:
                        attempts.popleft()
                    tripped = len(attempts) > cfg.login_limit
                    if tripped:
                        self._locked[client] = now + cfg.login_lockout
                        attempts.clear()
                    if len(self._logins) > 50_000:
                        for key in [k for k, v in self._logins.items() if not v]:
                            del self._logins[key]
            if locked_for:
                return Verdict(True, status=429, retry_after=locked_for, reason="brute_force") if block else None
            if tripped:
                det = Detection("brute_force", 1.0,
                                [f"more than {cfg.login_limit} login attempts in {int(cfg.login_window // 60)} min"],
                                req.route, "path", "login", {"brute_force": 1.0})
                verdict = self._incident(det, client, req.method, req.path, now, 0.0, strike=False)
                return Verdict(verdict.blocked, verdict.incident, status=429,
                               retry_after=int(cfg.login_lockout)) if block else None
        return None

    def report_response(self, finding, client: str, method: str, path: str, fields: dict[str, str],
                        replaced: bool = True):
        """The origin's answer showed a leak or a working attack (response.py). Returns the incident."""
        from .policy import normalize_path
        now = time.time()
        kind = finding.kind
        route = normalize_path(path.split("?")[0])
        if fields.get("rest_route"):  # WordPress serves the REST API on any URL
            route = "/wp-json" + normalize_path(fields["rest_route"])
        if kind == "sql_error" and finding.fields:
            for name in finding.fields:
                self.learned.learn(route, name, fields.get(name, ""), finding.evidence)
            attack, signals = "injection_point", ["confirmed injection point", ", ".join(finding.fields),
                                                  finding.evidence]
            value, param = fields.get(finding.fields[0], ""), finding.fields[0]
        elif kind in ("system_file", "web_shell"):
            attack, signals, value, param = ("exploit_confirmed", [kind, finding.evidence] + (["banned"] if finding.ban
                                             else []), finding.evidence, kind)
        else:
            attack, signals, value, param = "data_leak", [kind, finding.evidence], finding.evidence, kind
        det = Detection(attack, 1.0, signals, value, "response", param, {attack: 1.0})
        # Only the request decides about the requester: a reflected or merely shown leak must not ban a
        # visitor here and on every other site (shared immunity).
        strike = attack == "injection_point" or finding.ban
        blocked = finding.block and self.config.mode == "block" and replaced
        incident = self._incident(det, client, method, path, now, 0.0, strike=strike, blocked=blocked).incident
        if finding.ban and self.config.mode == "block" and self.config.ban_seconds:
            until = now + self.config.ban_seconds  # an attack that worked: no second try
            with self._lock:
                self._banned[client] = until
            if self.shared is not None:
                self.shared.ban(client, until, self.name)
        return incident

    def unlock(self, client: str) -> bool:
        """Lift every block on an address (ban, login lockout, rate window). True if one was active."""
        with self._lock:
            found = bool(self._banned.pop(client, None)) | bool(self._locked.pop(client, None))
            self._rate.pop(client, None)
            self._strikes.pop(client, None)
            self._logins.pop(client, None)
            if self.shared is not None:
                shared_until = self.shared.until(client)
                if shared_until:  # pardoned here; the other sites keep their protection
                    self._pardoned[client] = shared_until
                    found = True
        return found

    # --------------------------------------------------------- incidents --
    def _incident(self, det: Detection, client: str, method: str, path: str, now: float, detect_ms: float,
                  strike: bool = True, blocked: bool | None = None) -> Verdict:
        cfg = self.config
        blocked = cfg.mode == "block" if blocked is None else blocked
        incident = Incident(
            id=uuid.uuid4().hex[:12], timestamp=now, client=client, method=method, path=path,
            location=det.location, param=det.param, payload=mask(det.param, det.value)[:500],
            attack_type=det.attack_type, score=det.score, blocked=blocked, detect_ms=round(detect_ms, 3),
            signals=det.signals, classes=det.classes,
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
            if strike:
                strikes = self._strikes[client]
                strikes.append(now)
                while strikes and now - strikes[0] > cfg.ban_window:
                    strikes.popleft()
                if cfg.ban_after and len(strikes) >= cfg.ban_after:
                    self._banned[client] = now + cfg.ban_seconds
                    strikes.clear()
                    if self.shared is not None and cfg.mode == "block":  # learning sites do not ban others
                        self.shared.ban(client, now + cfg.ban_seconds, self.name)
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
        entry added by our own proxy (proxy_hops from the right) can be trusted, and only when the
        connection itself comes from one of our proxies (trusted_proxies): a client that reaches the
        shield directly must not be able to pick its own address, or someone else's."""
        if not (self.config.trust_proxy and forwarded_for) or not self._trusted_peer(peer):
            return peer
        hops = [h.strip() for h in forwarded_for.split(",") if h.strip()]
        n = max(1, self.config.proxy_hops)
        chosen = hops[-n] if len(hops) >= n else (hops[0] if hops else peer)
        try:
            return str(ipaddress.ip_address(chosen))
        except ValueError:  # "unknown", "1.2.3.4:5678", garbage: judge the connection instead
            return peer

    def _trusted_peer(self, peer: str) -> bool:
        try:
            ip = ipaddress.ip_address(peer)
        except ValueError:
            return False
        nets = self._proxy_nets
        return any(ip in net for net in nets)

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


BINARY_TYPES = ("application/octet-stream", "image/", "audio/", "video/", "font/", "application/zip",
                "application/gzip", "application/x-tar", "application/x-7z", "application/pdf")


def is_binary_type(content_type: str) -> bool:
    ctype = (content_type or "").lower()
    return any(t in ctype for t in BINARY_TYPES)


def oversize_is_suspicious(content_type: str, config: ShieldConfig) -> bool:
    """Whether a body above the inspection limit should be refused. Multipart has its own, larger
    limit; binary media may legitimately be large unless the app parses every body as a form."""
    if is_multipart(content_type):
        return True
    return not (is_binary_type(content_type) and config.binary_uploads)


def is_multipart(content_type: str) -> bool:
    """Forms with uploads: text fields are inspected, file contents are not, large is normal."""
    return "multipart/form-data" in (content_type or "").lower()


REASONS_RU = {
    "sqli": "попытка SQL-инъекции", "xss": "попытка внедрить скрипт (XSS)", "path_traversal": "попытка прочитать файлы сервера",
    "command_injection": "попытка выполнить команду на сервере", "ssti": "попытка внедрения в шаблон",
    "code_injection": "попытка выполнить код", "ssrf": "попытка обратиться к внутренним адресам",
    "recon": "сканирование уязвимостей", "header_injection": "подмена заголовков", "xxe": "атака через XML",
    "format_string": "атака через строку формата", "anomaly": "необычный запрос", "brute_force": "подбор пароля",
    "rate_limit": "слишком много запросов", "virtual_patch": "обращение к закрытому адресу",
    "injection_point": "атака на поле, через которое доступна база данных (подтверждено ответом сайта)",
    "exploit_confirmed": "атака удалась: сайт отдал системные данные или работает веб-шелл",
    "data_leak": "сайт показывает посетителям технические ошибки",
}

BLOCK_PAGE = """<!DOCTYPE html><html lang="ru"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Запрос остановлен</title>
<body style="font:16px/1.55 system-ui,sans-serif;max-width:36em;margin:12vh auto;padding:0 1.2em;color:#1d2b24">
<h1 style="font-size:26px;margin:0 0 .4em">Запрос остановлен защитой сайта</h1>
<p>{reason_ru}. Если вы просто пользовались сайтом, напишите владельцу и назовите код: <b>{code}</b>.</p>
<p style="color:#5b6b63;font-size:14px">This request was stopped by the site's protection ({reason}). Reference: {code}.</p>
</body></html>"""


SENSITIVE_NAME = re.compile(r"pass|pwd|secret|token|card|cvv|cvc|iin|ИИН|phone|tel|mail", re.I)
CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PHONE = re.compile(r"(?:\+7|8)[\s(-]*\d{3}[\s)-]*\d{3}[\s-]*\d{2}[\s-]*\d{2}")


def mask(name: str, value: str) -> str:
    """What is kept of a payload: the attack, not the visitor's personal data.

    Values of password, token, card, phone and e-mail fields are replaced; card numbers, e-mail
    addresses and Kazakhstani phone numbers inside any other value are masked."""
    if name and SENSITIVE_NAME.search(name):
        return f"[{len(value)} символов скрыто]"
    value = CARD.sub("[карта]", value)
    value = EMAIL.sub("[email]", value)
    return PHONE.sub("[телефон]", value)


def block_response(verdict: Verdict, accept: str = "") -> tuple[str, bytes]:
    """A page for browsers, JSON for everything else."""
    if "text/html" not in (accept or "").lower():
        return "application/json", block_body(verdict)
    inc = verdict.incident
    reason = "banned" if verdict.banned else ("error" if verdict.error else (inc.attack_type if inc else
                                                                            (verdict.reason or "attack")))
    if verdict.banned:
        reason_ru = "Ваш адрес временно заблокирован после повторных подозрительных запросов"
    elif verdict.error:
        reason_ru = "Запрос не удалось проверить"
    else:
        reason_ru = REASONS_RU.get(reason, "подозрительный запрос")
        reason_ru = reason_ru[:1].upper() + reason_ru[1:]
    code = inc.id if inc else reason
    import html
    page = BLOCK_PAGE.format(reason_ru=html.escape(reason_ru), reason=html.escape(reason), code=html.escape(code))
    return "text/html; charset=utf-8", page.encode("utf-8")


def block_body(verdict: Verdict) -> bytes:
    if verdict.reason and not verdict.incident:
        payload = {"error": "blocked by Aegis", "reason": verdict.reason}
        return json.dumps(payload).encode("utf-8")
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
