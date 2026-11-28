"""Site guard: Aegis looks at each protected site's home page every few minutes, the way a visitor would.

What it watches for (and tells the owner and the client in Telegram):
  * the site is down: two failed checks in a row (and again when it is back);
  * a script from a new outside domain on the page. That is how card skimmers (Magecart) and
    malicious redirects arrive in shops; a new widget the owner added looks the same, so this is an
    alert to confirm, never a block. Each new domain is reported once, then remembered;
  * an obfuscated script loader (eval(atob(...)), long String.fromCharCode chains, packed code) that
    was not there before;
  * SEO spam (casino, betting, pharmacy words that were not on the page before) and defacement
    ("hacked by ...", or a page title that changed completely).

The first look, and every look during the site's learning period, only records what is normal for
the site: its usual widgets (Yandex Metrika, Jivo, Kaspi, maps) never cause an alert.
"""
from __future__ import annotations

import html
import hashlib
import http.client
import json
import re
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import date
from html.parser import HTMLParser
from pathlib import Path

from ..shield.signing import ORIGIN_HEADER, origin_auth

SPAM = re.compile(
    r"(?<![\w-])(?:casino|казино|онлайн[- ]казино|слоты|игровые автоматы|viagra|виагра|cialis|сиалис|1xbet|1хбет|"
    r"pin-?up|mostbet|мостбет|vavada|вавада|joycasino|джойказино|порно|porn|xxx|ставки на спорт|букмекер|"
    r"kraken\d*|кракен|mega darknet|hydra\w*|гидра|займ без отказа|online pharmacy|buy cheap)(?![\w-])", re.I)
DEFACE = re.compile(r"hacked\s+by|owned\s+by|defaced\s+by|h4ck3d|hacked\s*!|взломан[оа]?\s+(?:by|кем|группой)", re.I)
LOADER = re.compile(
    r"eval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode|function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k)"
    r"|String\.fromCharCode\s*\((?:\s*\d{1,3}\s*,){24}|document\.write\s*\(\s*(?:unescape|atob)\s*\("
    r"|new\s+Function\s*\(\s*(?:atob|unescape)|(?:\\x[0-9a-fA-F]{2}){40}|atob\s*\(\s*['\"][A-Za-z0-9+/=]{300,}")


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts: list[str] = []      # external script URLs
        self.iframes: list[str] = []
        self.inline: list[str] = []       # inline script bodies
        self.title = ""
        self.text: list[str] = []
        self._in_script = False
        self._in_title = False
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
            else:
                self._in_script, self._buf = True, []
        elif tag == "iframe" and a.get("src"):
            self.iframes.append(a["src"])
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self.inline.append("".join(self._buf))
            self._in_script = False
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)
        elif self._in_title:
            self.title += data
        else:
            self.text.append(data)


def _host(url: str) -> str:
    m = re.match(r"^(?:https?:)?//([^/:?#]+)", url.strip(), re.I)
    return m.group(1).lower() if m else ""


def _same_site(host: str, domain: str) -> bool:
    base = domain.lower().removeprefix("www.")
    return host == base or host.endswith("." + base)


@dataclass
class Snapshot:
    status: int = 0
    ms: float = 0.0
    error: str = ""
    title: str = ""
    script_domains: list[str] = field(default_factory=list)
    iframe_domains: list[str] = field(default_factory=list)
    loaders: list[str] = field(default_factory=list)   # short hashes of obfuscated inline scripts
    spam: list[str] = field(default_factory=list)
    defaced: str = ""

    @property
    def up(self) -> bool:
        return not self.error and 0 < self.status < 500


def snapshot(html: str, domain: str, status: int = 200, ms: float = 0.0) -> Snapshot:
    page = _Page()
    try:
        page.feed(html[:3_000_000])
        page.close()
    except Exception:  # a broken page is still a page; keep what was parsed
        pass
    outside = lambda urls: sorted({h for h in map(_host, urls) if h and not _same_site(h, domain)})  # noqa: E731
    text = " ".join(page.text)
    loaders = sorted({hashlib.sha256(code.encode()).hexdigest()[:12] for code in page.inline if LOADER.search(code)})
    deface = DEFACE.search(page.title + " " + text[:20000])
    return Snapshot(status=status, ms=ms, title=re.sub(r"\s+", " ", page.title).strip()[:200],
                    script_domains=outside(page.scripts), iframe_domains=outside(page.iframes), loaders=loaders,
                    spam=sorted({m.group(0).lower() for m in SPAM.finditer(page.title + " " + text)}),
                    defaced=deface.group(0) if deface else "")


@dataclass
class Baseline:
    script_domains: set[str] = field(default_factory=set)
    loaders: set[str] = field(default_factory=set)
    spam: set[str] = field(default_factory=set)
    title: str = ""
    down_since: float = 0.0
    failures: int = 0
    reported_down: bool = False

    def to_json(self) -> dict:
        return {"script_domains": sorted(self.script_domains), "loaders": sorted(self.loaders),
                "spam": sorted(self.spam), "title": self.title, "down_since": self.down_since,
                "failures": self.failures, "reported_down": self.reported_down}

    @classmethod
    def from_json(cls, raw: dict) -> "Baseline":
        return cls(set(raw.get("script_domains", [])), set(raw.get("loaders", [])), set(raw.get("spam", [])),
                   raw.get("title", ""), raw.get("down_since", 0.0), raw.get("failures", 0),
                   raw.get("reported_down", False))


def _title_words(title: str) -> set[str]:
    return {w for w in re.findall(r"\w{3,}", title.lower())}


def compare(base: Baseline, snap: Snapshot, learning: bool, first: bool) -> list[tuple[str, str]]:
    """Findings (kind, Russian text) for one look; updates the baseline."""
    findings: list[tuple[str, str]] = []
    if not snap.up:
        base.failures += 1
        if base.failures == 1:
            base.down_since = time.time()
        if base.failures >= 2 and not base.reported_down:
            base.reported_down = True
            why = snap.error or f"ответ {snap.status}"
            findings.append(("down", f"сайт не отвечает ({why}). Проверьте сервер сайта или хостинг."))
        return findings
    if base.reported_down:
        minutes = int((time.time() - base.down_since) // 60)
        findings.append(("up", f"сайт снова работает (был недоступен около {max(minutes, 1)} мин)."))
    base.failures, base.reported_down = 0, False
    quiet = learning or first
    for domain in sorted(set(snap.script_domains) - base.script_domains):
        if not quiet:
            findings.append(("new_script", f"на главной появился скрипт с нового домена {domain}. Если вы его не "
                                           "добавляли (виджет, счётчик, оплата), так выглядит кража данных карт: "
                                           "проверьте шаблон сайта."))
        base.script_domains.add(domain)
    for code in sorted(set(snap.loaders) - base.loaders):
        if not quiet:
            findings.append(("loader", "в коде главной появился зашифрованный скрипт (eval/atob). Так прячут "
                                       "вредоносный код: покажите это разработчику."))
        base.loaders.add(code)
    new_spam = set(snap.spam) - base.spam
    if new_spam and not quiet:
        findings.append(("spam", "на главной появились слова, которых там не было: " + ", ".join(sorted(new_spam)) +
                         ". Так выглядит SEO-спам после взлома."))
    base.spam |= set(snap.spam)
    if snap.defaced:
        findings.append(("deface", f"на главной надпись «{snap.defaced}»: похоже, сайт взломан (дефейс)."))
    if base.title and snap.title and not quiet and not (_title_words(base.title) & _title_words(snap.title)):
        findings.append(("title", f"заголовок главной сменился целиком: «{base.title[:80]}» → «{snap.title[:80]}»."))
    if snap.title and (quiet or not base.title or _title_words(base.title) & _title_words(snap.title)):
        base.title = snap.title
    return findings


# ------------------------------------------------------------- fetching --

def fetch(site, timeout: float = 20.0) -> Snapshot:
    """The home page straight from the site's server, as Aegis sends it (signed for the connector)."""
    from ..proxy import Origin, _TLSConnection
    origin = Origin(site.origin, preserve_host=True, tls_verify=site.tls_verify)
    headers = {"Host": site.domain, "User-Agent": "Mozilla/5.0 (compatible; AegisGuard/1.0)",
               "Accept": "text/html", "Accept-Encoding": "identity", "X-Real-Ip": "127.0.0.1"}
    if site.secret:
        headers[ORIGIN_HEADER] = origin_auth(site.secret, site.domain, "127.0.0.1")
    t0 = time.time()
    try:
        if origin.scheme == "https":
            ctx = ssl.create_default_context()
            if not site.tls_verify:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            conn = _TLSConnection(origin.host, origin.port, site.domain, ctx, timeout)
        else:
            conn = http.client.HTTPConnection(origin.host, origin.port, timeout=timeout)
        conn.request("GET", "/", headers=headers)
        resp = conn.getresponse()
        body = resp.read(3_000_000)
        conn.close()
    except (OSError, http.client.HTTPException) as exc:
        return Snapshot(error=str(exc) or exc.__class__.__name__, ms=(time.time() - t0) * 1000)
    ms = (time.time() - t0) * 1000
    charset = re.search(r"charset=([\w-]+)", resp.getheader("Content-Type") or "", re.I)
    text = body.decode(charset.group(1) if charset else "utf-8", errors="replace")
    if resp.status in (301, 302, 303, 307, 308):
        return Snapshot(status=resp.status, ms=ms)
    return snapshot(text, site.domain, resp.status, ms)


class Guard:
    """Background loop over the edge's sites."""

    def __init__(self, edge, interval: float = 300.0, fetcher=fetch):
        self.edge = edge
        self.interval = interval
        self.fetcher = fetcher
        self.dir = Path(edge.home) / "guard"
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _load(self, domain: str) -> tuple[Baseline, bool]:
        path = self.dir / f"{domain}.json"
        if path.is_file():
            try:
                return Baseline.from_json(json.loads(path.read_text(encoding="utf-8"))), False
            except (OSError, ValueError):
                pass
        return Baseline(), True

    def _save(self, domain: str, base: Baseline) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / f"{domain}.json").write_text(json.dumps(base.to_json(), ensure_ascii=False), encoding="utf-8")

    def check(self, site) -> list[tuple[str, str]]:
        base, first = self._load(site.domain)
        snap = self.fetcher(site)
        findings = compare(base, snap, site.learning(date.today()), first)
        self._save(site.domain, base)
        bot = getattr(self.edge, "bot", None)
        for kind, text in findings:
            icon = {"down": "🔴", "up": "🟢", "deface": "🚨", "new_script": "⚠️", "loader": "⚠️", "spam": "⚠️",
                    "title": "⚠️"}.get(kind, "⚠️")
            # The texts quote the page (titles, words, domains): whoever hacked it controls them, so they are
            # escaped before Telegram reads the message as HTML (no injected links, no lost alerts).
            message = f"{icon} <b>{html.escape(site.domain)}</b>: {html.escape(text, quote=False)}"
            if bot is not None:
                for chat in {*self.edge.settings.owner_chats, *site.chats}:
                    bot.send(chat, message)
        return findings

    def run_once(self) -> dict[str, list]:
        results = {}
        for site in list(self.edge.sites.values()):
            if self._stop.is_set():
                break
            try:
                results[site.domain] = self.check(site)
            except Exception as exc:  # one site's trouble must not stop the others
                results[site.domain] = [("error", str(exc))]
        return results

    def start(self) -> None:
        def loop():
            while not self._stop.wait(5 if self._thread_first else self.interval):
                self._thread_first = False
                self.run_once()
        self._thread_first = True
        self._thread = threading.Thread(target=loop, name="aegis-guard", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
