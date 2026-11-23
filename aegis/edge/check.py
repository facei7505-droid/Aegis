"""Passive site check: what anyone can see about a site's security from its public pages.

Only ordinary GET requests to pages any visitor opens (the home page, the login page of the CMS it
runs, plain-HTTP redirect). No payloads, no probing for files: it is safe to run on a site before
its owner is a client, and the result is something to show them.

    aegis check shop.kz                 # text in Russian
    aegis check shop.kz --json
    aegis check shop.kz --pdf shop.pdf  # one page to send to the owner
"""
from __future__ import annotations

import http.client
import io
import re
import socket
import ssl
import time
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from urllib.parse import urljoin, urlsplit

from .sites import normalize_domain

UA = "Mozilla/5.0 (compatible; AegisCheck/1.0; passive security check)"
PHP_EOL = {"5": date(2018, 12, 31), "7.0": date(2019, 1, 10), "7.1": date(2019, 12, 1), "7.2": date(2020, 11, 30),
           "7.3": date(2021, 12, 6), "7.4": date(2022, 11, 28), "8.0": date(2023, 11, 26), "8.1": date(2025, 12, 31),
           "8.2": date(2026, 12, 31), "8.3": date(2027, 12, 31), "8.4": date(2028, 12, 31), "8.5": date(2029, 12, 31)}
WEIGHT = {"high": 20, "medium": 8, "low": 3}


@dataclass
class Finding:
    severity: str           # high | medium | low | ok
    title: str
    detail: str = ""
    fix: str = ""


@dataclass
class Result:
    target: str
    url: str = ""
    status: int = 0
    cms: str = ""
    cms_version: str = ""
    server: str = ""
    https: bool = False
    cert_days: int | None = None
    findings: list[Finding] = field(default_factory=list)
    checked: str = ""
    error: str = ""

    @property
    def score(self) -> int:
        return max(0, 100 - sum(WEIGHT.get(f.severity, 0) for f in self.findings))

    @property
    def grade(self) -> str:
        s = self.score
        return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"

    def to_dict(self) -> dict:
        return {**asdict(self), "score": self.score, "grade": self.grade}


@dataclass
class Page:
    url: str
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    cert: dict | None = None
    tls_error: str = ""

    def header(self, name: str) -> str:
        name = name.lower()
        return ", ".join(v for k, v in self.headers if k.lower() == name)

    def cookies(self) -> list[str]:
        return [v for k, v in self.headers if k.lower() == "set-cookie"]


def fetch(url: str, timeout: float = 12.0, verify: bool = True, connect_to: str | None = None) -> Page:
    """One GET, no redirects followed. `connect_to` sends it to another address (tests, origins)."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    address = connect_to or host
    cert, tls_error = None, ""
    if parts.scheme == "https":
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        raw = socket.create_connection((address, port), timeout)
        try:
            sock = ctx.wrap_socket(raw, server_hostname=host)
        except ssl.SSLCertVerificationError as exc:
            raw.close()
            if not verify:
                raise
            page = fetch(url, timeout, verify=False, connect_to=connect_to)
            page.tls_error = exc.verify_message or str(exc)
            return page
        cert = sock.getpeercert() if verify else None
        conn = http.client.HTTPSConnection(host, port, timeout=timeout)
        conn.sock = sock
    else:
        conn = http.client.HTTPConnection(address, port, timeout=timeout)
    try:
        conn.request("GET", target, headers={"Host": parts.netloc, "User-Agent": UA, "Accept": "text/html,*/*",
                                             "Accept-Language": "ru,kk;q=0.9,en;q=0.8"})
        resp = conn.getresponse()
        body = resp.read(400_000)
        return Page(url, resp.status, resp.getheaders(), body, cert, tls_error)
    finally:
        conn.close()


def follow(url: str, hops: int = 5, **kw) -> tuple[Page, list[str]]:
    chain = []
    page = fetch(url, **kw)
    while page.status in (301, 302, 303, 307, 308) and hops > 0:
        location = page.header("location")
        if not location:
            break
        url = urljoin(url, location)
        chain.append(url)
        page = fetch(url, **kw)
        hops -= 1
    return page, chain


CMS_SIGNS = [
    ("WordPress", re.compile(rb"/wp-content/|/wp-includes/|wp-json", re.I),
     re.compile(rb'<meta name="generator" content="WordPress ([\d.]+)', re.I)),
    ("1С-Битрикс", re.compile(rb"/bitrix/(?:js|templates|cache|components)/|BX\.message|bxSession", re.I), None),
    ("OpenCart", re.compile(rb"catalog/view/(?:theme|javascript)|route=common/home|index\.php\?route=", re.I), None),
    ("Tilda", re.compile(rb"tildacdn\.|tilda\.ws|data-tilda-", re.I), None),
    ("Joomla", re.compile(rb"/media/jui/|/media/system/js/|Joomla!", re.I),
     re.compile(rb'<meta name="generator" content="Joomla! ([\d.]+)', re.I)),
    ("Drupal", re.compile(rb"/sites/default/files/|Drupal\.settings|data-drupal-", re.I),
     re.compile(rb'<meta name="Generator" content="Drupal (\d+)', re.I)),
    ("Shopify", re.compile(rb"cdn\.shopify\.com", re.I), None),
    ("Next.js", re.compile(rb"__NEXT_DATA__|/_next/static/", re.I), None),
]


def detect_cms(page: Page) -> tuple[str, str]:
    for name, sign, version in CMS_SIGNS:
        if sign.search(page.body):
            found = version.search(page.body) if version else None
            return name, found.group(1).decode() if found else ""
    cookies = " ".join(page.cookies()).lower()
    if "bitrix_sm" in cookies:
        return "1С-Битрикс", ""
    if "laravel_session" in cookies:
        return "Laravel", ""
    if "csrftoken" in cookies:
        return "Django", ""
    return "", ""


def php_version(page: Page) -> str:
    m = re.search(r"PHP/(\d+)\.(\d+)", page.header("x-powered-by") + " " + page.header("server"))
    return f"{m.group(1)}.{m.group(2)}" if m else ""


def check(target: str, timeout: float = 12.0, connect_to: str | None = None, today: date | None = None) -> Result:
    today = today or date.today()
    if "://" in target:
        domain, start = normalize_domain(urlsplit(target).hostname or ""), target
    else:
        domain = normalize_domain(target)
        start = f"https://{domain}/"
    result = Result(target=domain, checked=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    add = result.findings.append

    # 1. HTTPS: the page, the certificate, and whether plain HTTP sends visitors there.
    page = None
    try:
        page, chain = follow(start, timeout=timeout, connect_to=connect_to)
        result.https = page.url.startswith("https://")
    except (OSError, http.client.HTTPException) as exc:
        add(Finding("high", "Сайт не открывается по HTTPS",
                    f"Соединение по https:// не удалось ({exc.__class__.__name__}).",
                    "Подключите бесплатный сертификат Let's Encrypt (у хостинга или через защиту сайта)."))
    if page is None and start.startswith("https://"):
        try:
            page, chain = follow(f"http://{domain}/", timeout=timeout, connect_to=connect_to)
        except (OSError, http.client.HTTPException) as exc:
            result.error = f"Сайт не ответил: {exc.__class__.__name__}"
            return result
    if page is None:
        result.error = "Сайт не ответил"
        return result
    result.url, result.status = page.url, page.status
    result.server = page.header("server")[:80]

    if result.https:
        if page.tls_error:
            add(Finding("high", "Сертификат HTTPS не принимается браузерами", page.tls_error,
                        "Выпустите действительный сертификат для этого домена (Let's Encrypt бесплатен)."))
        elif page.cert and page.cert.get("notAfter"):
            expires = datetime.strptime(page.cert["notAfter"], "%b %d %H:%M:%S %Y %Z").date()
            result.cert_days = (expires - today).days
            if result.cert_days < 0:
                add(Finding("high", "Сертификат HTTPS просрочен", f"Истёк {expires:%d.%m.%Y}.",
                            "Продлите сертификат и включите автопродление."))
            elif result.cert_days < 14:
                add(Finding("medium", "Сертификат HTTPS скоро истечёт", f"Осталось {result.cert_days} дн.",
                            "Проверьте, что автопродление работает."))
        try:
            plain = fetch(f"http://{domain}/", timeout=timeout, connect_to=connect_to)
            location = plain.header("location")
            if not (plain.status in (301, 302, 307, 308) and location.startswith("https://")):
                add(Finding("medium", "По http:// сайт открывается без шифрования",
                            "Посетитель, набравший адрес без https, работает с сайтом по открытому каналу.",
                            "Настройте постоянный редирект с http:// на https://."))
        except (OSError, http.client.HTTPException):
            pass
        if not page.header("strict-transport-security"):
            add(Finding("low", "Нет заголовка HSTS",
                        "Браузер не запоминает, что сайт работает только по HTTPS.",
                        "Добавьте Strict-Transport-Security: max-age=31536000."))
    elif not any(f.title.startswith("Сайт не открывается") for f in result.findings):
        add(Finding("high", "Сайт работает без HTTPS", "Пароли и данные форм передаются открытым текстом.",
                    "Подключите сертификат и редирект на https://."))

    # 2. Headers that stop common browser-side attacks.
    csp = page.header("content-security-policy")
    if not page.header("x-frame-options") and "frame-ancestors" not in csp:
        add(Finding("low", "Сайт можно встроить в чужую страницу (кликджекинг)", "Нет X-Frame-Options или frame-ancestors.",
                    "Добавьте X-Frame-Options: SAMEORIGIN."))
    if page.header("x-content-type-options").lower() != "nosniff":
        add(Finding("low", "Нет X-Content-Type-Options: nosniff", "", "Добавьте этот заголовок на сервере."))
    if not csp:
        add(Finding("low", "Нет политики безопасности контента (CSP)",
                    "CSP ограничивает, какие скрипты может выполнить страница, и смягчает XSS.",
                    "Начните с Content-Security-Policy-Report-Only, затем включите."))

    # 3. Versions shown to everyone, and what they say.
    php = php_version(page)
    if php:
        eol = PHP_EOL.get(php) or PHP_EOL.get(php.split(".")[0])
        if eol and eol < today:
            add(Finding("high", f"PHP {php} больше не получает обновлений безопасности",
                        f"Поддержка закончилась {eol:%d.%m.%Y}: новые уязвимости в нём не исправляются.",
                        "Обновите PHP до поддерживаемой версии (8.3 или новее) у хостинга."))
        elif eol and (eol - today).days < 90:
            add(Finding("medium", f"PHP {php} скоро перестанет получать обновления",
                        f"Поддержка заканчивается {eol:%d.%m.%Y}.", "Запланируйте переход на PHP 8.3 или новее."))
        add(Finding("low", "Сервер сообщает версию PHP", f"X-Powered-By: {page.header('x-powered-by')[:60]}",
                    "Отключите expose_php в php.ini."))
    if re.search(r"/\d+\.\d+", result.server):
        add(Finding("low", "Сервер сообщает свою версию", f"Server: {result.server}",
                    "Скройте версию (server_tokens off в nginx, ServerTokens Prod в Apache)."))

    result.cms, result.cms_version = detect_cms(page)
    if result.cms_version:
        add(Finding("low", f"Видна версия {result.cms}: {result.cms_version}",
                    "Боты подбирают эксплойты по версии.", "Уберите meta generator и держите CMS обновлённой."))

    # 4. Session cookies without protection flags.
    weak = []
    for raw in page.cookies():
        name = raw.split("=", 1)[0].strip()
        flags = raw.lower()
        if re.search(r"sess|sid|auth|login|token|bitrix_sm|wordpress", name, re.I):
            missing = [f for f, ok in (("Secure", "secure" in flags or not result.https),
                                       ("HttpOnly", "httponly" in flags)) if not ok]
            if missing:
                weak.append(f"{name} (нет {', '.join(missing)})")
    if weak:
        add(Finding("medium", "Cookie сессии без защитных флагов", "; ".join(weak[:4]),
                    "Включите Secure и HttpOnly для cookie сессии."))

    # 5. Login page open to the whole internet (an ordinary page of the CMS, nothing more).
    login = {"WordPress": "/wp-login.php", "1С-Битрикс": "/bitrix/admin/", "OpenCart": "/admin/",
             "Joomla": "/administrator/"}.get(result.cms)
    if login:
        try:
            lp, _ = follow(urljoin(result.url or f"https://{domain}/", login), timeout=timeout, connect_to=connect_to)
            if lp.status == 200 and re.search(rb'type=["\']?password', lp.body, re.I):
                add(Finding("medium", "Страница входа в админку открыта всему интернету", login,
                            "Ограничьте число попыток входа, включите двухфакторный вход; защита сайта "
                            "останавливает подбор паролей автоматически."))
        except (OSError, http.client.HTTPException):
            pass
    if result.cms == "1С-Битрикс":
        add(Finding("medium", "Сайт на «1С-Битрикс»: проверьте версию модуля «Опросы»",
                    "Уязвимость CVE-2022-27228 массово использовалась для взлома сайтов на Битриксе.",
                    "Обновите «1С-Битрикс» до актуальной версии; до обновления защита сайта закрывает этот путь."))
    if result.cms == "Tilda":
        add(Finding("ok", "Сайт на Tilda: сервер и обновления на стороне платформы", "",
                    "Следите за доступом к аккаунту Tilda: включите двухфакторный вход."))
    if not [f for f in result.findings if f.severity != "ok"]:
        add(Finding("ok", "Явных проблем снаружи не видно", "", "Это не замена проверке изнутри и защите от атак."))
    return result


SEVERITY_RU = {"high": "серьёзно", "medium": "важно", "low": "желательно", "ok": "в порядке"}


def as_text(result: Result) -> str:
    if result.error:
        return f"{result.target}: {result.error}"
    lines = [f"{result.target} — оценка {result.grade} ({result.score}/100)",
             f"  {result.url} · ответ {result.status}" + (f" · {result.cms} {result.cms_version}".rstrip() if result.cms else "")
             + (f" · сертификат ещё {result.cert_days} дн." if result.cert_days is not None else "")]
    order = {"high": 0, "medium": 1, "low": 2, "ok": 3}
    for f in sorted(result.findings, key=lambda f: order[f.severity]):
        lines.append(f"\n[{SEVERITY_RU[f.severity]}] {f.title}")
        if f.detail:
            lines.append(f"  {f.detail}")
        if f.fix:
            lines.append(f"  → {f.fix}")
    lines.append("\nПроверка пассивная: только обычные запросы к публичным страницам.")
    return "\n".join(lines)


def as_pdf(result: Result, brand: str = "Aegis Щит", contact: str = "") -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from xml.sax.saxutils import escape as esc  # noqa: I001

    from .report import FONTS, INK, MUTED, SOFT

    if "Aegis" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont("Aegis", str(FONTS / "DejaVuSans.ttf")))
        pdfmetrics.registerFont(TTFont("Aegis-Bold", str(FONTS / "DejaVuSans-Bold.ttf")))
    ink, muted, soft = (colors.HexColor(c) for c in (INK, MUTED, SOFT))
    tone = {"high": colors.HexColor("#b42318"), "medium": colors.HexColor("#b25e09"),
            "low": colors.HexColor("#5b6b63"), "ok": colors.HexColor("#0f7a55")}

    def st(name: str, font: str = "Aegis", color=ink, **kw) -> ParagraphStyle:
        return ParagraphStyle(name, fontName=font, textColor=color, **kw)

    kicker, title = st("k", fontSize=9, color=muted, leading=12), st("t", font="Aegis-Bold", fontSize=22, leading=27)
    body, small = st("b", fontSize=10, leading=14.5), st("s", fontSize=8.5, color=muted, leading=11.5)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm,
                            bottomMargin=14 * mm, title=f"Экспресс-проверка {result.target}", author=brand)
    width = A4[0] - 36 * mm
    grade_tone = tone["ok"] if result.grade in "AB" else tone["medium"] if result.grade == "C" else tone["high"]
    grade = Table([[Paragraph(result.grade, st("g", font="Aegis-Bold", fontSize=30, leading=34, color=grade_tone)),
                    Paragraph(f"<b>{result.score}/100</b><br/>{esc(result.cms or 'CMS не определена')} "
                              f"{esc(result.cms_version)}<br/>{esc(result.url)}", body)]],
                  colWidths=[22 * mm, width - 22 * mm])
    grade.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), soft), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                               ("LEFTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 8),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story = [Paragraph(f"{esc(brand)} · экспресс-проверка безопасности сайта", kicker), Paragraph(esc(result.target), title),
             Paragraph(f"Проверено {esc(result.checked)}. Только то, что видит любой посетитель.", small),
             Spacer(1, 8), grade, Spacer(1, 10)]
    order = {"high": 0, "medium": 1, "low": 2, "ok": 3}
    for f in sorted(result.findings, key=lambda f: order[f.severity]):
        story.append(Paragraph(f'<font color="{tone[f.severity].hexval().replace("0x", "#")}">'
                               f'{SEVERITY_RU[f.severity].upper()}</font> · <b>{esc(f.title)}</b>', body))
        if f.detail:
            story.append(Paragraph(esc(f.detail), small))
        if f.fix:
            story.append(Paragraph(f"Что сделать: {esc(f.fix)}", body))
        story.append(Spacer(1, 7))
    story += [Spacer(1, 6), Paragraph(
        "Эта проверка видит сайт только снаружи. Атаки на сайт — подбор паролей, SQL-инъекции, сканеры — идут "
        "постоянно; " + esc(brand) + " останавливает их до сайта и присылает отчёт каждый месяц."
        + (f" Связаться: {esc(contact)}." if contact else ""), small)]
    doc.build(story)
    return buf.getvalue()


def main_check(args) -> int:
    import json
    import sys
    try:
        result = check(args.target, timeout=args.timeout)
    except ValueError as exc:
        print(f"aegis check: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=1))
    else:
        print(as_text(result))
    if args.pdf:
        from pathlib import Path
        Path(args.pdf).write_bytes(as_pdf(result, contact=args.contact))
        print(f"\nPDF: {args.pdf}")
    return 1 if result.error else 0
