"""Response guard: what the site answers says whether an attack worked.

A request filter guesses; the answer knows. Aegis reads the start of every text answer from the origin:

  * database error text (MySQL, PostgreSQL, SQLite, SQL Server, Oracle, Bitrix and WordPress
    wrappers). If the request that caused it carried SQL syntax in a field, that field reaches the
    database unescaped: a *confirmed injection point*. Aegis then closes exactly that field on that
    page (learned patch: digits only for a numeric field, no quotes or comment marks for a text one),
    blocks the answer so the attacker sees nothing, and tells the owner what to fix;
  * contents of system files (`root:x:0:0:`) or command output (`uid=33(www-data)`): an attack that
    already succeeded. The answer is replaced and the address banned;
  * a known PHP web shell (titles from the OWASP CRS list): the site is already compromised;
  * PHP error messages with file paths: a leak worth an alert (display_errors is on), never a block,
    because sloppy sites print warnings on ordinary pages.

Error patterns follow OWASP CRS rules 951 and 953 (Apache-2.0); see data/crs/NOTICE.
"""
from __future__ import annotations

import json
import re
import threading
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl

from .policy import normalize_path

INSPECT_BYTES = 256 * 1024
TEXT_TYPES = ("text/html", "text/plain", "application/json", "text/xml", "application/xml", "application/xhtml")

SQL_ERRORS = re.compile(
    r"You have an error in your SQL syntax|mysql_(?:fetch_(?:array|assoc|row)|num_rows|result)\(\)"
    r"|supplied argument is not a valid (?:MySQL|PostgreSQL)|Column count doesn't match"
    r"|MySQL server version for the right syntax|SQLSTATE\[[0-9A-Z]{5}\]|PostgreSQL query failed"
    r"|pg_(?:query|exec)\(\) \[|org\.postgresql\.util\.PSQLException|ERROR:\s{1,5}syntax error at or near"
    r"|unterminated quoted string at or near|SQLite3::(?:query|exec|prepare)|SQLite(?:\.Exception|Exception)"
    r"|near \"[^\"\n]{1,40}\": syntax error|Unclosed quotation mark after the character string"
    r"|Incorrect syntax near|System\.Data\.SqlClient\.SqlException|\bORA-\d{5}:|java\.sql\.SQLException"
    r"|Microsoft OLE DB Provider for (?:SQL Server|ODBC)|\[Microsoft\]\[ODBC"
    r"|Warning</b>:\s{0,5}(?:mysql|mysqli|pg|sqlite|oci|mssql)_\w{1,30}\(|MySQL Query Error|DB query error\."
    r"|WordPress database error", re.I)
PHP_ERRORS = re.compile(
    r"(?:<b>)?(?:Fatal error|Parse error|Warning|Notice|Deprecated|Uncaught (?:Error|Exception|TypeError))"
    r"(?:</b>)?:\s{1,5}.{1,300}? in (?:<b>)?(?:/|[A-Za-z]:\\)[^<\s]{1,200}(?:</b>)? on line", re.S)
SYSTEM_FILES = re.compile(r"root:[x*]?:0:0:[^\n]{0,80}:/root:|\buid=\d{1,6}\([\w.-]{1,32}\) gid=\d{1,6}\("
                          r"|\[boot loader\][^\n]{0,40}\n[^\n]{0,80}timeout=|; for 16-bit app support")
PHP_ERRORS_I = re.compile(PHP_ERRORS.pattern, re.S | re.I)
SQL_SYNTAX = re.compile(r"['\"\\`;]|--|/\*|\b(?:union|select|sleep|benchmark|waitfor)\b|\b(?:or|and)\s+\d", re.I)


def _shell_titles() -> list[str]:
    path = Path(__file__).parent / "data" / "crs" / "web-shells-php.data"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    return [line for line in (raw.strip() for raw in lines)
            if line and not line.startswith("#") and len(line) >= 8 and line not in LEGIT_TOOLS]


LEGIT_TOOLS = {"<title>Tiny File Manager</title>"}  # in the CRS list, but also a file manager owners install


_SHELLS: list[str] | None = None


def web_shell(text: str) -> str | None:
    global _SHELLS
    if _SHELLS is None:
        _SHELLS = _shell_titles()
    head = text[:32768]  # a web shell's page is small; its marks are near the top
    return next((s for s in _SHELLS if s in head), None)


def decode(body: bytes, encoding: str) -> str | None:
    """Text of (the start of) a response body, or None for encodings we do not read."""
    encoding = (encoding or "").strip().lower()
    try:
        if encoding in ("", "identity"):
            raw = body
        elif encoding in ("gzip", "x-gzip"):
            raw = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(body, INSPECT_BYTES * 4)
        elif encoding == "deflate":
            try:
                raw = zlib.decompressobj().decompress(body, INSPECT_BYTES * 4)
            except zlib.error:
                raw = zlib.decompressobj(-zlib.MAX_WBITS).decompress(body, INSPECT_BYTES * 4)
        else:
            return None
    except zlib.error:
        return None
    return raw[:INSPECT_BYTES * 4].decode("utf-8", errors="replace")


@dataclass
class Finding:
    kind: str           # sql_error | php_error | system_file | web_shell
    evidence: str       # the matched text (short)
    fields: list[str]   # request fields carrying SQL syntax (sql_error only)
    block: bool         # replace the answer
    ban: bool = False   # ...and ban the requester: only when the request itself asked for the leak


# Cheap literal hints in front of the patterns: a 300 KB shop page is scanned in about a millisecond
# instead of tens (the patterns run only around a hint).
SQL_HINTS = ("sql", "syntax", "ora-", "odbc", "ole db", "column count", "query error", "database error",
             "pg_query(", "pg_exec(", "unterminated", "supplied argument", "warning</b>")
SYSTEM_HINTS = ("root:", "uid=", "[boot loader]", "16-bit app")
PHP_HINTS = ("error", "warning", "notice", "deprecated", "uncaught")


def _around(low: str, hints, pattern: re.Pattern, before: int = 300, after: int = 400):
    """Run `pattern` on the lower-cased text, only in windows around literal hints. Overlapping windows are
    merged, so decoy hints cost at most one pass over the page, and no occurrence is skipped."""
    for hint in hints:
        windows: list[list[int]] = []
        pos = low.find(hint)
        while pos != -1:
            lo, hi = max(0, pos - before), pos + after
            if windows and lo <= windows[-1][1]:
                windows[-1][1] = hi
            else:
                windows.append([lo, hi])
            pos = low.find(hint, pos + 1)
        for lo, hi in windows:
            found = pattern.search(low, lo, hi)
            if found:
                return found
    return None


def _reflected(evidence: str, request_text: str) -> bool:
    """The answer only repeats what the request sent (a search page echoing the query): no proof of anything."""
    probe = re.sub(r"\s+", " ", evidence.lower()).strip()[:40]
    return len(probe) >= 6 and probe in request_text


def _request_text(target: str, fields: dict[str, str]) -> str:
    import html as _html
    from urllib.parse import unquote_plus
    parts = [unquote_plus(target)] + [f"{k} {v}" for k, v in fields.items()]
    text = " ".join(parts).lower()
    return re.sub(r"\s+", " ", text + " " + _html.unescape(text))


def _attack_in_request(target: str, fields: dict[str, str]) -> bool:
    """Request-side evidence that the system file or command output was asked for (not just served)."""
    from .detectors import score_all
    for value in [target, *fields.values()]:
        classes = score_all(value or "")[3]
        if classes.get("path_traversal", 0) >= 0.5 or classes.get("command_injection", 0) >= 0.5:
            return True
    return False


def _is_page(low: str) -> bool:
    head = low[:4096]
    return any(tag in head for tag in ("<html", "<body", "<div", "<p>", "<pre", "<!doctype"))


def examine(text: str, request_fields: dict[str, str], target: str = "") -> Finding | None:
    """What the answer proves. Answers that merely reflect the request prove nothing and are ignored."""
    low = text.lower()
    request_text = _request_text(target, request_fields)
    found = _around(low, SYSTEM_HINTS, SYSTEM_FILES)
    if found and not _reflected(found.group(0), request_text):
        # A raw file (no page around it) is a leak whoever asked; a page that shows `id` output or an
        # /etc/passwd example is content. Banning needs the request itself to have asked for the file.
        asked = _attack_in_request(target, request_fields)
        return Finding("system_file", found.group(0)[:80], [], asked or not _is_page(low), ban=asked)
    shell = web_shell(text)
    if shell:
        return Finding("web_shell", shell[:80], [], False)  # someone runs a shell here: alert, never ban the visitor
    found = _around(low, SQL_HINTS, SQL_ERRORS)
    if found and not _reflected(found.group(0), request_text):
        fields = [name for name, value in request_fields.items() if SQL_SYNTAX.search(value or "")]
        return Finding("sql_error", found.group(0)[:80], fields, len(fields) == 1)
    found = _around(low, PHP_HINTS, PHP_ERRORS_I, before=40, after=700)
    if found and not _reflected(found.group(0), request_text):
        return Finding("php_error", re.sub(r"<[^>]+>", "", found.group(0))[:120], [], False)
    return None


def request_fields(target: str, body: bytes | None, content_type: str, php: bool = False) -> dict[str, str]:
    """Field -> value as the application reads it (`php`: PHP's names, last value wins)."""
    pairs = parse_qsl(target.split("?", 1)[1], keep_blank_values=True) if "?" in target else []
    if body and "application/x-www-form-urlencoded" in (content_type or ""):
        try:
            pairs += parse_qsl(body[:65536].decode("utf-8", errors="replace"), keep_blank_values=True)
        except ValueError:
            pass
    if php:
        from .policy import php_name
        pairs = [(php_name(k), v) for k, v in pairs]
    return dict(pairs)


# ------------------------------------------------------- learned patches --

NUMERIC = re.compile(r"\A[\s\d.,+-]{1,40}\Z")
TEXT_INJECTION = re.compile(r"['\"\\`;]|--|/\*")


class LearnedPatches:
    """Fields proven injectable on this site: (route, field) -> numeric | text. Kept in a JSON file."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._patches: dict[str, dict] = {}
        self._lock = threading.Lock()
        if self.path and self.path.is_file():
            try:
                self._patches = json.loads(self.path.read_text(encoding="utf-8") or "{}")
            except (OSError, ValueError):
                self._patches = {}

    @staticmethod
    def route(route: str) -> str:
        return normalize_path(route).rstrip("/") or "/"

    @classmethod
    def key(cls, route: str, field: str) -> str:
        return f"{cls.route(route)}?{field}"

    def learn(self, route: str, field: str, sample: str, evidence: str) -> bool:
        """True if this is a new patch."""
        key = self.key(route, field)
        with self._lock:
            if key in self._patches:
                return False
            kind = "numeric" if re.match(r"\A\s*-?\d", sample or "") else "text"
            self._patches[key] = {"route": self.route(route), "field": field, "kind": kind,
                                  "since": int(time.time()), "evidence": evidence[:120]}
            if self.path:
                try:
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                    self.path.write_text(json.dumps(self._patches, ensure_ascii=False, indent=1), encoding="utf-8")
                except OSError:
                    pass
            return True

    def check(self, route: str, fields: dict[str, str]) -> dict | None:
        """The patch a request breaks, if any."""
        if not self._patches:
            return None
        route = self.route(route)
        for name, value in fields.items():
            patch = self._patches.get(f"{route}?{name}")
            if patch is None:
                continue
            if patch["kind"] == "numeric" and value and not NUMERIC.match(value):
                return patch
            if patch["kind"] == "text" and TEXT_INJECTION.search(value or ""):
                return patch
        return None

    def __len__(self) -> int:
        return len(self._patches)

    def items(self) -> list[dict]:
        return list(self._patches.values())
