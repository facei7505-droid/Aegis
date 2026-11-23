"""Attack detectors for request inputs.

Each signal has a weight (0..1). Signals of the same attack class are
combined as independent evidence:  score = 1 - prod(1 - w_i).
A value is reported as an attack when its best class reaches the threshold.

Inputs are normalised first (repeated URL-decoding, HTML entities, SQL comment
padding, null bytes) so that common evasions do not hide the payload.
"""
from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote_plus

_F = re.IGNORECASE | re.DOTALL

# Shell commands that are not English words: dangerous after any separator.
_STRONG_CMDS = (
    r"whoami|uname|wget|curl|nc|ncat|netcat|socat|telnet|bash|sh|zsh|ksh|dash|busybox|powershell|pwsh|"
    r"cmd(\.exe)?|python[\d.]*|perl|php|ruby|node|ifconfig|ipconfig|systeminfo|tasklist|nslookup|chmod|chown|"
    r"base64|xxd|printf|printenv|ssh|scp|rm|mkfifo|crontab|certutil|bitsadmin"
)
# Commands that are also everyday words ("cat", "type", "net"): lowercase only, and they need
# shell context (end of value, flags, a file argument) to count fully.
_WORD_CMDS = (
    r"cat|ls|id|echo|ping|sleep|touch|type|dir|net|head|tail|more|less|env|find|grep|awk|sed|sort|kill|"
    r"dd|tee|cut|nl|od|wc|which|whereis|hostname|pwd|ps|set|ver"
)
_SEP = r"(?:;|&&?|\|\|?|`|\$\(|\n)"
_C = re.DOTALL  # case-sensitive
# Bounded horizontal whitespace. Unbounded \s* after a separator that can itself be a newline makes
# a value of 5,000 newlines quadratic (found in review: one request could stall a worker for seconds).
_HS = r"[ \t]{0,20}"

SIGNATURES: dict[str, list[tuple[str, re.Pattern, float]]] = {
    "sqli": [
        ("tautology", re.compile(r"['\"`)]\s*(or|and|\|\||&&)\s*['\"`(]?\s*[\w'\"]+\s*['\"`)]?\s*(=|like|<>|!=|<|>)\s*['\"`(]?\s*[\w'\"]+", _F), 0.9),
        ("boolean injection", re.compile(
            r"['\"`)]\s*(or|and|\|\|)\s+((not\s+)?(true|false|null)\b|\d+\s*($|--|#|/\*|\)|;))", _F), 0.9),
        ("numeric tautology", re.compile(r"\b(or|and)\s+(\d+)\s*=\s*\2\b", _F), 0.85),
        ("numeric comparison", re.compile(r"^\s*-?\d+\)*\s+(or|and)\s+\d+\s*(<=|>=|<>|!=|<|>|=)\s*\d+\s*($|--|#|/\*|;|\))", _F), 0.85),
        ("comment terminator", re.compile(r"['\"`]\s*\)*\s*(--|#|/\*)", _F), 0.85),
        ("closing paren comment", re.compile(r"\)\s*(--|/\*)", _F), 0.6),
        ("union select", re.compile(r"\bunion\b(\s+(all|distinct))?\s+select\b", _F), 0.95),
        ("subquery", re.compile(r"\(\s*select\b[^)]*\bfrom\b", _F), 0.6),
        ("subquery comparison", re.compile(r"\(\s*select\b.{0,200}?\bfrom\b.{0,200}?\)\s*(=|<|>|!=|<>|\bis\b|\blike\b)", _F), 0.85),
        ("blind function", re.compile(
            r"['\"`)]\s*(or|and)\s+\(*\s*(substr|substring|ascii|ord|char|mid|length|hex|unhex|load_file|"
            r"extractvalue|updatexml|if|case|exists)\s*\(", _F), 0.9),
        ("stacked query", re.compile(
            r";\s*(drop\s+(table|database|view|index)|delete\s+from|insert\s+into|update\s+\w+\s+set|"
            r"alter\s+table|create\s+(table|database|user)|truncate\s+table|exec(ute)?\s*(\(|xp_|sp_)|shutdown\b)", _F), 0.9),
        ("time delay", re.compile(r"\b(sleep|pg_sleep|benchmark|randomblob)\s*\(|\bwaitfor\s+delay\b", _F), 0.8),
        ("quoted statement", re.compile(
            r"['\"`]\s*\)*\s*;?\s*(delete\s+from|drop\s+(table|database)|insert\s+into|update\s+\w+\s+set|"
            r"select\s+[\w*@,\s()]+\s+from|exec(ute)?\s|waitfor\s+delay|shutdown\b)", _F), 0.9),
        ("self tautology", re.compile(r"\b(or|and)\s+(['\"]?)(\w+)\2\s*(=|like)\s*\2\3\2(?!\w)", _F), 0.85),
        ("null test", re.compile(r"['\"`)]\s*(or|and)\s+\w+\s+is\s+(not\s+)?null\b", _F), 0.9),
        ("dangerous procedure", re.compile(r"\b(xp_cmdshell|sp_executesql|sp_oacreate|load_file\s*\(|into\s+(out|dump)file\b|"
                                           r"utl_http|dbms_pipe|exec(ute)?\s+immediate)", _F), 0.95),
        ("sql variable", re.compile(r"\bdeclare\s+@\w+|@@(version|servername|datadir|hostname|basedir|variable)\b", _F), 0.85),
        ("char encoding", re.compile(r"\b(char|chr|nchar)\s*\(\s*\d+(\s*,\s*\d+){2,}\s*\)|\b0x[0-9a-f]{16,}\b", _F), 0.6),
        ("like probe", re.compile(r"\b(or|and)\s+\w+\s+like\s+", _F), 0.6),
        ("schema probe", re.compile(r"\b(information_schema|sqlite_master|pg_catalog|sysobjects)\b", _F), 0.8),
    ],
    "xss": [
        ("script tag", re.compile(r"<\s*script\b", _F), 0.95),
        ("event handler", re.compile(r"<[^<>]{0,300}?\bon[a-z]{3,}[ \t]{0,10}=", _F), 0.9),
        ("attribute breakout", re.compile(
            r"[\"'`][^<>\"'`]{0,200}?\bon(focus|blur|error|load|click|dblclick|mouse\w+|pointer\w+|key\w+|input|change|"
            r"submit|toggle|animation\w+|transition\w+|begin|end|drag\w*|wheel|scroll|copy|paste|auxclick|"
            r"contextmenu|show|beforeprint)[ \t]{0,10}=", _F), 0.9),
        ("javascript url", re.compile(r"j[\s\x00-\x1f]*a[\s\x00-\x1f]*v[\s\x00-\x1f]*a[\s\x00-\x1f]*s[\s\x00-\x1f]*"
                                      r"c[\s\x00-\x1f]*r[\s\x00-\x1f]*i[\s\x00-\x1f]*p[\s\x00-\x1f]*t[\s\x00-\x1f]*:", _F), 0.85),
        ("active tag", re.compile(r"<\s*(iframe|svg|object|embed|math|base|meta|link)\b", _F), 0.7),
        ("remote content tag", re.compile(r"<\s*(iframe|frame|embed|object|base|applet)\b[^>]*\b(src|data|code|href)\s*=|xlink:href\s*=", _F), 0.9),
        ("handler in tag", re.compile(r"<[a-z][\w:-]*(\s[^<]*?)?[\s/\"']on[a-z]{3,}\s*=", _F), 0.85),
        ("script breakout", re.compile(r"['\"`]\s*[-+*/;|&]\s*(alert|prompt|confirm|eval|fetch|import)\s*[(`]", _F), 0.9),
        ("vbscript or data url", re.compile(r"\b(vbscript|livescript)\s*:|\bdata\s*:\s*text/html", _F), 0.85),
        ("dom sink", re.compile(r"\b(document\.(cookie|domain|write)|window\.location)\b|\b(alert|prompt|confirm)\s*\(", _F), 0.55),
    ],
    "path_traversal": [
        ("dot-dot-slash", re.compile(r"\.\.[/\\]", _F), 0.85),
        ("sensitive file", re.compile(
            r"(^|[/\\])(etc[/\\](passwd|shadow|hosts|group)|proc[/\\](self|\d+)[/\\]|windows[/\\]win\.ini|"
            r"boot\.ini|\.ssh[/\\]|\.env\b|\.git[/\\]|\.aws[/\\])", _F), 0.9),
        ("null byte", re.compile(r"\x00"), 0.6),
        ("wrapper scheme", re.compile(r"^(file|php|zip|data|expect|phar)://", _F), 0.85),
        ("system path", re.compile(
            r"^\s*(/(etc|proc|root|var/(log|adm|mail|spool|lib/mysql)|usr/local/etc|opt/lampp)/|[a-z]:\\\\?(windows|winnt|boot\.ini|inetpub)\b)", _F), 0.85),
        ("secret config file", re.compile(r"(^|[/\\])(\.htpasswd|\.htaccess|web\.config|wp-config\.php|\.bash_history|id_rsa|"
                                          r"shadow|master\.passwd|httpd\.conf|php\.ini|my\.cnf)\b", _F), 0.85),
        ("encoded dot-dot", re.compile(r"\.\.(%2f|%5c|2f|5c|%c0%af|%c1%9c)", _F), 0.85),
    ],
    "command_injection": [
        ("chained command", re.compile(_SEP + _HS + r"(" + _STRONG_CMDS + r")\b", _F), 0.9),
        ("chained word command", re.compile(_SEP + _HS + r"(" + _WORD_CMDS + r")(?=[ \t]{0,20}($|[;&|`#)\r\n]))", _C), 0.9),
        ("piped word command", re.compile(r"(&|\||`|\$\()" + _HS + r"(" + _WORD_CMDS + r")\b(?![ \t]{0,20}=)", _C), 0.85),
        ("separated word command", re.compile(r"[;\n]" + _HS + r"(" + _WORD_CMDS + r")[ \t](?![ \t]{0,20}=)", _C), 0.75),
        ("absolute program path", re.compile(_SEP + _HS + r"/(usr/)?(local/)?s?bin/\w+", _F), 0.9),
        ("shell flags", re.compile(r"\s-[a-zA-Z]{1,4}(\s|$)", _C), 0.4),
        ("file argument", re.compile(r"\s[\w./-]+\.(txt|conf|cfg|ini|env|log|key|pem|py|sh|db|sqlite|json|ya?ml|xml|php)\b", _F), 0.5),
        ("command substitution", re.compile(r"\$\([^()]{0,200}\)", _F), 0.85),
        ("backticks", re.compile(r"`[^`]{1,200}`", _F), 0.75),
        ("logical chaining", re.compile(r"(\|\||&&)\s*\w+", _F), 0.7),
    ],
    "ssti": [
        ("jinja expression", re.compile(r"\{\{(?=[^{}]{0,300}\}\})[\w\s.]{0,300}[^\w\s.{}]", _F), 0.85),
        ("template variable", re.compile(r"\{\{[ \t]{0,10}[\w.]{1,100}[ \t]{0,10}\}\}", _F), 0.4),
        ("jinja statement", re.compile(r"\{%[^%]{0,300}%\}", _F), 0.85),
        ("expression language", re.compile(r"[$#]\{.*?\}", _F), 0.5),
        ("arithmetic probe", re.compile(r"[$#]\{\s*\d+\s*[*+/-]\s*\d+\s*\}", _F), 0.85),
        ("python internals", re.compile(r"__(class|mro|subclasses|globals|builtins|init)__", _F), 0.9),
    ],
    "code_injection": [
        ("__import__", re.compile(r"__import__\s*\(", _F), 0.95),
        ("dangerous call", re.compile(r"\b(eval|exec|compile|getattr)\s*\(", _F), 0.6),
        ("nested code call", re.compile(r"\b(eval|exec)\s*\(\s*(compile|__import__|getattr|open|['\"])", _F), 0.9),
        ("file access", re.compile(r"\bopen\s*\([^)]*\)\s*\.\s*(read|write|readlines)\b", _F), 0.9),
        ("os access", re.compile(r"\bos\.(system|popen|exec\w*|environ)\b|\bsubprocess\.", _F), 0.85),
        ("python internals", re.compile(r"__(class|mro|subclasses|globals|builtins)__", _F), 0.9),
        ("log4shell", re.compile(r"\$\{\s*jndi\s*:", _F), 0.97),
    ],
    "header_injection": [
        ("crlf set-cookie", re.compile(r"[\r\n][ \t]{0,10}set-cookie[ \t]{0,10}:", _F), 0.95),
        ("crlf framing header", re.compile(r"[\r\n][ \t]{0,10}(content-(length|type)|transfer-encoding|x-forwarded-\w+)[ \t]{0,10}:", _F), 0.85),
        ("crlf redirect header", re.compile(r"[\r\n][ \t]{0,10}(location|refresh)[ \t]{0,10}:", _F), 0.6),
    ],
    "xxe": [
        ("external entity", re.compile(r"<!ENTITY\s+%?\s*\w+\s+(SYSTEM|PUBLIC)\b", _F), 0.95),
        ("inline doctype", re.compile(r"<!DOCTYPE\s+\w+\s*\[", _F), 0.6),
    ],
    "format_string": [
        ("format directives", re.compile(r"(%[0-9$.]*[nsxXdpi]){5,}"), 0.85),
        ("write directive", re.compile(r"%\d*\$?n%|%n%n"), 0.85),
    ],
    "ssrf": [
        ("internal url", re.compile(
            r"^(https?|gopher|dict|ftp|file)://([^/@]*@)?(localhost|127\.|0\.0\.0\.0|0/|169\.254\.169\.254|\[::1?\]|10\.|"
            r"192\.168\.|172\.(1[6-9]|2\d|3[01])\.|metadata\.google\.internal)", _F), 0.85),
        ("obfuscated ip", re.compile(
            r"^(https?|gopher|dict|ftp)://([^/@]*@)?(\d{8,10}|0x[0-9a-f]{6,8}|0\d{1,3}\.\d|"
            r"\[[0-9a-f:]*:(ffff:)?(127|10|169\.254|192\.168|0)[.\d]*\]|\[0*(:0*)*:0*1?\])(:\d+)?(/|$)", _F), 0.85),
    ],
}

URL_HEADERS = {"referer", "origin"}

# Files no web app should serve (cf. OWASP CRS restricted extensions): backups, configs, VCS data.
PATH_PROBE = re.compile(
    r"\.(bak|backup|old|orig|inc|swp|save|sav|tmp|sql|dist|config|ini|log)(\.|$|/)|~$|"
    r"(^|/)(\.git|\.svn|\.hg|\.env|\.DS_Store|_vti_\w*|WEB-INF|META-INF)(/|$)", re.I)

SCANNER_AGENTS = re.compile(
    r"(sqlmap|nikto|nmap|masscan|acunetix|nessus|wpscan|dirbuster|gobuster|ffuf|nuclei|havij|w3af|zgrab)", re.I
)


@dataclass
class Detection:
    attack_type: str
    score: float
    signals: list[str] = field(default_factory=list)
    value: str = ""
    location: str = ""
    param: str = ""
    classes: dict[str, float] = field(default_factory=dict)  # every attack class seen in this value


_IIS_U = re.compile(r"%u([0-9a-fA-F]{4})")


def _decode(value: str) -> str:
    out = value
    for _ in range(3):
        decoded = unquote_plus(_IIS_U.sub(lambda m: chr(int(m.group(1), 16)), out) if "%u" in out else out)
        if decoded == out:
            break
        out = decoded
    if "&" in out:
        out = html.unescape(out)
    return out if out.isascii() else unicodedata.normalize("NFKC", out)  # fullwidth ＜script＞, small ﹨ ...


def normalize(value: str) -> str:
    """Decoded value with SQL comment padding removed (UNION/**/SELECT) and escaped nulls made real."""
    out = _decode(value)
    if "/*" in out:
        out = re.sub(r"/\*.*?\*/", " ", out, flags=re.S)
    return out.replace("\\x00", "\x00").replace("\\0", "\x00")


def variants(value: str) -> set[str]:
    """The normalised value, plus versions with comments kept and null bytes dropped (each can hide a payload)."""
    raw = _decode(value)
    text = raw
    if "/*" in text:
        text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    if "\\" in text:
        text = text.replace("\\x00", "\x00").replace("\\0", "\x00")
    out = {text, raw}
    if "\x00" in text or "\\0" in raw:
        out |= {text.replace("\x00", ""), raw.replace("\x00", "").replace("\\0", "")}
    return out


def score_value(value: str) -> tuple[str, float, list[str]]:
    """Best (attack_type, score, signals) for a single input value."""
    attack, score, signals, _ = score_all(value)
    return attack, score, signals


WINDOW = 8192   # long values are scored in overlapping windows: bounded time per window, nothing skipped
OVERLAP = 512


def score_all(value: str) -> tuple[str, float, list[str], dict[str, float]]:
    if len(value) > WINDOW:
        best: tuple[str, float, list[str], dict[str, float]] = ("", 0.0, [], {})
        merged: dict[str, float] = {}
        for start in range(0, len(value), WINDOW - OVERLAP):
            result = score_all(value[start:start + WINDOW])
            for k, v in result[3].items():
                merged[k] = max(merged.get(k, 0.0), v)
            if result[1] > best[1]:
                best = result
        return best[0], best[1], best[2], merged
    texts = variants(value)
    best: tuple[str, float, list[str]] = ("", 0.0, [])
    classes: dict[str, float] = {}
    for attack, signals in SIGNATURES.items():
        hits = [(name, w) for name, pattern, w in signals if any(pattern.search(t) for t in texts)]
        if not hits:
            continue
        miss = 1.0
        for _, w in hits:
            miss *= 1.0 - w
        score = round(1.0 - miss, 3)
        classes[attack] = score
        if score > best[1]:
            best = (attack, score, [name for name, _ in hits])
    return best[0], best[1], best[2], classes


REASSEMBLED = {"query", "form"}


def reassembled(inputs: list[tuple[str, str, str]], relaxed: set[str]) -> list[tuple[str, str, str]]:
    """Values a framework rebuilds from repeated parameters (HTTP parameter pollution).

    `?id=5/*&id=*/UNION/*&id=*/SELECT...` is harmless one value at a time, but ASP.NET and many
    hand-written handlers join repeats with ',' (giving `5/*,*/UNION/*,*/SELECT`), and others
    concatenate them. Each repeated name is also scored in both joined forms."""
    groups: dict[tuple[str, str], list[str]] = {}
    for location, name, value in inputs:
        if location in REASSEMBLED and name.lower() not in relaxed:
            groups.setdefault((location, name), []).append(value)
    out = []
    for (location, name), values in groups.items():
        if len(values) > 1:
            out.append((location, f"{name}[joined]", ",".join(values)))
            out.append((location, f"{name}[concat]", "".join(values)))
    return out


def analyze(inputs: list[tuple[str, str, str]], threshold: float = 0.8,
            relaxed: set[str] | None = None, relaxed_threshold: float = 0.97) -> Detection | None:
    """Return the strongest detection across all request inputs, if any crosses its threshold."""
    relaxed = relaxed or set()
    strongest: Detection | None = None
    for location, name, value in [*inputs, *reassembled(inputs, relaxed)]:
        if not value:
            continue
        if location == "header" and name.lower() == "user-agent" and SCANNER_AGENTS.search(value):
            det = Detection("recon", 0.95, ["scanner user-agent"], value, location, name)
        elif location == "path" and PATH_PROBE.search(value):
            det = Detection("recon", 0.85, ["backup, config or repository file probe"], value, location, name)
        else:
            attack, score, signals, classes = score_all(value)
            if location == "header" and name.lower() in URL_HEADERS and attack == "ssrf":
                # Referer/Origin are URLs of the site itself (http://localhost:8080/... in development):
                # an internal address there is normal, not a server-side request forgery.
                classes.pop("ssrf", None)
                if not classes:
                    continue
                attack = max(classes, key=classes.get)
                score, signals = classes[attack], [f"{attack} in {name}"]
            if not attack:
                continue
            det = Detection(attack, score, signals, value, location, name, classes)
        limit = relaxed_threshold if name.lower() in relaxed else threshold
        if det.score >= limit and (strongest is None or det.score > strongest.score):
            strongest = det
    return strongest
