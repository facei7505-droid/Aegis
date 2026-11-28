"""Phrase lists from the OWASP Core Rule Set (data/crs, Apache-2.0), used where they mean something.

CRS matches these lists anywhere in a value (@pmFromFile). That is right for a WAF tuned per site by
an administrator, and too eager for a managed service that cannot tune every shop: `/tmp/` in a list
of system files would also match a Bitrix upload URL `/upload/tmp/photo.jpg`. Aegis therefore uses
them with context:

  * restricted files (930130): in the request path, as whole names (`/.env`, `/wp-config.php.bak`);
  * OS files (930120): in a parameter that *is* a file path, i.e. starts at a system root (`/etc/`,
    `/usr/`, `c:/windows/`), climbs with `../`, or uses a stream wrapper (`php://`, `file://`). Elsewhere
    a hit is only a weak signal that needs a second one;
  * shell programs (932160): strong right after a command separator (`;` `|` `&&` `` ` `` `$(`), weak
    on their own.

The lists are compiled into one trie-shaped regular expression each, so a lookup costs about as much
as a single ordinary signature.
"""
from __future__ import annotations

import re
import threading
from pathlib import Path

DATA = Path(__file__).parent / "data" / "crs"

# Entries too generic for a shared service (a route called /sys/ exists in ordinary apps).
SKIP = {"restricted-files": {"/sys/", "/proc/", "sys/", "proc/", "perl/lib", "perl/bin"}, "lfi-os-files": {"/tmp/"}}

SYSTEM_ROOTS = ("etc", "usr", "var", "opt", "proc", "sys", "home", "root", "tmp", "dev", "boot", "lib", "lib64",
                "bin", "sbin", "srv", "private", "applications", "library", "system", "windows", "winnt",
                "program files", "program files (x86)", "inetpub", "xampp", "wamp", "apache", "apache2", "nginx",
                "mysql", "pgsql", "php", "users", "documents and settings", "volumes", "mnt", "run", "data")
_ROOTED = re.compile(r"\A(?:[a-z]:)?/(" + "|".join(re.escape(r) for r in SYSTEM_ROOTS) + r")(/|\Z)")
_TRAVERSAL = re.compile(r"(?:\A|/)\.\.(?:/|\Z)")
_WRAPPER = re.compile(r"\A(?:file|php|zip|phar|glob|data|expect|compress\.zlib)://")
_HOME_DOTFILE = re.compile(r"\A~?/\.[a-z]")  # /.netrc, ~/.aws/credentials
_SEPARATOR = re.compile(r"(?:[;|`\n]|&&|\$\()[ \t]{0,20}(?:\S{0,40}/)?\Z")


def _load(name: str) -> list[str]:
    skip = SKIP.get(name, set())
    words = set()
    for line in (DATA / f"{name}.data").read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#") and line not in skip:
            words.add(line)
    return sorted(words)


def _trie(words: list[str]) -> str:
    tree: dict = {}
    for word in words:
        node = tree
        for ch in word:
            node = node.setdefault(ch, {})
        node[""] = {}

    def emit(node: dict) -> str:
        ends = "" in node
        branches = [re.escape(ch) + emit(child) for ch, child in sorted(node.items()) if ch]
        if not branches:
            return ""
        body = branches[0] if len(branches) == 1 else "(?:" + "|".join(branches) + ")"
        return f"(?:{body})?" if ends else body

    return emit(tree)


class PhraseList:
    """`find(text)` -> the first entry found as a whole word (path-aware boundaries), or None."""

    def __init__(self, name: str, word_end: str = r"(?![a-z0-9_])"):
        self.name = name
        self.word_end = word_end
        self._regex: re.Pattern | None = None
        self._lock = threading.Lock()

    def _compiled(self) -> re.Pattern:
        if self._regex is None:
            with self._lock:
                if self._regex is None:
                    # A name starts where a path segment starts and ends where it ends. Entries that begin
                    # with `/` or `$` carry their own start; entries ending in a separator (`etc/apache2/`)
                    # or a prefix (`.bash_`, `bin/aa-`) may run on.
                    groups: dict[tuple[bool, bool], list[str]] = {}
                    for w in _load(self.name):
                        key = (w[0].isalnum() or w[0] in "._", w[-1].isalnum())
                        groups.setdefault(key, []).append(w)
                    parts = []
                    for (left, right), words in sorted(groups.items()):
                        parts.append((r"(?<![a-z0-9_.\-])" if left else "") + f"(?:{_trie(words)})"
                                     + (self.word_end if right else ""))
                    self._regex = re.compile("|".join(parts))
        return self._regex

    def find(self, text: str) -> re.Match | None:
        return self._compiled().search(text)


# In a path a name ends where the segment ends: /error.log-analysis/ is a blog post, not /error.log.
RESTRICTED = PhraseList("restricted-files", word_end=r"(?![a-z0-9_.\-])")
OS_FILES = PhraseList("lfi-os-files")
SHELL = PhraseList("unix-shell")


def normalize(text: str) -> str:
    """Lower case, forward slashes, no `//` or `/./` (CRS: t:lowercase, t:normalizePathWin)."""
    text = text.lower().replace("\\", "/")
    text = re.sub(r"/{2,}", "/", text) if "//" in text and "://" not in text else text
    return text.replace("/./", "/")


def restricted_path(path: str) -> str | None:
    match = RESTRICTED.find(normalize(path))
    return match.group(0) if match else None


def score(texts, classes: dict[str, float], best: tuple[str, float, list[str]]):
    """Add CRS phrase evidence to a value's scores (same independent-signal sum as the signatures)."""
    hits = []
    for raw in texts:
        if "/" not in raw and "\\" not in raw and "$" not in raw:
            continue
        text = normalize(raw.strip())
        if text.startswith(("http:", "https:", "//")):
            continue  # a link, not a file
        found = OS_FILES.find(text)
        if found:
            strong = bool(_ROOTED.match(text) or _TRAVERSAL.search(text) or _WRAPPER.match(text)
                          or _HOME_DOTFILE.match(text))
            hits.append(("path_traversal", 0.85 if strong else 0.5, f"OWASP CRS os file {found.group(0)}"))
        found = SHELL.find(text)
        if found:
            strong = bool(_SEPARATOR.search(text[:found.start()]))
            # A hit inside an absolute path (/bin/ls) is the same evidence the "absolute program path"
            # signature already weighed: counted twice, a review that mentions /bin/ls would be blocked.
            if text[found.start() - 1:found.start()] != "/":
                hits.append(("command_injection", 0.85 if strong else 0.5, f"OWASP CRS shell {found.group(0)}"))
        if hits:
            break
    for attack, weight, signal in hits:
        score_ = round(1.0 - (1.0 - classes.get(attack, 0.0)) * (1.0 - weight), 3)
        classes[attack] = score_
        signals = (best[2] + [signal]) if best[0] == attack else [signal]
        if score_ > best[1] or best[0] == attack:
            best = (attack, max(score_, best[1]), signals)
    return best
