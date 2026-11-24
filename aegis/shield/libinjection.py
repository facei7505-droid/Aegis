"""libinjection: the tokenizer-based SQLi/XSS detector ModSecurity and the OWASP CRS use (rule 942100).

Signatures look for the shapes of known attacks; libinjection tokenizes the input as SQL (in the
three contexts an input can land in: bare, inside '...' and inside "...") and compares the token
fingerprint with a list of thousands of known injection fingerprints. The two catch different
things, so Aegis uses both.

The C sources (BSD-3-Clause, github.com/libinjection/libinjection) are vendored in
`native/libinjection`. `aegis build-engine` compiles them into a small shared library; the Docker
image does it at build time. Without a compiler (a plain Windows laptop) Aegis runs exactly as
before, with signatures only: nothing here is required.
"""
from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

SOURCES = Path(__file__).parent / "native" / "libinjection"
SUFFIX = ".dll" if sys.platform == "win32" else (".dylib" if sys.platform == "darwin" else ".so")
NAME = "_libinjection" + SUFFIX


def _candidates(prefer: Path | None = None) -> list[Path]:
    paths = [prefer] if prefer else []
    if os.environ.get("AEGIS_LIBINJECTION"):
        paths.append(Path(os.environ["AEGIS_LIBINJECTION"]))
    paths.append(SOURCES.parent / NAME)
    paths.append(Path.home() / ".cache" / "aegis" / NAME)
    return paths


class _Engine:
    def __init__(self):
        self._lib = None
        self._tried = False
        self._lock = threading.Lock()
        self.path: Path | None = None
        self.prefer: Path | None = None  # a library just built somewhere else (aegis build-engine --output)

    def load(self):
        if self._tried:
            return self._lib
        with self._lock:
            if self._tried:
                return self._lib
            self._tried = True
            if os.environ.get("AEGIS_NO_LIBINJECTION"):
                return None
            for path in _candidates(self.prefer):
                if not path.exists():
                    continue
                try:
                    lib = ctypes.CDLL(str(path))
                    lib.libinjection_sqli.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
                    lib.libinjection_sqli.restype = ctypes.c_int
                    lib.libinjection_xss.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                    lib.libinjection_xss.restype = ctypes.c_int
                except (OSError, AttributeError):
                    continue
                self._lib, self.path = lib, path
                break
            return self._lib

    def reset(self, prefer: Path | None = None) -> None:
        with self._lock:
            self._lib, self._tried, self.path, self.prefer = None, False, None, prefer


ENGINE = _Engine()


def available() -> bool:
    return ENGINE.load() is not None


def is_sqli(value: str) -> tuple[bool, str]:
    """(is SQL injection, libinjection fingerprint such as 's&sos')."""
    lib = ENGINE.load()
    if lib is None or not value:
        return False, ""
    data = value.encode("utf-8", "surrogatepass")
    fingerprint = ctypes.create_string_buffer(8)
    return lib.libinjection_sqli(data, len(data), fingerprint) == 1, fingerprint.value.decode("ascii", "replace")


def is_xss(value: str) -> bool:
    lib = ENGINE.load()
    if lib is None or not value:
        return False
    data = value.encode("utf-8", "surrogatepass")
    return lib.libinjection_xss(data, len(data)) == 1


def build(dest: Path | None = None, compiler: str | None = None) -> Path:
    """Compile the vendored sources into a shared library. Returns its path."""
    cc = compiler or os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        raise RuntimeError("no C compiler found (install gcc or clang, or use the Docker image)")
    if dest is None:
        dest = SOURCES.parent / NAME
        if not os.access(dest.parent, os.W_OK):
            dest = Path.home() / ".cache" / "aegis" / NAME
    dest.parent.mkdir(parents=True, exist_ok=True)
    sources = [str(SOURCES / f) for f in ("libinjection_sqli.c", "libinjection_xss.c", "libinjection_html5.c")]
    flags = ["-O2", "-shared", "-o", str(dest)] + ([] if sys.platform == "win32" else ["-fPIC"])
    result = subprocess.run([cc, *flags, *sources], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"compiling libinjection failed:\n{result.stderr.strip()[:2000]}")
    ENGINE.reset(prefer=dest)
    return dest
