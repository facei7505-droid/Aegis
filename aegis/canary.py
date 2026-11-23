"""Canary check: does the patched app still behave like the live one on real traffic?

Static gates prove the vulnerable pattern is gone; they cannot prove the app still works. Before a
patch is accepted, the canary:

  1. copies the app folder, writes the patched file into the copy,
  2. starts the copy on a free port with the app's own command,
  3. replays recent real requests (safe methods only: GET/HEAD) against the copy and the live app,
  4. rejects the patch if the copy is worse anywhere: a server error, a 4xx where the live app
     answered 2xx/3xx, or a page that changed beyond small differences.

If the live app answered the attack itself (shield in monitor mode), the canary also replays the
attack against the copy and reports whether the answer changed. The attack is never sent to the
live app again.

Only apps the gateway can start (a `command`) and whose state lives in their folder get a canary:
the copy works on copies of their files, so replayed requests cannot touch real data.
"""
from __future__ import annotations

import difflib
import http.client
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

SAFE_METHODS = {"GET", "HEAD"}
KEPT_HEADERS = ("Cookie", "Accept", "Accept-Language", "Authorization", "User-Agent")
IGNORE = shutil.ignore_patterns(".git", "__pycache__", ".aegis", "logs", "*.pyc", ".pytest_cache", "node_modules")


@dataclass
class Recorded:
    method: str
    target: str
    headers: dict
    body: bytes | None = None


class TrafficRecorder:
    """The last N distinct clean requests per app (attacks are never recorded)."""

    def __init__(self, size: int = 100):
        self.size = size
        self._items: OrderedDict[tuple[str, str], Recorded] = OrderedDict()
        self._lock = threading.Lock()
        self.attack_responses: dict[str, tuple[int, bytes]] = {}

    def add(self, method: str, target: str, headers: dict) -> None:
        if method not in SAFE_METHODS:
            return
        key = (method, target)
        with self._lock:
            self._items.pop(key, None)
            self._items[key] = Recorded(method, target, {k: v for k, v in headers.items() if k in KEPT_HEADERS})
            while len(self._items) > self.size:
                self._items.popitem(last=False)

    def recent(self, n: int) -> list[Recorded]:
        with self._lock:
            return list(self._items.values())[-n:]

    def remember_attack(self, incident_id: str, request: Recorded, status: int, body: bytes) -> None:
        """What the live app answered to an attack it was not shielded from (monitor mode)."""
        with self._lock:
            self.attack_responses[incident_id] = (request, status, body[:200_000])
            if len(self.attack_responses) > 200:
                self.attack_responses.pop(next(iter(self.attack_responses)))


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _fetch(port: int, rec: Recorded, timeout: float = 10.0) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request(rec.method, rec.target, body=rec.body, headers=rec.headers)
        resp = conn.getresponse()
        return resp.status, resp.read()
    except OSError:
        return 0, b""
    finally:
        conn.close()


_NOISE = re.compile(rb"\d+|[0-9a-f]{16,}", re.I)


def similar(a: bytes, b: bytes) -> float:
    if a == b:
        return 1.0
    a, b = _NOISE.sub(b"0", a)[:50_000], _NOISE.sub(b"0", b)[:50_000]
    return difflib.SequenceMatcher(None, a, b, autojunk=False).quick_ratio() if a != b else 1.0


def worse(live: tuple[int, bytes], canary: tuple[int, bytes]) -> str | None:
    """Why the patched copy answered worse than the live app, or None."""
    (ls, lb), (cs, cb) = live, canary
    if cs == 0:
        return "no answer"
    if cs >= 500 and ls < 500:
        return f"{ls} → {cs}"
    if 400 <= cs < 500 and ls < 400:
        return f"{ls} → {cs}"
    if ls < 400 and cs == ls and similar(lb, cb) < 0.6:
        return "page changed"
    return None


class Canary:
    """Plugs into Healer.replay: `check_patch(incident, file, patched_source) -> (bad, notes)`."""

    def __init__(self, spec, recorder: TrafficRecorder, sample: int = 30, start_timeout: float = 20.0):
        self.spec = spec
        self.recorder = recorder
        self.sample = sample
        self.start_timeout = start_timeout

    def _live_port(self) -> int:
        return int(self.spec.upstream.rsplit(":", 1)[1].split("/")[0])

    def check_patch(self, incident, file: str, patched: str) -> tuple[bool, str]:
        root = Path(self.spec.cwd or self.spec.source).resolve()
        target = Path(file).resolve()
        if not self.spec.command or root not in target.parents:
            return False, "canary skipped: the gateway cannot start this app"
        with tempfile.TemporaryDirectory(prefix="aegis-canary-") as tmp:
            copy = Path(tmp) / root.name
            shutil.copytree(root, copy, ignore=IGNORE, symlinks=True)
            (copy / target.relative_to(root)).write_text(patched, encoding="utf-8")
            port = _free_port()
            command = [part.replace("{port}", str(port)) for part in self.spec.command]
            env = dict(os.environ, PYTHONUNBUFFERED="1", AEGIS_CANARY="1", **self.spec.env)
            env["PYTHONPATH"] = os.pathsep.join([str(Path(__file__).resolve().parents[1]), env.get("PYTHONPATH", "")])
            proc = subprocess.Popen(command, cwd=copy, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                if not _wait(port, self.start_timeout, proc):
                    return True, "the patched app did not start"
                requests = self.recorder.recent(self.sample)
                problems = []
                for rec in requests:
                    why = worse(_fetch(self._live_port(), rec), _fetch(port, rec))
                    if why:
                        problems.append(f"{rec.method} {rec.target[:60]} ({why})")
                notes = f"canary: {len(requests)} real request(s) replayed"
                if problems:
                    return True, notes + f", {len(problems)} worse: " + "; ".join(problems[:3])
                notes += ", all as before"
                seen = self.recorder.attack_responses.get(incident.id)
                if seen is not None:  # replayed against the copy only, never the live app
                    attack, status, body = seen
                    after = _fetch(port, attack)
                    changed = after[0] != status or similar(body, after[1]) < 0.999
                    notes += "; the attack now gets a different answer" if changed else "; the attack gets the same answer"
                return False, notes
            finally:
                proc.terminate()
                try:
                    proc.wait(5)
                except subprocess.TimeoutExpired:
                    proc.kill()


def _wait(port: int, timeout: float, proc: subprocess.Popen) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.15)
    return False
