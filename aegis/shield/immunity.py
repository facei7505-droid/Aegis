"""Shared immunity: an address banned for attacking one protected site is banned on all of them.

Attackers rarely stop at one shop: scanners walk lists of sites. One Aegis server protects many sites,
so the first site that sees an attack protects the rest. The more sites, the sooner an attacker is
known everywhere.

Rules that keep this from hurting real people:
  * only sites in block mode contribute bans (a site still learning may produce false alarms);
  * the ban lasts as long as the local one (15 minutes by default), never forever;
  * a site's owner can pardon an address for their own site (`/unban`); the ban stays elsewhere.

Bans are kept in a small JSON file, so a restart does not let a known attacker straight back in.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path


class SharedBans:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._bans: dict[str, tuple[float, str]] = {}   # address -> (until, the site that banned it)
        self._lock = threading.Lock()
        self._load()

    def ban(self, address: str, until: float, site: str) -> None:
        with self._lock:
            current = self._bans.get(address)
            if current and current[0] >= until:
                return
            self._bans[address] = (until, site)
            self._prune(time.time())
            self._save()

    def until(self, address: str, now: float | None = None) -> float:
        entry = self._bans.get(address)
        if not entry:
            return 0.0
        return entry[0] if entry[0] > (now if now is not None else time.time()) else 0.0

    def source(self, address: str) -> str:
        entry = self._bans.get(address)
        return entry[1] if entry else ""

    def lift(self, address: str) -> bool:
        with self._lock:
            found = self._bans.pop(address, None) is not None
            if found:
                self._save()
            return found

    def active(self, now: float | None = None) -> dict[str, tuple[float, str]]:
        now = now if now is not None else time.time()
        return {a: e for a, e in list(self._bans.items()) if e[0] > now}

    # -------------------------------------------------------------- disk --
    def _prune(self, now: float) -> None:
        if len(self._bans) > 1000:
            self._bans = {a: e for a, e in self._bans.items() if e[0] > now}

    def _load(self) -> None:
        if not self.path or not self.path.is_file():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        except (OSError, ValueError):
            return
        now = time.time()
        self._bans = {a: (float(e[0]), str(e[1])) for a, e in raw.items()
                      if isinstance(e, list) and len(e) == 2 and float(e[0]) > now}

    def _save(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".bans.", suffix=".json")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({a: [e[0], e[1]] for a, e in self._bans.items()}, fh)
            os.replace(tmp, self.path)
        except OSError:
            pass  # bans still work in memory
