"""Shared immunity: an address banned for attacking one protected site is banned on all of them.

Attackers rarely stop at one shop: scanners walk lists of sites. One Aegis server protects many sites,
so the first site that sees an attack protects the rest. The more sites, the sooner an attacker is
known everywhere.

Rules that keep this from hurting real people:
  * only sites in block mode contribute bans (a site still learning may produce false alarms);
  * the ban lasts as long as the local one (15 minutes by default), never forever;
  * a site's owner can pardon an address for their own site (`/unban`); the ban stays elsewhere.

Bans are kept in a small JSON file, so a restart does not let a known attacker straight back in. The file
is written at most every few seconds (a scanner wave bans thousands of addresses at once), and a broken
file costs the old bans, never the start of the server.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path


class SharedBans:
    SAVE_EVERY = 5.0      # seconds between writes of the file
    LIMIT = 200_000       # addresses kept; past it, the bans that end soonest go first

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._bans: dict[str, tuple[float, str]] = {}   # address -> (until, the site that banned it)
        self._lock = threading.Lock()
        self._saved_at = 0.0
        self._timer: threading.Timer | None = None
        self._load()

    def ban(self, address: str, until: float, site: str) -> None:
        with self._lock:
            current = self._bans.get(address)
            if current and current[0] >= until:
                return
            self._bans[address] = (until, site)
            self._prune(time.time())
            self._save_soon()

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
                self._save_soon()
            return found

    def flush(self) -> None:
        """Write pending changes now (shutdown, tests)."""
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            self._save()

    def active(self, now: float | None = None) -> dict[str, tuple[float, str]]:
        now = now if now is not None else time.time()
        return {a: e for a, e in list(self._bans.items()) if e[0] > now}

    # -------------------------------------------------------------- disk --
    def _prune(self, now: float) -> None:
        if len(self._bans) > 1000 and len(self._bans) % 500 == 0:  # now and then, not on every ban
            self._bans = {a: e for a, e in self._bans.items() if e[0] > now}
        if len(self._bans) > self.LIMIT:
            keep = sorted(self._bans.items(), key=lambda item: item[1][0])[-self.LIMIT // 2:]
            self._bans = dict(keep)

    def _save_soon(self) -> None:
        """Called with the lock held: write now if the last write is old enough, else once a little later."""
        wait = self.SAVE_EVERY - (time.time() - self._saved_at)
        if wait <= 0:
            self._save()
        elif self._timer is None and self.path:
            self._timer = threading.Timer(wait, self._timed_save)
            self._timer.daemon = True
            self._timer.start()

    def _timed_save(self) -> None:
        with self._lock:
            self._timer = None
            self._save()

    def _load(self) -> None:
        if not self.path or not self.path.is_file():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        except (OSError, ValueError):
            return
        now = time.time()
        if not isinstance(raw, dict):
            return
        for address, entry in raw.items():
            try:
                until, site = float(entry[0]), str(entry[1])
            except (TypeError, ValueError, IndexError, KeyError):
                continue  # one bad entry does not cost the rest
            if until > now and isinstance(address, str):
                self._bans[address] = (until, site)

    def _save(self) -> None:
        self._saved_at = time.time()
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
