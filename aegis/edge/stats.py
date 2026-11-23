"""Per-site, per-day numbers: what the client's report and the Telegram /status are made of.

stats/<domain>/<YYYY-MM-DD>.json
    {"requests": 18234, "attacks": 412, "blocked": 398, "by_type": {"sqli": 120, ...},
     "patches": {"wp-user-enum": 31}, "paths": {"/wp-login.php": 260}, "clients": {"45.9.20.1": 88},
     "brute_force": 3, "rate_limited": 1}

Counts are kept in memory and merged into the day's file every few seconds, so a restart loses at
most that much. Only counts and attacked paths are stored: no request bodies, no visitor data.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from pathlib import Path

from ..models import Incident

TOP = 50  # paths and addresses kept per day


def _day(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts if ts is not None else time.time()).date().isoformat()


class Stats:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self._lock = threading.Lock()
        self._pending: dict[tuple[str, str], dict] = defaultdict(self._blank)

    @staticmethod
    def _blank() -> dict:
        return {"requests": 0, "attacks": 0, "blocked": 0, "by_type": Counter(), "patches": Counter(),
                "paths": Counter(), "clients": Counter(), "brute_force": 0, "rate_limited": 0}

    # ---------------------------------------------------------- recording --
    def requests(self, site: str, n: int, ts: float | None = None) -> None:
        if n > 0:
            with self._lock:
                self._pending[(site, _day(ts))]["requests"] += n

    def incident(self, site: str, inc: Incident) -> None:
        with self._lock:
            day = self._pending[(site, _day(inc.timestamp))]
            day["attacks"] += 1
            day["blocked"] += int(inc.blocked)
            day["by_type"][inc.attack_type] += 1
            day["paths"][inc.path[:200]] += 1
            day["clients"][inc.client] += 1
            if inc.attack_type == "virtual_patch":
                day["patches"][inc.param] += 1
            elif inc.attack_type == "brute_force":
                day["brute_force"] += 1
            elif inc.attack_type == "rate_limit":
                day["rate_limited"] += 1

    # ------------------------------------------------------------ storage --
    def flush(self) -> None:
        with self._lock:
            pending, self._pending = self._pending, defaultdict(self._blank)
        for (site, day), delta in pending.items():
            path = self.root / site / f"{day}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            current = self._read(path)
            for key in ("requests", "attacks", "blocked", "brute_force", "rate_limited"):
                current[key] = current.get(key, 0) + delta[key]
            for key in ("by_type", "patches", "paths", "clients"):
                merged = Counter(current.get(key, {}))
                merged.update(delta[key])
                current[key] = dict(merged.most_common(TOP if key in ("paths", "clients") else None))
            fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".day.", suffix=".json")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(current, fh, ensure_ascii=False)
            os.replace(tmp, path)

    @staticmethod
    def _read(path: Path) -> dict:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            return {}

    def day(self, site: str, day: str) -> dict:
        data = {**{k: (dict(v) if isinstance(v, Counter) else v) for k, v in self._blank().items()},
                **self._read(self.root / site / f"{day}.json")}
        with self._lock:  # not yet flushed
            pending = self._pending.get((site, day))
            if pending:
                for key in ("requests", "attacks", "blocked", "brute_force", "rate_limited"):
                    data[key] += pending[key]
                for key in ("by_type", "patches", "paths", "clients"):
                    merged = Counter(data[key])
                    merged.update(pending[key])
                    data[key] = dict(merged)
        return data

    def period(self, site: str, first: date, last: date) -> dict:
        """Sum of days first..last, plus the per-day series for charts."""
        total = {k: (dict(v) if isinstance(v, Counter) else v) for k, v in self._blank().items()}
        series = []
        day = first
        while day <= last:
            d = self.day(site, day.isoformat())
            series.append((day.isoformat(), d["requests"], d["blocked"], d["attacks"]))
            for key in ("requests", "attacks", "blocked", "brute_force", "rate_limited"):
                total[key] += d[key]
            for key in ("by_type", "patches", "paths", "clients"):
                merged = Counter(total[key])
                merged.update(d[key])
                total[key] = dict(merged)
            day += timedelta(days=1)
        total["series"] = series
        return total

    def prune(self, keep_days: int) -> int:
        """Delete day files older than keep_days. Returns how many were removed."""
        cutoff = (date.today() - timedelta(days=keep_days)).isoformat()
        removed = 0
        for path in self.root.glob("*/*.json"):
            if path.stem < cutoff:
                path.unlink()
                removed += 1
        return removed


def prune_jsonl(path: str | Path, keep_days: int) -> int:
    """Keep only the last keep_days of a JSON Lines incident log. Returns lines dropped."""
    path = Path(path)
    if not path.exists():
        return 0
    cutoff = time.time() - keep_days * 86400
    kept, dropped = [], 0
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                ts = json.loads(line).get("timestamp", 0)
            except ValueError:
                continue
            if ts >= cutoff:
                kept.append(line)
            else:
                dropped += 1
    if dropped:
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".log.", suffix=".jsonl")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.writelines(kept)
        os.replace(tmp, path)
    return dropped
