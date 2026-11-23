"""Positive security model: learn what normal requests to each endpoint look like.

Signatures recognise known attack syntax. A profile recognises *anything unusual for this app*:
a parameter the endpoint never receives (`idA=2`), letters in a field that always held digits,
a quote in a field that never contained one, a value ten times longer than ever seen.

    profile = TrafficProfile()
    for each clean request during the learning window:  profile.learn(path, inputs)
    then for every request:                              profile.check(path, inputs) -> Finding | None

Learned per endpoint (path with numeric/hex/uuid segments generalised) and per parameter:
the character classes seen, the longest value, whether it was always numeric. Only query, form,
JSON and multipart fields are profiled; headers and cookies vary too much between clients.
"""
from __future__ import annotations

import json
import re
import threading
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

PROFILED = {"query", "form", "json"}
TRACKING = re.compile(r"^(utm_\w+|fbclid|gclid|yclid|_ga|_gl|mc_\w+|ref|source|lang|_|v|t|ts|cb|nocache)$", re.I)
DANGEROUS = set("'\"<>;|&$`(){}[]\\%\r\n\x00*=")
_SEGMENT = re.compile(r"^(\d+|[0-9a-f]{12,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$", re.I)


def template(path: str) -> str:
    """/user/42/orders/9f8e... -> /user/{id}/orders/{id}"""
    return "/".join("{id}" if _SEGMENT.match(seg) else seg for seg in path.split("/"))


def char_classes(value: str) -> set[str]:
    out = set()
    for ch in value:
        if ch.isdigit():
            out.add("digit")
        elif ch.isascii() and ch.isalpha():
            out.add("ascii")
        elif ch.isalpha():
            out.add("letter")  # Cyrillic, Kazakh, accented: one class
        elif ch == " ":
            out.add("space")
        elif unicodedata.category(ch).startswith("C"):
            out.add("control")
        else:
            out.add(ch)  # each symbol on its own: ' and - mean very different things
    return out


@dataclass
class ParamStats:
    seen: int = 0
    classes: set[str] = field(default_factory=set)
    max_len: int = 0
    numeric: bool = True

    def learn(self, value: str) -> None:
        self.seen += 1
        self.classes |= char_classes(value)
        self.max_len = max(self.max_len, len(value))
        self.numeric = self.numeric and bool(re.fullmatch(r"-?\d+(\.\d+)?", value or "0"))


@dataclass
class Endpoint:
    seen: int = 0
    params: dict[str, ParamStats] = field(default_factory=dict)


@dataclass
class Anomaly:
    score: float
    reasons: list[str]
    param: str
    value: str
    location: str


class TrafficProfile:
    def __init__(self, min_samples: int = 20, strict_paths: bool = False):
        self.min_samples = min_samples      # an endpoint is judged only after this many clean requests
        self.strict_paths = strict_paths    # also flag paths never seen while learning
        self.endpoints: dict[str, Endpoint] = {}
        self.learned = 0
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- learn --
    def learn(self, path: str, inputs: list[tuple[str, str, str]]) -> None:
        key = template(path)
        with self._lock:
            ep = self.endpoints.setdefault(key, Endpoint())
            ep.seen += 1
            self.learned += 1
            for location, name, value in inputs:
                if location in PROFILED:
                    ep.params.setdefault(name, ParamStats()).learn(value)

    # ---------------------------------------------------------------- check --
    def check(self, path: str, inputs: list[tuple[str, str, str]]) -> Anomaly | None:
        key = template(path)
        ep = self.endpoints.get(key)
        if ep is None:
            if self.strict_paths and self.learned >= self.min_samples * 5:
                return Anomaly(0.85, [f"path never seen while learning: {key}"], "path", path, "path")
            return None
        if ep.seen < self.min_samples:
            return None
        worst: Anomaly | None = None
        for location, name, value in inputs:
            if location not in PROFILED:
                continue
            found = self._check_param(ep, name, value)
            if found and (worst is None or found[0] > worst.score):
                worst = Anomaly(found[0], found[1], name, value, location)
        return worst

    def _check_param(self, ep: Endpoint, name: str, value: str) -> tuple[float, list[str]] | None:
        stats = ep.params.get(name)
        if stats is None or stats.seen < 3:
            if stats is None and not TRACKING.match(name):
                return 0.85, [f"parameter '{name}' never sent to this endpoint"]
            return None
        reasons, score = [], 0.0
        new = char_classes(value) - stats.classes
        dangerous = sorted(c for c in new if len(c) == 1 and c in DANGEROUS or c == "control")
        if dangerous:
            reasons.append("characters never seen in this field: " + " ".join(repr(c) for c in dangerous))
            score = max(score, 0.85)
        if stats.numeric and value and not re.fullmatch(r"-?\d+(\.\d+)?", value):
            reasons.append("text in a field that was always a number")
            score = max(score, 0.85)
        if len(value) > max(stats.max_len * 2, stats.max_len + 24):
            reasons.append(f"{len(value)} characters, longest seen {stats.max_len}")
            score = max(score, 0.85)
        other = sorted(c for c in new if c not in dangerous and len(c) == 1)
        if other and not reasons:
            reasons.append("unusual symbols for this field: " + " ".join(repr(c) for c in other))
            score = max(score, 0.5)
        return (score, reasons) if reasons else None

    # ---------------------------------------------------------- persistence --
    def to_dict(self) -> dict:
        with self._lock:
            return {"min_samples": self.min_samples, "strict_paths": self.strict_paths, "learned": self.learned,
                    "endpoints": {k: {"seen": e.seen, "params": {n: {"seen": p.seen, "classes": sorted(p.classes),
                                                                     "max_len": p.max_len, "numeric": p.numeric}
                                                                 for n, p in e.params.items()}}
                                  for k, e in self.endpoints.items()}}

    @classmethod
    def from_dict(cls, data: dict) -> "TrafficProfile":
        prof = cls(data.get("min_samples", 20), data.get("strict_paths", False))
        prof.learned = data.get("learned", 0)
        for key, e in data.get("endpoints", {}).items():
            ep = Endpoint(e["seen"])
            for name, p in e["params"].items():
                ep.params[name] = ParamStats(p["seen"], set(p["classes"]), p["max_len"], p["numeric"])
            prof.endpoints[key] = ep
        return prof

    def save(self, path: str) -> None:
        tmp = Path(path).with_suffix(".tmp")
        tmp.write_text(json.dumps(self.to_dict(), ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)

    @classmethod
    def load(cls, path: str) -> "TrafficProfile":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
