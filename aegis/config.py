"""Project configuration from `[tool.aegis]` in pyproject.toml or from aegis.toml.

    [tool.aegis]
    exclude = ["tests/*", "migrations/*"]
    disable = ["AEG010"]
    fail_on = "high"
    baseline = ".aegis-baseline.json"
    language = "ru"
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    tomllib = None

from .models import Finding


TEST_FILES = ["tests/*", "*/tests/*", "test/*", "*/test/*", "test_*.py", "*_test.py", "conftest.py"]


@dataclass
class Config:
    exclude: list[str] = field(default_factory=list)
    fix_tests: bool = False   # `aegis fix` leaves test code alone unless enabled
    disable: set[str] = field(default_factory=set)
    fail_on: str = "high"
    baseline: str | None = None
    language: str = "en"
    source: str | None = None


def load_config(start: str | os.PathLike = ".") -> Config:
    start = Path(start).resolve()
    folder = start if start.is_dir() else start.parent
    for directory in [folder, *folder.parents]:
        for name, section in (("aegis.toml", None), ("pyproject.toml", "tool.aegis")):
            candidate = directory / name
            if candidate.is_file() and tomllib is not None:
                try:
                    data = tomllib.loads(candidate.read_text(encoding="utf-8"))
                except (tomllib.TOMLDecodeError, UnicodeDecodeError):
                    continue
                if section:
                    for part in section.split("."):
                        data = data.get(part, {}) if isinstance(data, dict) else {}
                    if not data:
                        continue
                return Config(
                    exclude=list(data.get("exclude", [])),
                    disable={str(r).upper() for r in data.get("disable", [])},
                    fail_on=str(data.get("fail_on", "high")).lower(),
                    baseline=data.get("baseline"),
                    language=str(data.get("language", "en")),
                    fix_tests=bool(data.get("fix_tests", False)),
                    source=str(candidate),
                )
    return Config()


# ----------------------------------------------------------------- baseline --

def fingerprint(finding: Finding, root: str | os.PathLike = ".") -> str:
    """Stable id for a finding: survives line moves, changes when the code changes."""
    try:
        rel = Path(finding.file).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        rel = Path(finding.file).name
    code = re.sub(r"\s+", " ", re.sub(r"#.*$", "", finding.snippet)).strip()
    raw = f"{finding.rule_id}|{rel}|{finding.function}|{code}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def write_baseline(findings: list[Finding], path: str, root: str = ".") -> int:
    entries = sorted({fingerprint(f, root) for f in findings})
    Path(path).write_text(json.dumps({"version": 1, "fingerprints": entries}, indent=2) + "\n", encoding="utf-8")
    return len(entries)


def filter_baseline(findings: list[Finding], path: str, root: str = ".") -> tuple[list[Finding], int]:
    """Drop findings that are already in the baseline. Returns (new findings, suppressed count)."""
    try:
        known = set(json.loads(Path(path).read_text(encoding="utf-8")).get("fingerprints", []))
    except (OSError, ValueError):
        return findings, 0
    fresh = [f for f in findings if fingerprint(f, root) not in known]
    return fresh, len(findings) - len(fresh)
