"""End-to-end demonstration of the self-healing loop on VulnShop.

    python -m aegis demo            # rules only
    python -m aegis demo --ai       # + Claude for what rules can't fix

Phases
  1. baseline  - real attacks against the unprotected app (shows the holes are real)
  2. defend    - same attacks with Aegis Shield in front; each block triggers healing
  3. proof     - replay every attack against the healed app WITHOUT the shield
  4. function  - legitimate requests still work after healing
"""
from __future__ import annotations

import importlib.util
import logging
import os
import re
import shutil
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .healer import Healer
from .models import Finding, HealingRecord
from .scanner.engine import scan_source, sort_by_severity
from .shield import AegisShield, ShieldConfig

DEMO_SRC = Path(__file__).parent / "demo_app" / "vulnshop"
ADMIN_PASSWORD = "correct-horse-battery"  # aegis: ignore[AEG006] demo credential, not a real secret


@dataclass
class Case:
    name: str
    label: str
    method: str
    path: str
    params: dict = field(default_factory=dict)
    exploited: Callable[[int, str], bool] = lambda status, body: False


@dataclass
class Check:
    name: str
    path: str
    params: dict
    ok: Callable[[int, str], bool]
    method: str = "GET"


def _canary(status: int, body: str) -> bool:
    return bool(re.search(r"(^|\n|>)\s*AEGIS_CANARY\s*($|\n|<)", body))


ATTACKS = [
    Case("Login bypass", "SQL injection", "POST", "/login",
         {"username": "admin' --", "password": "anything"},
         lambda s, b: "Welcome admin" in b),
    Case("Dump password hashes", "SQL injection", "GET", "/search",
         {"q": "zzz' UNION SELECT username, password_hash FROM users --"},
         lambda s, b: "admin - " in b),
    Case("Reflected XSS", "Cross-site scripting", "GET", "/search",
         {"q": "<script>alert(document.cookie)</script>"},
         lambda s, b: "<script>alert(document.cookie)</script>" in b),
    Case("Run OS command", "Command injection", "GET", "/ping",
         {"host": "127.0.0.1 & echo AEGIS_CANARY"}, _canary),
    Case("Read secret file", "Path traversal", "GET", "/download",
         {"file": "../secret.txt"}, lambda s, b: "AEGIS_SECRET_FLAG" in b),
    Case("Template injection", "Server-side template injection", "GET", "/greet",
         {"name": "{{7*7}}"}, lambda s, b: "Hello 49" in b),
    Case("Execute Python", "Code injection", "GET", "/products",
         {"filter": "__import__('platform').system()"},
         lambda s, b: any(os_name in b for os_name in ("'Linux'", "'Windows'", "'Darwin'"))),
]

CHECKS = [
    Check("Admin can log in", "/login", {"username": "admin", "password": ADMIN_PASSWORD},
          lambda s, b: s == 200 and "Welcome admin" in b, "POST"),
    Check("Wrong password is rejected", "/login", {"username": "admin", "password": "nope"},
          lambda s, b: s == 401, "POST"),
    Check("Search finds products", "/search", {"q": "Lap"}, lambda s, b: s == 200 and "Laptop" in b),
    Check("Search with an apostrophe", "/search", {"q": "O'Brien"}, lambda s, b: s == 200 and "O'Brien Mug" in b),
    Check("Network check works", "/ping", {"host": "8.8.8.8"}, lambda s, b: s == 200 and "8.8.8.8 is reachable" in b),
    Check("Public file download", "/download", {"file": "readme.txt"}, lambda s, b: s == 200 and "public files" in b),
    Check("Greeting", "/greet", {"name": "Magzhan"}, lambda s, b: s == 200 and "Hello Magzhan" in b),
    Check("Price filter", "/products", {"filter": "{'max_price': 50000}"},
          lambda s, b: s == 200 and "Headphones" in b and "Laptop" not in b),
]


MARKER = ".aegis-vulnshop"


class Lab:
    """A private copy of VulnShop that can be (re)loaded from disk at any time."""

    def __init__(self, workdir: str | None = None):
        self.root = Path(workdir or tempfile.mkdtemp(prefix="aegis-demo-"))
        if self.root.exists() and any(self.root.iterdir()):
            if not (self.root / MARKER).exists():
                raise FileExistsError(
                    f"{self.root} is not empty and was not created by Aegis; choose an empty or new folder")
            shutil.rmtree(self.root)  # our own earlier copy of VulnShop
        elif self.root.exists():
            self.root.rmdir()
        shutil.copytree(DEMO_SRC, self.root)
        (self.root / MARKER).write_text("VulnShop copy made by `aegis demo`/`aegis lab`. Safe to delete.\n")
        self.app_file = str(self.root / "app.py")
        os.environ.setdefault("SECRET_KEY", "demo-" + uuid.uuid4().hex)
        os.environ["VULNSHOP_DB"] = str(self.root / "shop.db")

    def load(self):
        name = f"vulnshop_{uuid.uuid4().hex[:8]}"
        spec = importlib.util.spec_from_file_location(name, self.app_file)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        module.init_db()
        module.app.config["PROPAGATE_EXCEPTIONS"] = False
        module.app.logger.disabled = True  # the demo provokes errors on purpose
        logging.getLogger("werkzeug").disabled = True
        return module.app


def _send(client, method: str, path: str, params: dict) -> tuple[int, str]:
    if method == "POST":
        resp = client.post(path, data=params)
    else:
        resp = client.get(path, query_string=params)
    return resp.status_code, resp.get_data(as_text=True)


@dataclass
class DemoResult:
    findings_before: list[Finding]
    findings_after: list[Finding]
    baseline: list[tuple[Case, bool]]
    defended: list[tuple[Case, int]]
    proof: list[tuple[Case, bool]]
    checks_before: list[tuple[Check, bool]]
    checks_after: list[tuple[Check, bool]]
    false_positives: list[str]
    records: list[HealingRecord]
    diff: str
    duration_s: float
    ai_enabled: bool
    workdir: str
    fix_report: object = None

    def summary(self) -> dict:
        healed = [r for r in self.records if r.status == "healed"]
        return {
            "vulnerabilities_found": len(self.findings_before),
            "exploitable_before": sum(1 for _, e in self.baseline if e),
            "attacks_blocked": sum(1 for _, s in self.defended if s == 403),
            "attacks_total": len(self.defended),
            "exploitable_after": sum(1 for _, e in self.proof if e),
            "incidents_healed": len(healed),
            "patches_applied": sum(len(r.patches) for r in self.records),
            "mean_heal_ms": round(sum(r.total_ms for r in healed) / len(healed), 1) if healed else 0.0,
            "false_positives": len(self.false_positives),
            "checks_passing_before": sum(1 for _, ok in self.checks_before if ok),
            "checks_passing_after": sum(1 for _, ok in self.checks_after if ok),
            "checks_total": len(self.checks_after),
            "remaining_findings": len(self.findings_after),
        }


def run_demo(workdir: str | None = None, ai_fixer=None, harden: bool = True,
             log: Callable[[str], None] = print) -> DemoResult:
    started = time.perf_counter()
    lab = Lab(workdir)
    findings_before = sort_by_severity(scan_source(lab.app_file))
    log(f"[scan]     {len(findings_before)} vulnerabilities in VulnShop")

    # 1. baseline ------------------------------------------------------
    client = lab.load().test_client()
    baseline = []
    for case in ATTACKS:
        status, body = _send(client, case.method, case.path, case.params)
        baseline.append((case, case.exploited(status, body)))
    checks_before = []
    for chk in CHECKS:
        status, body = _send(client, chk.method, chk.path, chk.params)
        checks_before.append((chk, chk.ok(status, body)))
    log(f"[baseline] {sum(e for _, e in baseline)}/{len(baseline)} attacks succeed against the unprotected app")

    # 2. defend + heal ---------------------------------------------------
    current: dict = {}

    def replay(incident, file):
        case = current.get("case")
        if case is None:
            return False
        c = lab.load().test_client()
        status, body = _send(c, case.method, case.path, case.params)
        return case.exploited(status, body)

    healer = Healer(str(lab.root), mode="auto", ai_fixer=ai_fixer, replay=replay)
    app = lab.load()
    shield = AegisShield(app.wsgi_app, ShieldConfig(ban_after=0), on_incident=[healer])
    app.wsgi_app = shield
    client = app.test_client()
    defended = []
    for case in ATTACKS:
        current["case"] = case
        status, _ = _send(client, case.method, case.path, case.params)
        defended.append((case, status))
        rec = healer.records[-1] if healer.records else None
        if status == 403 and rec is not None:
            log(f"[defend]   {case.label:<31} blocked in {rec.incident.detect_ms:.2f} ms -> {rec.status}"
                f" ({rec.total_ms:.0f} ms)")
        else:
            log(f"[defend]   {case.label:<31} NOT blocked (status {status})")
    current.clear()

    false_positives = []
    for chk in CHECKS:
        status, body = _send(client, chk.method, chk.path, chk.params)
        if status == 403:
            false_positives.append(chk.name)

    # 3. harden: fix the remaining issues found by the scanner ---------
    fix_report = None
    if harden:
        from .patcher.engine import fix_file
        fix_report = fix_file(lab.app_file, ai_fixer=ai_fixer)
        log(f"[harden]   {len(fix_report.patches)} more verified patch(es), "
            f"{len(fix_report.escalated)} escalated to a human")

    # 4. proof + function ---------------------------------------------
    client = lab.load().test_client()
    proof = []
    for case in ATTACKS:
        status, body = _send(client, case.method, case.path, case.params)
        proof.append((case, case.exploited(status, body)))
    checks_after = []
    for chk in CHECKS:
        status, body = _send(client, chk.method, chk.path, chk.params)
        checks_after.append((chk, chk.ok(status, body)))
    log(f"[proof]    {sum(e for _, e in proof)}/{len(proof)} attacks still work after healing (no shield)")
    log(f"[function] {sum(ok for _, ok in checks_after)}/{len(checks_after)} legitimate requests work "
        f"(before healing: {sum(ok for _, ok in checks_before)}/{len(checks_before)})")

    from .patcher.engine import unified_diff
    original = (DEMO_SRC / "app.py").read_text(encoding="utf-8")
    patched = Path(lab.app_file).read_text(encoding="utf-8")
    return DemoResult(
        findings_before=findings_before,
        findings_after=sort_by_severity(scan_source(lab.app_file)),
        baseline=baseline, defended=defended, proof=proof,
        checks_before=checks_before, checks_after=checks_after,
        false_positives=false_positives, records=healer.records,
        diff=unified_diff(original, patched, "app.py"),
        duration_s=round(time.perf_counter() - started, 2),
        ai_enabled=ai_fixer is not None, workdir=str(lab.root), fix_report=fix_report,
    )
