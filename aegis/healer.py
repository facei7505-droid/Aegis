"""The self-healing loop.

    attack hits the app
      -> Shield blocks it and records an Incident            (milliseconds)
      -> Healer maps the request to the handler that served it
      -> finds the vulnerable line(s) behind that attack class
      -> patches them (rules first, then Claude), verifies every patch
      -> optionally replays the real attack against the patched code
      -> applies the patch (auto) or saves it for review (propose)
"""
from __future__ import annotations

import queue
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .models import Escalation, Finding, HealingRecord, Incident
from .patcher.engine import fix_file
from .config import TEST_FILES
from .scanner.astutil import call_name
from .scanner.engine import FileAnalysis, iter_python_files, scan_source
from .scanner.project import analyze_project

# Which static rules can be the root cause of a runtime attack class.
ATTACK_RULES: dict[str, set[str]] = {
    "sqli": {"AEG001"},
    "xss": {"AEG008"},
    "path_traversal": {"AEG005"},
    "command_injection": {"AEG002"},
    "ssti": {"AEG009"},
    "code_injection": {"AEG003", "AEG004", "AEG009"},
    "ssrf": {"AEG011"},
}

ReplayFn = Callable[[Incident, str], bool]  # -> True if the exploit STILL works on the patched file


def _route_regex(pattern: str, prefixed: bool = False) -> re.Pattern:
    """Flask '/item/<int:id>' and FastAPI '/item/{id}' -> regex.

    prefixed=True also accepts a mount prefix in front ('/api' + '/search'), for blueprints and
    routers whose url_prefix is set elsewhere.
    """
    out, i = "", 0
    for m in re.finditer(r"<(?:[^:<>]+:)?([^<>]+)>|\{([^{}:]+)(?::[^{}]+)?\}", pattern):
        out += re.escape(pattern[i:m.start()]) + r"[^/]+"
        i = m.end()
    out += re.escape(pattern[i:])
    head = "^(/[^?#]*?)?" if prefixed else "^"
    return re.compile(head + out.rstrip("/") + "/?$")


COOLDOWN = 600.0  # seconds before an incident that could not be healed is analysed again


@dataclass
class Healer:
    root: str
    mode: str = "propose"             # "auto" applies verified patches; "propose" writes .diff files
    ai_fixer: object | None = None
    test_cmd: str | None = None
    replay: ReplayFn | None = None
    patch_dir: str | None = None
    background: bool = False
    records: list[HealingRecord] = field(default_factory=list)
    max_records: int = 1000
    _healed: set[tuple[str, str | None, str]] = field(default_factory=set)
    _escalated: dict[tuple, float] = field(default_factory=dict)
    _routes: dict[str, tuple[float, list]] = field(default_factory=dict)
    errors: int = 0
    _queue: "queue.Queue[Incident] | None" = None

    def __post_init__(self):
        self._lock = threading.Lock()
        self._records_lock = threading.Lock()
        if self.background:
            self._queue = queue.Queue(maxsize=1000)
            threading.Thread(target=self._worker, daemon=True).start()

    # The shield calls this for every incident.
    def __call__(self, incident: Incident) -> None:
        if self._queue is not None:
            try:
                self._queue.put_nowait(incident)
            except queue.Full:  # an attack flood: the shield keeps blocking, healing catches up later
                pass
        else:
            self.heal(incident)

    def _worker(self):
        while True:
            incident = self._queue.get()
            try:
                self.heal(incident)
            except Exception as exc:  # one bad incident (read-only disk, odd file) must not stop healing
                self.errors += 1
                self._store(HealingRecord(incident, None, None, [], [], f"error: {type(exc).__name__}: {exc}"))
            finally:
                self._queue.task_done()

    def wait(self) -> None:
        if self._queue is not None:
            self._queue.join()

    # ---------------------------------------------------------- locate --
    def _files(self):
        return iter_python_files(self.root, exclude=TEST_FILES)

    def _route_table(self) -> list[tuple[str, str, list[str], str]]:
        """(file, full pattern, methods, function) for every route.

        Blueprint and router prefixes (`register_blueprint(mod_user, url_prefix="/user")`,
        `include_router(r, prefix="/api")`, `Blueprint(..., url_prefix=...)`) are resolved, so
        `/user/login` maps to the `/login` route of `mod_user`. Files are re-parsed only when they change.
        """
        parsed, prefixes = [], {}
        for file in self._files():
            key = str(file)
            try:
                mtime = Path(file).stat().st_mtime
                cached = self._routes.get(key)
                if cached is None or cached[0] != mtime:
                    analysis = FileAnalysis(file)
                    cached = (mtime, analysis.routes(), _route_owners(analysis.tree), _mount_prefixes(analysis.tree))
                    self._routes[key] = cached
            except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
                continue
            parsed.append((key, cached))
            prefixes.update(cached[3])
        table = []
        for key, (_, routes, owners, _) in parsed:
            for pattern, methods, func in routes:
                prefix = prefixes.get(owners.get(func, ""), "")
                table.append((key, prefix.rstrip("/") + pattern if prefix else pattern, methods, func))
        return table

    def _callees(self, file: str, function: str) -> list[tuple[str, str]]:
        """Project functions the handler calls directly: `libuser.login(...)`, `helper(...)`."""
        import ast

        try:
            analysis = FileAnalysis(file)
        except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
            return []
        func = next((n for n in ast.walk(analysis.tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and n.name == function), None)
        if func is None:
            return []
        here = Path(file).parent
        local = {n.name for n in analysis.tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        out: list[tuple[str, str]] = []
        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue
            name = call_name(node) or ""
            module, _, attr = name.rpartition(".")
            target = None
            if not module and name in local and name != function:
                target = (file, name)
            else:
                real = analysis.aliases.get(module or name)
                if real and not module:  # from libuser import login
                    module, _, attr = real.rpartition(".")
                elif real:
                    module = real
                for base in (here, Path(self.root)):
                    candidate = base / (module.replace(".", "/") + ".py") if module else None
                    if candidate is not None and candidate.is_file():
                        target = (str(candidate), attr)
                        break
            if target and target not in out:
                out.append(target)
        return out[:12]

    def _server_handler(self, incident: Incident) -> tuple[str | None, str | None]:
        """Plain http.server apps (DSVW) have no route table: one do_GET/do_POST serves every path."""
        import ast

        wanted = f"do_{incident.method.upper()}"
        hits = []
        for file in self._files():
            try:
                tree = FileAnalysis(file).tree
            except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and any(
                        isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef)) and b.name == wanted for b in node.body):
                    bases = {call_name(b) if isinstance(b, ast.Call) else (getattr(b, "attr", None) or getattr(b, "id", None))
                             for b in node.bases}
                    if bases & {"BaseHTTPRequestHandler", "SimpleHTTPRequestHandler", "StreamRequestHandler"}:
                        hits.append((str(file), wanted))
        return hits[0] if len(hits) == 1 else (None, None)

    def locate(self, incident: Incident) -> tuple[str | None, str | None, str | None]:
        """Return (file, function, route pattern) that handled the request.

        An exact route match wins. Otherwise a route mounted under a prefix (blueprint, router) is
        accepted only if exactly one route fits. Aegis never guesses: an ambiguous request is left to
        a human (the shield keeps blocking it).
        """
        table = self._route_table()

        def allowed(methods):
            return incident.method in methods or "*" in methods or not methods

        exact = [r for r in table if _route_regex(r[1]).match(incident.path) and allowed(r[2])]
        if exact:
            file, pattern, _, func = exact[0]
            return file, func, pattern
        mounted = [r for r in table if r[1].strip("/") and _route_regex(r[1], prefixed=True).match(incident.path)
                   and allowed(r[2])]
        if len(mounted) == 1:
            file, pattern, _, func = mounted[0]
            return file, func, pattern
        if not table:
            file, func = self._server_handler(incident)
            if file:
                return file, func, "*"
        return None, None, None

    # ------------------------------------------------------------ heal --
    def heal(self, incident: Incident) -> HealingRecord:
        t0 = time.perf_counter()
        file, function, route = self.locate(incident)
        classes = {c for c, s in (incident.classes or {}).items() if s >= 0.5} | {incident.attack_type}
        rules = set().union(*(ATTACK_RULES.get(c, set()) for c in classes))
        if file is None or not rules:
            rec = HealingRecord(incident, route, function, [], [], "no_root_cause",
                                locate_ms=_ms(t0))
            return self._store(rec)
        key = (file, function, frozenset(rules))
        if time.time() - self._escalated.get(key, 0) < COOLDOWN:
            # Already analysed and handed to a human: do not re-run the fixer (or pay for Claude) per request.
            return self._store(HealingRecord(incident, route, function, [], [], "already_escalated",
                                             locate_ms=_ms(t0)))

        # The sink is often in a helper the handler calls (vulpy: do_login -> libuser.login), so the
        # handler and the project functions it calls directly are searched, handler first, with
        # request data followed across modules.
        try:
            analyze_project(self.root, list(self._files()))
        except OSError:
            pass
        findings, handled, pending = [], set(), []
        for tfile, tfunc in [(file, function)] + self._callees(file, function):
            found = [f for f in scan_source(tfile) if f.function == tfunc and f.rule_id in rules]
            done = {r for r in rules if (tfile, tfunc, r) in self._healed}
            todo = [f for f in found if f.rule_id not in done]
            handled |= done
            if todo:
                file, function, findings, pending = tfile, tfunc, found, todo
                break
        locate_ms = _ms(t0)
        if not pending:
            if handled:
                status = "already_healed" if self.mode == "auto" else "already_proposed"
            else:
                status = "not_vulnerable"  # the handler has no hole of this class (fixed earlier, or never had one)
            return self._store(HealingRecord(incident, route, function, [], [], status, locate_ms=locate_ms))
        rules = {f.rule_id for f in pending}

        with self._lock:  # one patch at a time per process
            t1 = time.perf_counter()
            report = fix_file(file, select=lambda f: f.function == function and f.rule_id in rules,
                              ai_fixer=self.ai_fixer, test_cmd=self.test_cmd,
                              cwd=str(Path(self.root)), write=False)
            patch_ms = _ms(t1)

            t2 = time.perf_counter()
            status = "needs_human"
            if report.patches and report.changed:
                exploitable = False
                if self.replay is not None:
                    original = Path(file).read_text(encoding="utf-8")
                    Path(file).write_text(report.patched, encoding="utf-8")
                    try:
                        exploitable = bool(self.replay(incident, file))
                    finally:
                        Path(file).write_text(original, encoding="utf-8")
                if self.replay is not None:  # recorded only when a replay really ran
                    for p in report.patches:
                        p.checks["exploit_replay"] = not exploitable
                if exploitable:
                    report.escalated.extend(Escalation(p.finding, "Patch passed static checks but the replayed "
                                                       "attack still worked; rejected.") for p in report.patches)
                    report.patches = []
                else:
                    status = "healed"
                    self._apply(file, report, incident)
                    for p in report.patches:
                        self._healed.add((file, function, p.finding.rule_id))
            verify_ms = _ms(t2)

        if status == "needs_human":
            self._escalated[key] = time.time()
        rec = HealingRecord(incident, route, function, findings, report.patches, status,
                            locate_ms=locate_ms, patch_ms=patch_ms, verify_ms=verify_ms,
                            escalations=report.escalated)
        return self._store(rec)

    def _apply(self, file: str, report, incident: Incident) -> None:
        if self.mode == "auto":
            Path(file).write_text(report.patched, encoding="utf-8")
        else:
            out = Path(self.patch_dir or Path(self.root) / ".aegis" / "patches")
            out.mkdir(parents=True, exist_ok=True)
            (out / f"{incident.id}-{Path(file).stem}.diff").write_text(report.diff, encoding="utf-8")

    def _store(self, rec: HealingRecord) -> HealingRecord:
        with self._records_lock:
            self.records.append(rec)
            if len(self.records) > self.max_records:
                del self.records[: len(self.records) - self.max_records]
        return rec


ROUTE_METHODS = {"route", "get", "post", "put", "patch", "delete", "api_route", "websocket"}


def _route_owners(tree) -> dict[str, str]:
    """function name -> the object whose decorator registers it (`mod_user` in @mod_user.route)."""
    import ast

    owners = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                if isinstance(target, ast.Attribute) and target.attr in ROUTE_METHODS and isinstance(target.value, ast.Name):
                    owners[node.name] = target.value.id
    return owners


def _mount_prefixes(tree) -> dict[str, str]:
    """Blueprint / router variable -> URL prefix, from registration calls and constructors."""
    import ast

    out = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        name = call_name(node) or ""
        if name.endswith((".register_blueprint", ".include_router")) and node.args and isinstance(node.args[0], ast.Name):
            value = kw.get("url_prefix") or kw.get("prefix")
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                out[node.args[0].id] = value.value
    for node in ast.walk(tree):  # Blueprint("x", __name__, url_prefix="/x") / APIRouter(prefix="/x")
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call) and (call_name(node.value) or "").split(".")[-1] in ("Blueprint", "APIRouter")):
            for k in node.value.keywords:
                if k.arg in ("url_prefix", "prefix") and isinstance(k.value, ast.Constant):
                    out.setdefault(node.targets[0].id, k.value.value)
    return out


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 2)
