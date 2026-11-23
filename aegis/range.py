"""Aegis Range: several real vulnerable apps behind one Aegis Gateway, on your machine.

    aegis range              # set up (first run clones the apps from GitHub) and start everything
    aegis range --shield block --heal propose

Apps (pinned to exact commits, cloned into ./aegis-range/apps):
  * VulnShop  — Aegis' own demo shop (Flask)
  * DSVW      — "Damn Small Vulnerable Web" by Miroslav Stampar, author of sqlmap (plain http.server)
  * vulpy     — "Vulpy" by Fabian Martinez Portantier, the insecure half (Flask + blueprints)

Each app runs as its own process on an internal port. The gateway on :8080 is the only door:
  http://shop.localhost:8080   http://dsvw.localhost:8080   http://vulpy.localhost:8080
  (or http://localhost:8081 / 8082 / 8083), dashboard at http://localhost:8080/

When an app is healed in auto mode, the range restarts that app so the fix is live at once.
Only run the range on your own machine. Never expose these apps to a network.
"""
from __future__ import annotations

import os
import runpy
import shutil
import socket
import subprocess
import sys
import time
import types
from pathlib import Path

from .gateway import AppSpec, Gateway, serve

REPOS = {
    "dsvw": ("https://github.com/stamparm/DSVW.git", "9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908"),
    "vulpy": ("https://github.com/fportantier/vulpy.git", "5249cc8b05a1c37f6b2f757b1cf16a509c327122"),
}
OPTIONAL = {"vulpy": ["pyotp", "qrcode"]}  # only its MFA pages need these


def _free(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def _wait(port: int, timeout: float = 20.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if not _free(port):
            return True
        time.sleep(0.15)
    return False


def setup(root: Path, fetch: bool = True) -> list[AppSpec]:
    """Prepare the apps folder and return the specs (ports 5101.. internal, 8081.. on the gateway)."""
    from .demo import DEMO_SRC

    apps = root / "apps"
    apps.mkdir(parents=True, exist_ok=True)
    if not (apps / "shop").exists():
        shutil.copytree(DEMO_SRC, apps / "shop")
    for name, (url, commit) in REPOS.items():
        target = apps / name
        if target.exists() or not fetch:
            continue
        print(f"  cloning {name} from {url} …", flush=True)
        subprocess.run(["git", "clone", "-q", url, str(target)], check=True)
        subprocess.run(["git", "-C", str(target), "checkout", "-q", commit], check=True)
    py = sys.executable
    specs = [AppSpec("shop", "http://127.0.0.1:5101", ["shop.localhost"], 8081, str(apps / "shop"),
                     command=[py, "-m", "aegis.range", "run-flask", "app.py", "5101"], cwd=str(apps / "shop"))]
    if (apps / "dsvw").exists():
        specs.append(AppSpec("dsvw", "http://127.0.0.1:5102", ["dsvw.localhost"], 8082, str(apps / "dsvw"),
                             command=[py, "dsvw.py", "--port=5102"], cwd=str(apps / "dsvw")))
    if (apps / "vulpy").exists():
        bad = apps / "vulpy" / "bad"
        specs.append(AppSpec("vulpy", "http://127.0.0.1:5103", ["vulpy.localhost"], 8083, str(bad),
                             command=[py, "-m", "aegis.range", "run-flask", "vulpy.py", "5103", "--init", "db_init.py",
                                      "--optional", ",".join(OPTIONAL["vulpy"])], cwd=str(bad)))
    return specs


class Supervisor:
    """Starts each app as a child process and restarts it after a heal."""

    def __init__(self, specs: list[AppSpec], log_dir: Path):
        self.specs = specs
        self.procs: dict[str, subprocess.Popen] = {}
        self.log_dir = log_dir
        log_dir.mkdir(parents=True, exist_ok=True)

    def start(self, spec: AppSpec) -> bool:
        port = int(spec.upstream.rsplit(":", 1)[1])
        env = dict(os.environ, PYTHONUNBUFFERED="1", **spec.env)
        env["PYTHONPATH"] = os.pathsep.join([str(Path(__file__).resolve().parents[1]), env.get("PYTHONPATH", "")])
        log = open(self.log_dir / f"{spec.name}.log", "ab")
        self.procs[spec.name] = subprocess.Popen(spec.command, cwd=spec.cwd, env=env, stdout=log, stderr=log)
        return _wait(port)

    def stop(self, spec: AppSpec) -> None:
        proc = self.procs.pop(spec.name, None)
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
        port = int(spec.upstream.rsplit(":", 1)[1])
        end = time.time() + 5
        while not _free(port) and time.time() < end:
            time.sleep(0.1)

    def restart(self, spec: AppSpec, record=None) -> None:
        self.stop(spec)
        self.start(spec)
        what = f"{record.function}() patched" if record is not None else "restarted"
        print(f"  ✔ {spec.name}: {what}, app restarted with the fix", flush=True)

    def stop_all(self) -> None:
        for spec in self.specs:
            self.stop(spec)


def run(root: str = "aegis-range", port: int = 8080, shield: str = "monitor", heal: str = "auto",
        fetch: bool = True, ai_fixer=None, block_forever: bool = True):
    base = Path(root).resolve()
    specs = setup(base, fetch=fetch)
    for spec in specs:
        spec.shield, spec.heal = shield, heal
    sup = Supervisor(specs, base / "logs")
    print("\n  Aegis Range — real vulnerable apps behind one Aegis Gateway\n", flush=True)
    for spec in specs:
        ok = sup.start(spec)
        print(f"  {'✔' if ok else '✖'} {spec.name:<6} → http://{spec.hosts[0]}:{port}  (or http://localhost:{spec.listen})"
              + ("" if ok else f"  — did not start, see {base / 'logs' / (spec.name + '.log')}"), flush=True)
    gateway = Gateway(specs, on_healed=sup.restart if heal == "auto" else None, log_dir=str(base / "logs"),
                      ai_fixer=ai_fixer)
    servers = serve(gateway, port)
    print(f"\n  dashboard: http://localhost:{port}/    shield: {shield} · heal: {heal}", flush=True)
    print("  Ctrl+C to stop. Only attack your own machine.\n", flush=True)
    if not block_forever:
        return gateway, sup, servers
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for srv in servers:
            srv.shutdown()
        sup.stop_all()


# ------------------------------------------------------- app process entry --

def run_flask(script: str, port: int, init: str | None = None, optional: list[str] = ()) -> None:
    """Run a Flask script on our port, with debug and the reloader off (as in production)."""
    import flask

    for name in optional:  # e.g. vulpy's MFA pages: the rest of the app works without them
        try:
            __import__(name)
        except ImportError:
            stub = types.ModuleType(name)
            stub.__getattr__ = lambda attr, n=name: (_ for _ in ()).throw(
                ImportError(f"'{n}' is not installed (pip install {n}); only MFA pages need it"))
            sys.modules[name] = stub
    # Compatibility: apps written for older Werkzeug pass bytes as cookie values (vulpy does).
    set_cookie = flask.Response.set_cookie

    def compat_set_cookie(self, key, value="", *a, **k):
        if isinstance(value, (bytes, bytearray)):
            value = value.decode("latin-1")
        return set_cookie(self, key, value, *a, **k)
    flask.Response.set_cookie = compat_set_cookie
    if init:
        runpy.run_path(init, run_name="__main__")
    original = flask.Flask.run
    flask.Flask.run = lambda self, *a, **k: original(self, host="127.0.0.1", port=port, debug=False,
                                                      use_reloader=False, threaded=True)
    sys.path.insert(0, str(Path(script).resolve().parent))
    namespace = runpy.run_path(script, run_name="__main__")
    app = namespace.get("app")
    if app is not None and _free(port):  # the script did not start a server itself
        app.run()


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "run-flask":
        args = sys.argv[4:]
        init = args[args.index("--init") + 1] if "--init" in args else None
        opt = args[args.index("--optional") + 1].split(",") if "--optional" in args else []
        run_flask(sys.argv[2], int(sys.argv[3]), init, opt)
    else:
        raise SystemExit("usage: python -m aegis.range run-flask SCRIPT PORT [--init FILE] [--optional a,b]")
