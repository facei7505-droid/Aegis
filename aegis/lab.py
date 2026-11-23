"""Live lab: run VulnShop on localhost and watch it heal itself in the browser.

    aegis lab                # http://127.0.0.1:5000

Default mode is `monitor` + `auto` heal, which makes the loop visible:
  1st attack  -> works (the hole is real), Aegis records it and patches the code
  the server reloads with the patched file
  2nd attack  -> the same request no longer works
Use `--shield block` to see attacks blocked immediately instead.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import uuid
from pathlib import Path
from urllib.parse import quote

from .demo import ATTACKS, DEMO_SRC, MARKER
from .healer import Healer
from .shield import AegisShield, ShieldConfig


def run_lab(workdir: str = "aegis-lab", port: int = 5000, shield_mode: str = "monitor", heal: str = "auto",
            fresh: bool = False, ai_fixer=None) -> None:
    root = Path(workdir).resolve()
    is_child = os.environ.get("WERKZEUG_RUN_MAIN") == "true"
    if root.exists() and any(root.iterdir()) and not (root / MARKER).exists():
        raise SystemExit(f"{root} is not empty and was not created by Aegis; pass --workdir with a new folder")
    if fresh and root.exists() and not is_child:
        shutil.rmtree(root)
    if not root.exists() or not any(root.iterdir()):
        shutil.copytree(DEMO_SRC, root, dirs_exist_ok=True)
        (root / MARKER).write_text("VulnShop copy made by `aegis lab`. Safe to delete.\n")
    os.environ.setdefault("SECRET_KEY", "lab-" + uuid.uuid4().hex)
    os.environ["VULNSHOP_DB"] = str(root / "shop.db")

    spec = importlib.util.spec_from_file_location("vulnshop_lab", root / "app.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["vulnshop_lab"] = module
    spec.loader.exec_module(module)
    module.init_db()
    app = module.app

    # Heal inside the request: a file change restarts the dev server, which would drop queued work.
    healer = Healer(str(root), mode=heal, ai_fixer=ai_fixer) if heal != "off" else None

    def report(incident):
        action = "BLOCKED" if incident.blocked else "seen (monitor)"
        print(f"\n  ⚡ {incident.attack_type} on {incident.path} {action} — healing…", flush=True)

    callbacks = [report] + ([healer] if healer else [])
    if healer:
        original_heal = healer.heal

        def heal_and_log(incident):
            rec = original_heal(incident)
            if rec.status == "healed":
                rules = ", ".join(sorted({p.finding.rule_id for p in rec.patches}))
                verb = "patched" if heal == "auto" else "patch proposed in .aegis/patches"
                print(f"  ✔ {rec.function}() {verb} ({rules}) in {rec.total_ms:.0f} ms — "
                      f"{'server reloads with the fix' if heal == 'auto' else 'review the .diff'}", flush=True)
            elif rec.status in ("not_vulnerable", "already_healed"):
                print(f"  ✔ {rec.function}() is already safe against this attack", flush=True)
            else:
                print(f"  · {rec.status.replace('_', ' ')}", flush=True)
            return rec

        healer.heal = heal_and_log

    app.wsgi_app = AegisShield(app.wsgi_app, ShieldConfig(mode=shield_mode, ban_after=0,
                                                         log_path=str(root / "incidents.jsonl")),
                               on_incident=callbacks)

    if not is_child:
        base = f"http://127.0.0.1:{port}"
        print("\n  Aegis lab — VulnShop is running with Aegis in front of it")
        print(f"  shield: {shield_mode} · heal: {heal} · code: {root / 'app.py'}\n")
        print("  Try these (open each one twice):")
        for case in ATTACKS:
            if case.method == "GET":
                q = "&".join(f"{k}={quote(str(v))}" for k, v in case.params.items())
                print(f"   {case.label:<31} {base}{case.path}?{q}")
        print(f"   {'SQL injection (login)':<31} curl -X POST {base}/login -d \"username=admin' --&password=x\"")
        print("\n  Ctrl+C to stop. Incidents: " + str(root / "incidents.jsonl") + "\n")
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=True)
