"""One-line protection for real applications.

Flask:
    from aegis.integrations import protect
    protect(app)                                   # block attacks, propose patches, alerts from env

FastAPI / Starlette:
    from aegis.integrations import protect_asgi
    app = protect_asgi(app, source_root="src")

Django (wsgi.py):
    from aegis.integrations import protect_wsgi
    application = protect_wsgi(get_wsgi_application(), source_root=BASE_DIR)

Environment variables picked up automatically:
    AEGIS_MODE=block|monitor      AEGIS_HEAL=propose|auto|off
    AEGIS_TELEGRAM_TOKEN / AEGIS_TELEGRAM_CHAT      AEGIS_WEBHOOK_URL
    AEGIS_LOG=path/to/incidents.jsonl              ANTHROPIC_API_KEY (Claude patches)
"""
from __future__ import annotations

import inspect
import os
from pathlib import Path

from .healer import Healer
from .shield import AegisShield, AegisShieldASGI, ShieldConfig, TelegramAlerter, WebhookAlerter


def _parts(source_root: str | None, mode: str | None, heal: str | None, app_name: str, ai: bool | None,
           log_path: str | None, caller_file: str | None):
    mode = mode or os.environ.get("AEGIS_MODE", "block")
    heal = heal or os.environ.get("AEGIS_HEAL", "propose")
    root = source_root or (str(Path(caller_file).parent) if caller_file else os.getcwd())
    config = ShieldConfig(mode=mode, log_path=log_path or os.environ.get("AEGIS_LOG"))

    alerters = []
    if os.environ.get("AEGIS_TELEGRAM_TOKEN") and os.environ.get("AEGIS_TELEGRAM_CHAT"):
        alerters.append(TelegramAlerter(app_name=app_name))
    if os.environ.get("AEGIS_WEBHOOK_URL"):
        alerters.append(WebhookAlerter(app_name=app_name))

    callbacks = []
    healer = None
    if heal in ("propose", "auto"):
        ai_fixer = None
        use_ai = ai if ai is not None else bool(os.environ.get("ANTHROPIC_API_KEY"))
        if use_ai:
            from .ai import AIFixer, ClaudeClient
            client = ClaudeClient()
            if client.available:
                ai_fixer = AIFixer(client)
        # Healing runs on a background thread: a blocked request never waits for a patch.
        healer = Healer(root, mode=heal, ai_fixer=ai_fixer, background=True)
        callbacks.append(healer)
    return config, callbacks, alerters, healer


def _caller_file() -> str | None:
    frame = inspect.stack()[2]
    return frame.filename


def protect(app, source_root: str | None = None, mode: str | None = None, heal: str | None = None,
            app_name: str | None = None, ai: bool | None = None, log_path: str | None = None):
    """Protect a Flask app in place and return it."""
    name = app_name or getattr(app, "name", "app")
    config, callbacks, alerters, healer = _parts(source_root, mode, heal, name, ai, log_path, _caller_file())
    shield = AegisShield(app.wsgi_app, config, on_incident=callbacks, alerters=alerters)
    shield.healer = healer
    app.wsgi_app = shield
    app.extensions = getattr(app, "extensions", {})
    app.extensions["aegis"] = shield
    return app


def protect_wsgi(wsgi_app, source_root: str | None = None, mode: str | None = None, heal: str | None = None,
                 app_name: str = "app", ai: bool | None = None, log_path: str | None = None) -> AegisShield:
    config, callbacks, alerters, healer = _parts(source_root, mode, heal, app_name, ai, log_path, _caller_file())
    shield = AegisShield(wsgi_app, config, on_incident=callbacks, alerters=alerters)
    shield.healer = healer
    return shield


def protect_asgi(asgi_app, source_root: str | None = None, mode: str | None = None, heal: str | None = None,
                 app_name: str = "app", ai: bool | None = None, log_path: str | None = None) -> AegisShieldASGI:
    config, callbacks, alerters, healer = _parts(source_root, mode, heal, app_name, ai, log_path, _caller_file())
    shield = AegisShieldASGI(asgi_app, config, on_incident=callbacks, alerters=alerters)
    shield.healer = healer
    return shield
