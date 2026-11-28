"""Signatures shared by Aegis and the site connectors (aegis/edge/connectors/*.php).

Origin lock. Aegis adds `X-Aegis-Auth: v1.<unix time>.<hmac>` to every request it forwards; the HMAC
covers the time, the public host and the visitor address Aegis sends in `X-Real-Ip`. The connector on
the site's own server refuses requests without a valid header, so someone who found the server's real
IP cannot go around Aegis, and it can trust `X-Real-Ip` as the visitor's address.

Editor pass. After a sign-in with editing rights, the connector sets a cookie
`aegis_editor=v1.<expires>.<user id>.<hmac>`. Aegis relaxes markup checks for editors only when this
cookie verifies, so a forged "I am signed in" cookie no longer works.

Both use HMAC-SHA256 with one secret per site, shared by Aegis and that site only. The PHP side
computes exactly the same strings: keep the two in step (tests/test_signing.py checks it with PHP).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time

VERSION = "v1"
ORIGIN_HEADER = "X-Aegis-Auth"
EDITOR_COOKIE = "aegis_editor"
MAX_SKEW = 300  # seconds an origin signature stays valid (clock drift plus slow uploads)


def new_secret() -> str:
    return secrets.token_hex(32)


def _mac(secret: str, message: str) -> str:
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def canonical_host(host: str) -> str:
    host = (host or "").strip().lower()
    if host.startswith("["):                       # [2001:db8::1]:443
        return host.split("]")[0] + "]"
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def origin_auth(secret: str, host: str, client_ip: str, now: float | None = None) -> str:
    ts = int(now if now is not None else time.time())
    return f"{VERSION}.{ts}.{_mac(secret, f'{VERSION}|{ts}|{canonical_host(host)}|{client_ip}')}"


def verify_origin(secret: str, value: str, host: str, client_ip: str, now: float | None = None) -> bool:
    try:
        version, ts, mac = (value or "").split(".")
        ts_i = int(ts)
    except ValueError:
        return False
    if not ts.isdigit():
        return False
    if version != VERSION or abs((now if now is not None else time.time()) - ts_i) > MAX_SKEW:
        return False
    return hmac.compare_digest(mac, _mac(secret, f"{VERSION}|{ts_i}|{canonical_host(host)}|{client_ip}"))


def editor_pass(secret: str, user_id: int | str, expires: int) -> str:
    return f"{VERSION}.{int(expires)}.{user_id}.{_mac(secret, f'editor|{int(expires)}|{user_id}')}"


def verify_editor(secret: str, value: str, now: float | None = None) -> bool:
    try:
        version, expires, user_id, mac = (value or "").split(".")
        exp_i = int(expires)
    except ValueError:
        return False
    if not expires.isdigit():
        return False
    if version != VERSION or not user_id.isdigit() or exp_i < (now if now is not None else time.time()):
        return False
    return hmac.compare_digest(mac, _mac(secret, f"editor|{exp_i}|{user_id}"))


FAILOVER_HEADER = "X-Aegis-Failover"
FAILOVER_MAX = 24 * 3600  # the longest a site can be opened at once


def failover_token(secret: str, host: str, until: int) -> str:
    """Tells the connector to accept direct visitors until `until`: Aegis is down and DNS points at the site."""
    return f"{VERSION}.{int(until)}.{_mac(secret, f'failover|{int(until)}|{canonical_host(host)}')}"


def verify_failover(secret: str, value: str, host: str, now: float | None = None) -> bool:
    try:
        version, until, mac = (value or "").split(".")
    except ValueError:
        return False
    now = now if now is not None else time.time()
    if version != VERSION or not until.isdigit() or not now < int(until) <= now + FAILOVER_MAX:
        return False
    return hmac.compare_digest(mac, _mac(secret, f"failover|{int(until)}|{canonical_host(host)}"))
