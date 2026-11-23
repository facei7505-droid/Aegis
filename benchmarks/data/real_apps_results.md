## 5. Real vulnerable applications from GitHub

Measured 2026-11-23 with `aegis range` (one Aegis Gateway in front of all three apps). Commits are pinned in `aegis/range.py`.

| App | What it is | Aegis findings | Healed live through the gateway |
| --- | --- | --- | --- |
| [DSVW](https://github.com/stamparm/DSVW) | "Damn Small Vulnerable Web" by Miroslav Stampar (author of sqlmap); plain `http.server`, no framework | 8 (6 critical, 2 high) | 3 SQL injections, OS command injection, 2 path traversals: automatic, verified. `pickle` and `exec` go to a human |
| [vulpy](https://github.com/fportantier/vulpy) (`bad/`) | Insecure Flask app with blueprints, by Fabian Martinez Portantier | 7 (SQL injection in a helper module, debug mode) | Login bypass `admin' --`: the sink is in `libuser.login`, one call away from the route `/user/login`; Aegis follows the call and patches it |
| VulnShop | Aegis' own demo shop | 13 | 7/7 attack classes |

Things vulpy needed that are not about security: its MFA pages import `pyotp`/`qrcode` (optional in the range), and it passes bytes to `set_cookie`, which current Werkzeug rejects. `aegis range` adds a small compatibility shim for that; it does not change the app's code.

## 6. Real attack tools

Same DSVW, same parameter (`/?id=2`), four setups. Commands and output are in `docs/REAL_TOOLS.md`.

| Setup | sqlmap 1.10 (`--batch --dump`) |
| --- | --- |
| No protection | 4 injection techniques found, `users` table dumped (admin password `7en8aiDoh!`) |
| Behind Aegis Gateway (defaults) | 101/101 requests blocked (scanner user-agent, then auto-ban); "not injectable" |
| Behind the gateway, sqlmap evading (`--random-agent --tamper=space2comment --level 3 --risk 2`), auto-ban **off** | 1,168 of 1,204 requests blocked. The 36 that passed were the baseline request and simple probes such as a lone quote (28 caused SQL errors); none extracted data. "Not injectable" |
| After Aegis healed the code, **no shield at all** (`--level 3 --risk 2`) | "not injectable": the hole is gone, not just hidden |

| Setup | commix 4 (command injection, `/?domain=`) |
| --- | --- |
| No protection | injectable two ways; `id` ran as root |
| Behind Aegis Gateway, auto-ban off | "not injectable"; some probe fragments reached the shell and produced errors, none executed |

One false positive was found this way and fixed: at `--level 3` sqlmap sends `Referer: http://127.0.0.1:.../`, and the shield used to score an internal URL in `Referer` as SSRF. Referer and Origin are now excluded from the SSRF class (regression test `test_local_referer_is_not_ssrf`).
