# Aegis Shield on real, third-party data

Nothing below was written by the Aegis authors. Reproduce with `python benchmarks/realdata.py --csic ... --seclists ... --markdown REAL_WORLD.md`.

## 1. CSIC 2010: false alarms on 72,000 normal requests

HTTP DATASET CSIC 2010 (Spanish National Research Council): traffic to an e-commerce app with Spanish
names, addresses, passwords and product names. The training half was used to check new signatures for
false alarms. **The test half was never looked at while tuning.**

| Set | v1.0 (before) | Now |
| --- | --- | --- |
| Normal, training (36,000) | 0 flagged | **0 flagged** |
| Normal, test (36,000, held out) | 0 flagged | **0 flagged** |
| Inspection time per request | | median 138 µs, p99 527 µs |

## 2. CSIC 2010: 25,065 anomalous requests

CSIC labels a request anomalous for many reasons, not only injections. Aegis splits them by what is
anomalous (labels derived from the normal training set). These requests were used while tuning, so
the "now" column is not a held-out number.

| What is anomalous | Requests | v1.0 | Now |
| --- | --- | --- | --- |
| attack syntax in a value | 5,542 | 57.1% | **76.8%** |
| backup / config file probe | 5,508 | 0.0% | **45.0%** |
| renamed parameter | 7,038 | 0.0% | **0.0%** |
| unusual value, no attack syntax | 6,977 | 11.8% | **11.9%** |
| **All anomalous** | 25,065 | 15.9% | **30.2%** |

"Renamed parameter" and "unusual value" requests mostly carry no attack syntax (`idA=2` instead of
`id=2`, a password that is merely odd). Catching those needs a model of the app's normal traffic, which
is anomaly detection, not signatures. Aegis does not try, so it does not block real users for them either.

## 2b. CSIC 2010 with a learned traffic profile

Signatures only know attack syntax. With `learn=N` the shield also learns, per endpoint, which
parameters arrive, which characters each one holds and how long it gets, then flags what is unusual
(a positive security model). Here it learned the 36,000 requests of the **training** half and was then
judged on the **test** half and on the anomalies, which it never saw.

| | Signatures only | + learned profile | + strict paths |
| --- | --- | --- | --- |
| Normal test requests flagged (of 36,000) | 0 | **2** | **2** |
| attack syntax in a value | 76.8% | **91.6%** | **91.6%** |
| backup / config file probe | 45.0% | **45.0%** | **100.0%** |
| renamed parameter | 0.0% | **100.0%** | **100.0%** |
| unusual value, no attack syntax | 11.9% | **49.4%** | **49.4%** |
| **All anomalous (25,065)** | 30.2% | **72.0%** | **84.1%** |

CSIC is a closed, generated shop, which is the best case for a learned profile: every legitimate page and
parameter shows up during learning. A real site changes, so the profile is per app, kept on disk, and
relearned after deploys; password fields keep their relaxed threshold, and tracking parameters
(`utm_*`, `fbclid`…) are ignored. `strict_paths` suits APIs and closed apps, not sites that add pages often.

## 3. SecLists payload lists used while tuning

Misses in these lists were studied, so these numbers are an upper bound.

| List | Class | Payloads | v1.0 | Now |
| --- | --- | --- | --- | --- |
| Generic-SQLi.txt | sqli | 268 | 47.4% | **59.7%** |
| quick-SQLi.txt | sqli | 77 | 70.1% | **70.1%** |
| sqli.auth.bypass.txt | sqli | 96 | 100.0% | **100.0%** |
| Generic-BlindSQLi.fuzzdb.txt | sqli | 42 | 97.6% | **97.6%** |
| SQLi-Polyglots.txt | sqli | 3 | 100.0% | **100.0%** |
| MySQL-SQLi-Login-Bypass.fuzzdb.txt | sqli | 8 | 62.5% | **62.5%** |
| XSS-Jhaddix.txt | xss | 110 | 92.7% | **100.0%** |
| XSS-BruteLogic.txt | xss | 114 | 92.1% | **97.4%** |
| XSS-Cheat-Sheet-PortSwigger.txt | xss | 6,047 | 100.0% | **100.0%** |
| XSS-Polyglots.txt | xss | 14 | 100.0% | **100.0%** |
| LFI-Jhaddix.txt | path_traversal | 930 | 28.4% | **80.4%** |
| command-injection-commix.txt | command_injection | 8,262 | 100.0% | **100.0%** |
| UnixAttacks.fuzzdb.txt | command_injection | 512 | 38.1% | **41.4%** |

## 4. SecLists payload lists held out

Measured once before tuning, then once after. Their misses were never looked at.

| List | Class | Payloads | v1.0 | Now |
| --- | --- | --- | --- | --- |
| MSSQL.fuzzdb.txt | sqli | 17 | 41.2% | **82.4%** |
| MySQL.fuzzdb.txt | sqli | 6 | 66.7% | **66.7%** |
| Oracle.fuzzdb.txt | sqli | 55 | 92.7% | **94.5%** |
| XSS-OFJAAAH.txt | xss | 2,976 | 78.8% | **82.6%** |
| XSS-Bypass-Strings-BruteLogic.txt | xss | 17 | 5.9% | **5.9%** |
| XSS-EnDe-evation.txt | xss | 207 | 25.6% | **29.0%** |
| XSS-payloadbox.txt | xss | 2,690 | 78.3% | **82.2%** |
| XSS-RSNAKE.txt | xss | 74 | 66.2% | **71.6%** |
| xss-without-parentheses-semi-colons-portswigger.txt | xss | 8 | 100.0% | **100.0%** |
| XSS-Somdev.txt | xss | 22 | 100.0% | **100.0%** |
| LFI-LFISuite-pathtotest.txt | path_traversal | 569 | 62.6% | **91.0%** |
| LFI-linux-and-windows_by-1N3@CrowdShield.txt | path_traversal | 1,156 | 9.3% | **69.9%** |

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

## Reading these numbers

- Single-token fuzz entries (`update`, `&`, `!`, `asc`) are in the lists but are not attacks on their own;
  blocking them would block real users. They count as misses here.
- A signature shield is the first layer. The point of Aegis is the second one: the hole in the code is
  patched, so a payload the shield misses still finds nothing to exploit.

## WordPress lab: a real CMS behind Aegis Edge (v1.3)

A real WordPress (github.com/WordPress/WordPress, SQLite, PHP 8.3) behind the gateway with the
`wordpress` preset, driven by Google Chrome through Playwright. Scripts: `benchmarks/wordpress/`;
numbers: `benchmarks/data/wordpress_lab.json`.

**Ordinary work, block mode.** Install, log in, quick draft, the block editor, a post with a Kaspi
button (`onclick`), a Yandex map iframe and an SQL sample, a page with a Yandex.Metrika counter,
autosaves, Cyrillic categories, settings with quotes, the comment blocklist, a user named O'Brien,
a profile bio with links, a photo upload, plugins, a navigation menu, export, visitor searches with
quotes and symbols, a comment with an emoji and a Kazakh name, an admin reply, the customizer:
**21 of 21 steps, 0 of 2,247 requests blocked.** With signatures alone (no preset) 3 of those
requests would have been blocked: the post, the Metrika page and the blocklist setting.

**Attacks, block mode** (each scenario from its own address):

| | |
| --- | --- |
| 40 password guesses on wp-login.php | 10 reach WordPress, 30 refused with 429; the same address still reads the site |
| xmlrpc `system.multicall` (200 passwords) and `pingback.ping` | 403, 403 |
| `?author=1`, REST `/wp/v2/users` (both URL forms) | 403 (allowed for signed-in editors) |
| `/wp-content/uploads/…/x.php`, `debug.log`, `wp-config.php.bak`, WPScan user-agent | 403 |
| Fake editor cookie + `<script>` post via REST | Aegis lets the markup through; WordPress refuses (401) |
| 400 page requests in a minute from one address | 429 after the limit (300 page requests; redirects count) |
| SecLists in search and comments: XSS / commands / LFI / SQLi | 110/110, 150/150, 126/150, 100/150 |

Most SQLi "misses" are list entries that are not attacks on their own (`update`, `like`, `asc`,
`0`); blocking those would block shoppers. Real misses found here (quote tautologies without a closing
quote, hex-encoded `waitfor delay`, `\x27UNION`, Windows paths) became signatures, and CSIC 2010
normal traffic stayed at 0 false alarms.

**Speed.** Median added latency +2.5 ms on a WordPress page (18.4 -> 20.9 ms) and +0.8 ms on a
static file; about 750 requests per second on 2 vCPU through Aegis with the PHP origin included,
0 errors at 32 concurrent clients.

**Not covered:** Bitrix and OpenCart presets are built from documentation and published attack
write-ups (including 1C-Bitrix's own advice on CVE-2022-27228), not from a running Bitrix.

