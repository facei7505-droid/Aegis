<div align="center">

# 🛡 Aegis

### Self-healing application security

**Aegis blocks an attack in under a millisecond, finds the line of code the attack went through, patches it, and proves the exploit no longer works, usually in 30–50 ms.**

`zero runtime dependencies on 3.11+` · `Flask · Django · FastAPI` · `rules first, Claude second` · `every patch gated`

</div>

---

## Aegis Edge: protection for client sites (the product)

One server protects many websites. The site owner changes one DNS record; Caddy issues the HTTPS
certificate; Aegis applies the site's CMS preset (WordPress, 1C-Bitrix, OpenCart or generic) and
forwards clean requests to the site's own server. Built for small businesses in Kazakhstan: Russian
alerts and commands in Telegram, a monthly PDF report for the client, a 7-day learning period before
anything is blocked.

What a protected site gets:

| | |
| --- | --- |
| **Shield** | signatures, libinjection (the tokenizer behind ModSecurity's SQLi/XSS checks) as a second opinion, OWASP CRS file and shell lists used with context, CMS presets and virtual patches, login and flood limits |
| **Origin lock** | a small PHP connector on the site's server answers only requests signed by Aegis, so the server's real IP is no back door; the CMS sees the visitor's real IP; editors carry a signed pass, so a forged "signed in" cookie relaxes nothing |
| **Response guard** | reads the site's answers: a database error after a request with SQL syntax is a *confirmed* injection point, and Aegis closes exactly that field on that page and tells the owner what to fix; leaked system files or web-shell output are replaced and the address banned |
| **Shared immunity** | an address banned for attacking one site is banned on every site of the server |
| **Siege mode** | under a bot flood, visitors solve a one-second proof-of-work in the browser (idea of Anubis); bots without a browser get nothing. By hand (`/siege`) or automatically |
| **Site guard** | every 5 minutes: is the site up, did a script from a new outside domain appear (card skimmers), obfuscated loaders, SEO spam, defacement |
| **Failover** | if the Aegis server dies, a watchdog on a second machine points the sites back at their own servers and opens the connectors; sites keep working without protection until Aegis is back |

| Measured on real CMSs behind Aegis, driven in Chrome | WordPress ([data](benchmarks/data/wordpress_lab.json)) | 1C-Bitrix 26 shop ([data](benchmarks/data/bitrix_lab.json)) |
| --- | --- | --- |
| Ordinary owner, staff and shopper work, block mode | **21/21 steps, 0 blocked** | **17/17 steps, 0 blocked** (checkout, SQL and PHP consoles incl.) |
| Same session, signatures without the CMS preset | 3 would have been blocked | 3 would have been blocked |
| Known CMS attacks (CVE-2022-27228, xmlrpc, enumeration, backdoors, backups, shells in uploads) | all refused | all refused |
| Forged editor cookie posting `<script>` (connector installed) | 403 from Aegis | 403 from Aegis |
| Request straight to the site's server, around Aegis | 403 from the connector | 403 from the connector |
| SecLists XSS / commands / LFI / SQLi | 100% / 100% / 89% / 71% | 100% / 100% / 89% / 71% |
| Password guessing | 429 after 10 tries, site stays open | 429 after 10 tries, site stays open |
| Added latency, median: page / search / static file | +2.9 / +1.2 / +1.2 ms | +4 to +12 / +11 / +1 ms (287 KB home page: +12) |

```bash
aegis check shop.kz --pdf shop.pdf                 # passive check to show a prospective client
aegis edge add shop.kz --origin 198.51.100.7 --cms bitrix --client "ИП Ромашка"
aegis edge origin-test shop.kz                     # before the client moves DNS
aegis edge connector shop.kz                       # PHP files for the site: origin lock, real IP, editor pass
aegis edge serve                                   # behind Caddy: deploy/docker-compose.yml
aegis edge watchdog --config failover.json         # on a second machine
```

Start here: [deploy/README.ru.md](deploy/README.ru.md) (from an empty server to the first client),
[docs/SALES.ru.md](docs/SALES.ru.md) (offer, prices, objections, first messages),
[docs/shield/index.html](docs/shield/index.html) (landing page for clients). Reproduce the labs:
`benchmarks/wordpress/` and `benchmarks/bitrix/` (install, `lab.sh` with `session.py` and `attack.py`).

## Self-healing for Python developers (open source)

Most security tools stop at a warning. A scanner gives you a PDF with 200 findings. A firewall blocks the request and the hole stays open. AI code assistants suggest a fix, and you have to trust it.

Aegis closes the loop:

```
 attack ──► 1 DETECT ──► 2 BLOCK ──► 3 LOCATE ──► 4 PATCH ──► 5 VERIFY ──► 6 REPLAY
            0.1 ms       403         the handler   rules, then    4 gates     the real attack
                                     + vulnerable  Claude                     against the
                                     line                                     patched code
```

A patch is accepted only if it passes **all** of these gates:

1. **syntax**: the patched file compiles
2. **fixed**: the vulnerability is gone from that function
3. **no new**: no other vulnerability appeared anywhere in the file
4. **tests**: your own test suite still passes (optional, `--test "pytest -q"`)
5. **replay / canary**: the patched code runs in a copy of the app; recent real requests are replayed against the copy and the live app and must answer the same, and the attack is replayed against the copy (never the live app). In the demo the exploit must fail; behind the gateway any app it can start gets this canary.

Gates 1–3 are static: they re-scan the code with the same scanner. They prove the pattern is gone, not that the app still behaves the same. That is what gates 4 and 5, the property tests below, and `propose` mode (a human merges the diff) are for.

![Aegis self-healing report](docs/demo-report.png)

Videos: [Aegis Range, real apps behind one gateway (42 s)](docs/aegis-range-demo.mp4) · [VulnShop lab (50 s)](docs/aegis-lab-demo.mp4)

## Results

Reproduce with `python benchmarks/run.py --real-world` (full details in [BENCHMARKS.md](BENCHMARKS.md)).

| | |
| --- | --- |
| Real attacks against the demo shop that worked before | **7 / 7** |
| Blocked by the shield | **7 / 7** |
| Traced to the vulnerable line and patched automatically | **7 / 7** |
| Mean time from attack to verified patch | **30–50 ms** |
| Attacks that still work after healing (shield removed) | **0 / 7** |
| Legitimate requests that work after healing | **8 / 8**, up from 7 / 8: the SQL fix also repaired search for `O'Brien` |
| Shield on its tuning corpus (89 attacks / 146 tricky benign inputs) | **100 % detected / 0 % false alarms**: an upper bound, the corpus includes every bypass found in review |
| Shield on a frozen held-out set written after tuning (30 / 30) | **28 / 30 detected, 0 / 30 false alarms** |
| Noise on 3,000 files of real open-source libraries | 0 critical, 0 high, 0 automatic edits, 0 crashes |

### On real, third-party data and apps ([REAL_WORLD.md](REAL_WORLD.md))

| | |
| --- | --- |
| False alarms on 72,000 normal requests of the public CSIC 2010 dataset (test half never seen while tuning) | **0** |
| CSIC 2010 anomalies caught: signatures → + learned traffic profile → + strict paths (2 false alarms in 36,000) | **30 % → 72 % → 84 %** |
| SecLists payload lists held out from tuning: LFI / MSSQL injection / XSS | **9→70 % and 63→91 % / 41→82 % / 78→82 %** detected (before → after) |
| sqlmap against DSVW (a real vulnerable app by sqlmap's author): unprotected → behind Aegis Gateway | **table dumped → "not injectable"**, also with `--random-agent --tamper --level 3` |
| Same sqlmap run after Aegis healed the code, **with no shield at all** | **"not injectable"** |
| Holes healed live in other people's code (DSVW, vulpy) | SQL injection ×4, command injection, path traversal ×2, a login bypass whose sink was in a helper module |
| Every heal in the range checked by a canary: recent real requests replayed against the patched copy | **all answers as before**; the attack's answer changed |

## Why this is different

| | Finds the bug | Stops the live attack | Fixes the code | Proves the fix |
| --- | :-: | :-: | :-: | :-: |
| Static scanners (SAST) | ✅ | — | — | — |
| Web application firewalls | — | ✅ | — | — |
| AI coding assistants | sometimes | — | ✅ unverified | — |
| Autonomous cyber reasoning systems (e.g. DARPA AIxCC finalists) | ✅ | — | ✅ | ✅ (offline, before release) |
| **Aegis** | ✅ | ✅ | ✅ | ✅ **in production, at the moment of attack** |

The DARPA AI Cyber Challenge showed that AI can find and patch vulnerabilities on its own. Those systems work **offline**: they fuzz a codebase before release. Aegis takes the same idea to the place where most small companies actually get hurt: a **live web app**, at the moment it is attacked, with nobody on the security team because there is no security team.

## Quick start

```bash
git clone https://github.com/facei7505-droid/aegis && cd aegis
pip install -e ".[demo]"                # Python 3.10+, the core itself has no dependencies

aegis demo                              # watch the whole loop, writes aegis-demo-report.html
aegis lab                               # run the vulnerable shop on localhost and attack it yourself:
                                        # 1st attack works, Aegis patches, the server reloads, 2nd attack fails
aegis scan .                            # find vulnerabilities
aegis fix . --dry-run                   # show verified patches, change nothing
aegis fix . --test "pytest -q"          # apply them, but only if your tests still pass
aegis range                             # real vulnerable apps from GitHub behind one Aegis Gateway
aegis gateway -c gateway.toml           # protect your own apps (any language) from one server
```

With Claude for everything the rules cannot fix (your key never leaves your machine except to Anthropic's API):

```bash
export ANTHROPIC_API_KEY=sk-ant-...     # Windows PowerShell: $env:ANTHROPIC_API_KEY="sk-ant-..."
aegis fix . --ai --test "pytest -q"
aegis scan . --ai-triage --lang ru      # Claude confirms each finding and explains it for a business owner
```

**Spending is capped.** Every run stops calling Claude at `--ai-budget` (default **$0.25**). Before each request the worst case
(whole prompt plus the maximum answer) has to fit in what is left; afterwards the real cost from the API's usage block is
recorded. A ledger in `~/.aegis/ai-spend.json` adds up all runs, and `AEGIS_AI_TOTAL_BUDGET=3.5` stops everything at
that total. Triage and explanations use Claude Haiku 5.5 ($0.10/$0.50 per million tokens), patches use Sonnet 5.5
($2/$10). Each run ends with a line like `Claude: 3 request(s), 1,632 in / 1,150 out tokens, ≈$0.015`.
`aegis demo --ai` costs about $0.02–0.04, at most about $0.12.

### Protect a running app (one line)

```python
from aegis.integrations import protect

protect(app)            # Flask: block attacks, alert, write verified patches to .aegis/patches/
```

```python
from aegis.integrations import protect_asgi, protect_wsgi

app = protect_asgi(app)                                   # FastAPI / Starlette
application = protect_wsgi(get_wsgi_application())        # Django (wsgi.py)
```

Environment variables: `AEGIS_MODE=block|monitor`, `AEGIS_HEAL=propose|auto|off`, `AEGIS_TELEGRAM_TOKEN` and `AEGIS_TELEGRAM_CHAT` for instant alerts, `AEGIS_WEBHOOK_URL` for Slack and other webhooks, `AEGIS_LOG=incidents.jsonl`.

### Protect many apps from one server

```toml
# gateway.toml — see docs/GATEWAY.md
[[app]]
name = "shop"
upstream = "http://127.0.0.1:5101"
hosts = ["shop.localhost"]
source = "./shop"        # Python source enables healing; leave it out for apps in other languages
heal = "propose"
```

`aegis gateway -c gateway.toml` puts a shield in front of every app, a healer behind every Python app, and a live dashboard at `http://localhost:8080/`.

**Production default is `heal="propose"`:** Aegis writes a verified `.diff` for a human to merge instead of rewriting code on a live server. `auto` exists for staging, demos and teams that want it.

## How it works

```mermaid
flowchart LR
    R[HTTP request] --> S{Shield<br/>WSGI / ASGI}
    S -- clean --> A[Your app]
    S -- attack --> B[403 + incident]
    B --> AL[Telegram / webhook alert]
    B --> H[Healer]
    H --> L[Map path to route handler]
    L --> F[Taint-tracked findings<br/>in that function]
    F --> P1[Deterministic fixers]
    P1 -- cannot fix --> P2[Claude]
    P1 --> V{Verifier<br/>syntax · fixed · no new · tests}
    P2 --> V
    V -- rejected --> P2
    V -- passed --> RP{Replay the attack}
    RP -- still works --> X[Reject, escalate to a human]
    RP -- blocked --> D[Apply or propose .diff]
```

- **Scanner** (`aegis/scanner`): parses Python with `ast` and tracks attacker-controlled data (query, form, JSON, cookies, headers, Flask/FastAPI path parameters, Django `request.GET/POST`) through assignments, f-strings, concatenation and calls, until it reaches a dangerous sink. Sanitizers (`int()`, `html.escape`, `os.path.basename`, `secure_filename` and others) end the taint. Severity depends on whether the data is really attacker-controlled.
- **Patcher** (`aegis/patcher`): deterministic fixers rewrite the exact AST span and keep the file's own style (quotes, import order). When in doubt they refuse and escalate. SQL is parameterized only in value positions and only when the driver's placeholder style is known from the file's imports. Shell strings become argument lists only without pipes, globs or expansions, and never when the request picks the program. A variable assigned on two paths is never half-fixed. Fixes that change behaviour (`eval` to `literal_eval`, shell to argv) run only when taint analysis says the input comes from the request. Configuration fixes (secrets to environment variables, `yaml.safe_load`, `debug=False`) are applied regardless, and the secret fix means the app needs that variable set before it starts.
- **AI engine** (`aegis/ai`): Claude sees one function, the finding and the verifier's feedback. The proposal must be that one function and nothing else (same name, signature, decorators). Imports come from an allow-list and may not shadow builtins. A proposal that adds capabilities the original did not use (`eval`, `os.environ`, sockets, HTTP clients, new routes) is rejected. Then it goes through the same gates as rule patches. `--test` runs your tests against the candidate in a temporary copy of the project, so the real file changes only after every gate passes (and never with `--dry-run`). Your tests do execute the candidate: run AI + `--test` in CI or a container.
- **Shield** (`aegis/shield`): normalizes input (repeated URL decoding, HTML entities, SQL comment padding), scores 10 attack classes (SQLi, XSS, path traversal, command, template and code injection, SSRF, header injection, XXE, format strings) as independent evidence, uses a relaxed threshold for password fields, auto-bans repeat offenders, alerts without blocking the request thread, and logs incidents as JSON Lines. It inspects query, path, headers, cookies, form, JSON and every text field of multipart forms (streamed, so a large upload placed first cannot hide a field). A body it cannot parse is inspected as raw text, never skipped. On an internal error it fails open by default (`fail_open=False` to refuse instead).
- **Healer** (`aegis/healer.py`): maps the blocked request to its route (Flask `<int:id>`, FastAPI `{id}`, blueprints and routers mounted under a prefix when exactly one route fits). It never guesses: an ambiguous request stays blocked and goes to a human. It selects only the rules that match the attack class, patches, verifies, replays when configured, and applies or proposes. A finding it could not fix is not re-analysed on every request (10-minute cooldown), so an attack flood cannot multiply Claude calls.

## Rules

| ID | Vulnerability | CWE | Automatic fix |
| --- | --- | --- | --- |
| AEG001 | SQL injection | CWE-89 | parameterized query (`?` or `%s` chosen by driver) |
| AEG002 | OS command injection | CWE-78 | argument list without a shell |
| AEG003 | Code injection (`eval`/`exec`) | CWE-95 | `ast.literal_eval` (user input only) |
| AEG004 | Insecure deserialization | CWE-502 | `yaml.safe_load`; pickle → Claude / human |
| AEG005 | Path traversal | CWE-22 | `os.path.basename` on the user part |
| AEG006 | Hardcoded secret | CWE-798 | read from environment (+ rotate) |
| AEG007 | Debug mode | CWE-489 | `debug=False` |
| AEG008 | Reflected XSS | CWE-79 | `html.escape` on user values only |
| AEG009 | Server-side template injection | CWE-1336 | pass data as Jinja variables |
| AEG010 | Weak hash | CWE-328 | Claude / human (needs a migration) |
| AEG011 | SSRF | CWE-918 | Claude / human (needs an allow-list) |

## CI/CD

- **GitHub Action**: `uses: facei7505-droid/Aegis@v1.2.0`. Results appear in GitHub Code Scanning (SARIF 2.1.0), and verified patches go to the job summary.
- **pre-commit**: hook id `aegis`.
- **Exit codes**: `aegis scan --fail-on high` returns 1 when something at that level is found.
- **Baseline** for legacy code: `aegis baseline` once, after that CI fails only on *new* problems.
- **Suppress** a reviewed line: `# aegis: ignore[AEG006]`.
- **Outputs**: `--format text | json | sarif | markdown | html` (the HTML report comes in English or Russian with `--lang ru`).

```toml
# pyproject.toml
[tool.aegis]
exclude = ["migrations/*"]
disable = ["AEG010"]
fail_on = "high"
baseline = ".aegis-baseline.json"
language = "ru"
```

## Independent review

A separate reviewer agent tried to break Aegis: 18 confirmed findings, from a shield bypass to AI guardrail gaps. All 18 are fixed, each with a regression test: see [REVIEW.md](REVIEW.md). What is still open is listed right below.

## Limitations (read before you trust it)

- **Python only** for code analysis. The shield protects any WSGI/ASGI app.
- **Taint follows request data into project functions** the handler calls (same file, `import mod`, `from mod import f`), up to four levels deep. Methods, dynamic dispatch and data passed through objects or globals are not followed. Stored XSS (attacker data saved to the DB and rendered later) is not tracked. Django and FastAPI coverage is narrower than Flask (`HttpResponse`, `HTMLResponse` and `FileResponse` are covered; class-based views and DRF are not yet).
- **Argument injection.** An argument list stops shell injection, but a value starting with `-` can still be read as an option by the program (`curl`, `tar`). Aegis does not add `--` for you.
- **Path fixes use `os.path.basename`.** Safe, but it also drops legitimate sub-folders in the user's part. Containment checks with `realpath` are on the roadmap.
- **The shield is signatures plus an optional learned profile.** It is not a replacement for a mature WAF against a determined attacker (see BENCHMARKS.md and REAL_WORLD.md, including the held-out misses). Signatures are the first layer; fixing the code is the point.
- **Bodies above the inspection limit (1 MB).** Form-like and untyped bodies above it are refused; binary media (`image/*`, archives, `octet-stream`) pass so uploads keep working. Set `binary_uploads = false` for apps that parse every body as a form.
- **Parameter pollution** is covered for repeated names (joined with `,` and concatenated). A payload split across *different* parameter names that the app glues together is not reassembled.
- **Self-healing on a live server** patches the source file. Your process still needs a reload, or a deploy for `propose` mode, before the fix is live. Until then the shield keeps blocking.
- The range runs third-party apps (DSVW, vulpy) and real tools (sqlmap, commix), but on one machine with one attacker. The next milestone is pilots on real, maintained codebases.
- **Aegis Edge** needs the site connector (or a firewall rule) to stop traffic that goes to the site's server directly. WebSocket is not proxied (answered 501). WordPress and 1C-Bitrix are measured on real installations in a lab, with scripted sessions; OpenCart is built from documentation and attack write-ups. None has met production traffic yet, which is what the learning week and a pilot are for. Failover needs a second machine and DNS in your zone (CNAME); a root domain without ALIAS support at the registrar has no automatic failover. The watchdog's Cloudflare provider is tested against a local fake of the API, not Cloudflare itself. The response guard reads answers up to 512 KB in full (larger or streamed ones only on the way through, so they cannot be stopped, only learned from).

## Roadmap

Done since v1.0: cross-module taint, canary on recorded traffic before a patch goes live, live dashboard,
learned traffic profile, real-data evaluation (CSIC 2010, SecLists, sqlmap, commix), two outside reviews.

- Stored-XSS tracking and taint through methods and objects
- JavaScript/TypeScript (Express, Next.js) support
- The OWASP Benchmark for the scanner

## Development

```bash
pip install -e ".[dev]"
pytest -q                     # 310+ tests, incl. property tests on 300 SQL queries and 200 shell commands
python benchmarks/run.py      # regenerates BENCHMARKS.md
aegis scan .                  # Aegis scans itself in CI
```

## Responsible use

Aegis is a defensive tool. `VulnShop` (`aegis/demo_app`) is vulnerable on purpose and must never be deployed. Only test systems you own or have written permission to test.

## Author

**Magzhan Koilybai** · Shymkent, Kazakhstan · Telegram [@makakke4](https://t.me/makakke4)

Built with AI pair-programming (Claude by Anthropic). Design decisions, testing and the product direction are documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

MIT License.
