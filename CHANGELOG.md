# Changelog

Each section is the release notes for its tag. The major tag (`v1`) used by the GitHub Action points
at the latest `v1.x.y`.

## v1.4.0

Aegis Edge closes the ways around it, reads the site's answers, and is measured on a real 1C-Bitrix shop.

- **Origin lock and site connectors.** Aegis signs every request it forwards (HMAC per site).
  `aegis edge connector` writes a PHP connector: WordPress mu-plugin, Bitrix (dbconn.php + init.php), or
  a generic file for any PHP site. The site then refuses requests that did not come through Aegis, sees
  the visitor's real IP, and gives editors a signed pass, so a forged "signed in" cookie relaxes nothing.
  `--verify` checks it from Aegis' side. Firewall rules for VPS clients are printed too.
- **Response guard.** Aegis reads the start of every text answer (gzip and deflate too). A database
  error after a request with SQL syntax is a confirmed injection point: the answer is replaced and that
  field on that page is closed (digits only, or no quotes), kept across restarts, with a Russian alert on
  what to fix. Leaked system files and web-shell output are replaced and the address banned at once.
  PHP warnings are reported, never blocked.
- **libinjection** (BSD-3, vendored C, `aegis build-engine`) as a second SQLi/XSS opinion, and **OWASP
  CRS phrase lists** (Apache-2.0) for system files, restricted files and shell programs, used only where
  a value is a file path. CSIC 2010: still 0 of 72,000 normal requests flagged; held-out LFI lists
  81% -> 92% and 94% -> 98%; quick-SQLi 70% -> 94%; XSS-RSNAKE 72% -> 91%.
- **Shared immunity.** An address banned on one site is banned on every site of the server for the same
  time; learning sites do not contribute; a client's /unban pardons only their site.
- **Siege mode.** A proof-of-work gate (the idea of Anubis): visitors pass in about a second, bots
  without a browser never; payment callbacks, 1C exchange and cron are exempt. Telegram `/siege`, or
  automatic above 1,800 requests a minute. 0.3 s median in real Chrome on the lab machine.
- **Site guard.** Every 5 minutes: is the site up, did a script from a new outside domain appear (card
  skimmers), an obfuscated loader, SEO spam, a defacement. First look and learning only record.
- **Failover.** `aegis edge watchdog` on a second machine: if Aegis stops answering, it opens the
  connectors with a signed token and points the sites' CNAME targets at their own servers (Cloudflare API
  or any command), then back when Aegis returns. `aegis edge failover-export` writes its config.
- **Real 1C-Bitrix lab** (26.150 Enterprise for PostgreSQL, online-shop solution, installed by its own
  wizard in Chrome): shoppers and staff, block mode, preset and connector: 17/17 steps, 0 requests
  refused, including the checkout, the SQL console and the PHP command line. Known Bitrix attacks all
  refused; forged admin post 403; straight to the shop's server 403.
- **WordPress lab re-run with the connector:** 21/21 steps, 0 refused; forged editor post refused by
  Aegis (403) instead of WordPress (401); SecLists LFI 84% -> 89%, SQLi 67% -> 71%.
- **Fixes:** the gateway and test servers no longer do a reverse DNS lookup when binding (stalled CI on
  macOS); visitors never see X-Aegis-* headers.

## v1.3.0

Aegis Edge: a protection service for client websites, measured on a real WordPress.

- **Aegis Edge.** One server protects many sites: the client changes DNS, Caddy issues HTTPS
  certificates on demand (only for domains Aegis knows), Aegis applies the site's CMS preset and
  forwards to the client's real server, keeping the public Host and using the site name for TLS.
  New sites start with a 7-day learning period. `aegis edge add/list/pause/resume/remove/origin-test/
  serve/report/caddyfile`; changes apply without a restart.
- **CMS presets** (WordPress, 1C-Bitrix, OpenCart, generic): fields where a signed-in editor writes
  markup; virtual patches (CVE-2022-27228 and html_editor_action.php on Bitrix, PHP in upload folders,
  xmlrpc multicall, user enumeration, backups, known backdoors); login flood cut per address with 429
  while the rest of the site stays open; per-address page rate limit.
- **Telegram bot** in Russian: alerts to the owner and the client (repeats folded), /status /report
  /pause /resume /unban; strangers only learn their chat id.
- **Monthly PDF report** for the client with advice chosen from what happened on that site; per-day
  stats; 90-day retention; payloads masked (passwords, tokens, cards, e-mails, Kazakhstani phones).
- **`aegis check`**: passive site check in Russian with a one-page PDF for prospective clients.
- **Signatures**: quote tautologies, IN-lists, `\xNN` and hex/UTF-16 literals, SQL function chains,
  EXEC(@var), Windows and Unix system paths. CSIC 2010: still 0 of 72,000 normal requests flagged;
  held-out LFI lists 70% -> 81% and 91% -> 94%.
- **Measured on a real WordPress** (Chrome, block mode): 0 wrongful blocks in 2,247 requests of owner
  and visitor work; +2.5 ms per page; ~750 requests/s on 2 vCPU.
- **Fixes**: an outside review (REVIEW.md round 4) found a skip-path tunnel, forgeable WordPress
  patch exemptions, spoofable X-Forwarded-For, dropped chunked bodies and no client timeout: all fixed
  and re-tested on the WordPress lab. Also: the gateway announced `Server: WSGIServer/0.2 CPython/3.x`; a reload could answer
  "unknown host" for a changed site for a moment.
- **Selling it**: deploy kit (Docker, Caddy, systemd), Russian runbook, sales kit, client landing page.

## v1.2.0

Second outside review closed, real traffic before every patch, and a learned model of normal traffic.

- **Canary.** Before an `auto` heal goes live, the patched app runs as a copy on a free port and
  recorded real requests are replayed against it and the live app. A patch that turns a 200 into an
  error, or changes a page beyond recognition, is held as a proposal.
- **Learned traffic profile** (positive security model). Per endpoint: parameters, characters,
  lengths, numeric fields. On CSIC 2010 it raises caught anomalies from 30% to 72% (84% with strict
  paths) at 2 false alarms in 36,000 normal requests. Off by default; `range --learn N` or
  `learn = N` in the gateway config.
- **Cross-module taint.** Request data is followed into helpers in other files; found a real path
  traversal in vulpy's `libapi.keygen`.
- **Spending guard for Claude.** A per-run budget (default $0.25, `--ai-budget`), a total cap across
  runs (`AEGIS_AI_TOTAL_BUDGET`), worst-case check before each request, real cost recorded after.
- **Gateway dashboard** answers only on this machine or with `--dashboard-token`.
- **Shield, from the second review:** repeated parameters are reassembled (HPP bypass closed); every
  signature bounded and long values scored in windows (60 KB worst case 15 s → 81 ms, timed in CI);
  oversized untyped bodies refused, one policy for WSGI and ASGI.
- **Portability:** CI green on Linux, macOS and Windows with Python 3.10 to 3.13; `[tool.aegis]` in
  `pyproject.toml` is read on 3.10 too (via `tomli`).

Signatures alone still raise 0 false alarms on 72,000 real requests (CSIC 2010 normal traffic and
SecLists). Details: README, REAL_WORLD.md, REVIEW.md.

## v1.1.0

First public release.

- Scanner: AST taint analysis, 11 rules (SQL injection, command injection, path traversal, SSRF,
  XSS, SSTI, unsafe deserialization and more), SARIF, HTML, JSON and text reports.
- Patcher: deterministic fixes behind verification gates (parse, re-scan, tests); Claude fixes and
  triage behind the same gates.
- Shield: WSGI/ASGI runtime protection with normalisation and streamed multipart inspection.
- Healer: an attack the shield blocks leads to the vulnerable line, a verified patch and a report.
- Aegis Gateway and Range: one server in front of several real apps, attacked by sqlmap and commix.
- GitHub Action, pre-commit hook, benchmarks with held-out sets.
