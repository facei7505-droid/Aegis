# Changelog

Each section is the release notes for its tag. The major tag (`v1`) used by the GitHub Action points
at the latest `v1.x.y`.

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
