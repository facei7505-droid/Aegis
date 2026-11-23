# Security policy

Aegis is a security tool, so its own security matters.

- Report vulnerabilities privately via Telegram @makakke4. Please do not open a public issue.
- `aegis/demo_app/vulnshop` is intentionally vulnerable. Reports about it are expected behaviour, not bugs.
- Without `--test`, code proposed by the AI engine is only parsed and compiled, never run.
- With `--test`, your test command runs against the candidate in a temporary copy of the project. Your tests import and execute the candidate, so use AI patches with `--test` in CI or a container. The real file is written only after every gate passes, and never with `--dry-run`.
- AI proposals are limited to the one function they were given, allow-listed imports that cannot shadow builtins, and no capabilities the original code did not already use.
- The shield fails open on its own internal errors by default, so a shield bug cannot take your site down. Set `fail_open=False` if you prefer to refuse such requests.
