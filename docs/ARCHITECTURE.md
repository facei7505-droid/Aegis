# Aegis architecture and design decisions

This document explains *why* Aegis is built the way it is. The README explains *what* it does.

## 1. The problem

Small and medium businesses run web apps written fast, often by one developer, with no security team. They get three kinds of tools:

- **Scanners** produce long reports. Somebody still has to understand and fix every item.
- **Firewalls** block known attack strings, but the vulnerable code stays. One bypass and the hole is open again.
- **AI assistants** can write a fix, but nobody verifies it, so a wrong fix can break the app or leave the hole.

Aegis connects detection, blocking and repair into one loop, and refuses to trust any fix, its own or the AI's, until the fix is verified.

## 2. Components

```
aegis/
  scanner/      ast + taint tracking -> Finding
    project.py    cross-module taint: request data followed from handlers into helpers, up to 4 levels
    taint.py      what is attacker-controlled, what sanitizes it
    rules.py      11 detection rules (detect only, never fix)
    engine.py     runs rules with context, suppression, excludes
  patcher/
    fixes.py      deterministic fixers: AST span -> safe code
    engine.py     plan -> apply -> verify loop, escalation
  ai/
    client.py     dependency-free Anthropic Messages API client (retries, backoff)
    fixer.py      Claude proposes a function rewrite; guardrails + verifier decide
    triage.py     Claude confirms findings and explains them in en/ru/kk
    prompts.py    all prompts in one reviewable file
  shield/
    detectors.py  normalization + weighted signatures for 10 attack classes
    profile.py    learned traffic profile: per-endpoint parameters, characters, lengths (positive model)
    core.py       framework-independent inspection, bans, incident log, callbacks
    middleware.py WSGI and ASGI adapters
    alerts.py     Telegram / webhook, throttled, off the request thread
  healer.py     incident -> route -> root cause -> patch -> verify -> replay -> apply/propose
  gateway.py    reverse proxy: one server, a shield per app, a healer per Python app, live dashboard
  range.py      local lab: VulnShop + DSVW + vulpy (pinned commits) behind one gateway, restart after heal
  integrations.py  protect(app) one-liners
  report_html.py   client-ready report (en/ru), output.py: text/json/sarif/markdown
  demo.py       end-to-end proof on VulnShop
```

## 3. Key decisions

### Rules first, AI second
Deterministic fixers are instant, free, explainable, and give the same output every time. A parameterized SQL query has one correct form, so there is no reason to ask a language model for it. Claude is used where rules would have to guess: pickle replacement, password hashing, SSRF allow-lists, unusual code shapes. In the demo, 10 of 13 findings are fixed by rules. Claude handles the rest or explains why a human is needed.

### Verification is the product
Any patch, from rules or from Claude, must pass the same gates:

| Gate | What it catches |
| --- | --- |
| syntax | broken code |
| fixed | a "fix" that did not remove the vulnerability (re-scan of the function) |
| no new | a fix that moved the problem or created a new one (re-scan of the whole file, per rule and function) |
| tests | behaviour regressions (the project's own test command) |
| replay | the real attack still succeeds against the patched code (only when a replay function is configured; the check is not recorded otherwise) |

If a gate fails, the AI gets the exact reason back and tries again (3 attempts by default). After that the finding is escalated with the reason. Nothing that failed a gate is written to disk.

The first three gates are static: a re-scan by the same scanner. They catch a fix that did not remove the pattern, not a fix that breaks behaviour. Behaviour is covered by the `tests` gate, by the generated property tests of the fixers (below), and by `propose` mode. An independent review found five ways a patch could pass the static gates and still break an app (a re-assigned query variable, an unknown driver's placeholder, a dropped `con=` keyword, a lost base folder, a format spec escaped before formatting). Each is now refused or handled, and has a regression test.

### Fixes that change behaviour need proof of attacker control
Replacing `eval` with `ast.literal_eval`, or a shell string with an argument list, changes what the code does. For an internal command (`EDITOR="code --wait"`, a Windows `.cmd` shim) that change can break things. So these fixers run **only when taint analysis proves the value comes from the request**. Running the patch engine over 3,000 files of popular open-source libraries produced **zero** automatic edits, which is exactly what should happen to library code.

### SQL placeholders only where values go
Bind parameters can replace values, not identifiers. `f"SELECT {cols} FROM {table}"` is refused, because `?` there would break the query. A bare `IN ({ids})` is refused too: one placeholder would turn `"1,2,3"` into a single value. These cases are escalated with the reason, since they need an allow-list.

A value inside a quoted SQL literal becomes one parameter holding the whole literal: `LIKE '%{q}%'` turns into `LIKE ?` with `f"%{q}%"`, and `'it''s {x}'` keeps its escaped quote. Quoted identifiers (`"{table}"`) and unclosed literals are refused.

### The program a command runs is never chosen by input
Dropping the shell stops `;`, `&&` and `$( )`, but if the request picks the program itself (`subprocess.run(request.args["cmd"], shell=True)`), an argument list still runs whatever the attacker names. Aegis refuses to call that fixed and hands it to a human. Pipes, redirects, `$VAR` expansions and values glued together (`{a}{b}`) are refused for the same reason: an argument list would change what the command means.

### Property tests, not only examples
Two generated test suites check the fixers against a real database and a real shell: 300 SQL queries in five code styles (f-string, `.format`, `%`, concatenation, variable) and 200 shell commands. For every rewrite, ordinary input must return exactly the same rows or output as before, and injection payloads must stop working. Every case the fixer cannot rewrite safely (identifiers, `ORDER BY {col}`, input-chosen programs, pipes) must be left untouched.

### Propose by default in production
Rewriting files on a live server is a deployment decision. `heal="propose"` writes a verified `.diff` per incident for a human to merge. `heal="auto"` exists for staging, demos and teams that choose it. Either way the shield keeps blocking the attack until the fix ships.

### Zero runtime dependencies
The core uses only the standard library (`ast`, `urllib`, `json`, `difflib`). That means nothing new to audit in the supply chain, it installs anywhere, and it fits a security tool that will itself be scrutinized.

## 4. Threat model of Aegis itself

| Risk | Mitigation |
| --- | --- |
| Prompt injection through code comments sent to Claude | Claude only returns a candidate. Guardrails decide before the verifier: only the one function (no module-level code), the same signature and decorators, allow-listed imports that cannot shadow builtins, and no capability the original did not use (`eval`, `os.environ`, sockets, HTTP clients, new routes). In `propose` mode a human reviews every diff. |
| A malicious but "passing" AI patch (e.g. adds a backdoor that the rules cannot see) | AI scope is limited to one function, `no new` re-scans the whole file, and production default is human review (`propose`). This risk is not zero. That is why `auto` + AI is opt-in. |
| Executing untrusted code during verification | Without `--test`, candidates are only compiled. With `--test`, the user's tests run the candidate in a temporary copy of the project, so the real file is untouched until every gate passes. Run that in CI or a container. |
| Shield bypass through a malformed body | Bodies that fail to parse are inspected as raw text; JSON is flattened iteratively (no recursion limit); multipart forms are streamed field by field. |
| Spoofed `X-Forwarded-For` | Only honoured with `trust_proxy=True`, and the client is taken `proxy_hops` entries from the right, the entry your own proxy added. |
| Attack floods driving cost | Healing is queued (bounded), deduplicated, and a finding that needs a human is not re-analysed for 10 minutes. Incidents in memory are capped. |
| Leaking the API key | Read from `ANTHROPIC_API_KEY`, never logged, never written to reports. |
| Report XSS from attacker payloads | Every value in HTML reports is escaped (covered by a test). |
| Shield slowing requests | Inspection takes about 10 µs per value. Alerts and healing run on background threads. |

## 5. Known limitations

- Taint crosses function and module boundaries for plain function calls only (not methods, callbacks or objects). Python only, no stored-XSS tracking.
- Signature-based shield. Small corpora so far.
- Route mapping covers Flask and FastAPI decorators, and prefixed blueprints/routers when only one route fits. Django URLconfs are not mapped yet: those incidents stay blocked and go to a human.
- Argument injection (values starting with `-`) is not handled by the command fixer.
- After an `auto` heal the process must reload to run the new code.

## 6. Next steps

1. Pilots with 3–5 real small-business codebases in Kazakhstan (with written permission).
2. Inter-procedural taint, then JavaScript/TypeScript.
3. Independent benchmark (OWASP Benchmark for the scanner, public payload sets for the shield).
4. Hot reload with canary traffic after `auto` heals.
