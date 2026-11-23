# Independent review log

Aegis is a security tool, so it was reviewed the way it reviews others. A separate agent, with no access to the build conversation, got the repository and one instruction: find bugs, bypasses and claims the code does not support. It wrote re-runnable proof-of-concept scripts for each finding. Every confirmed finding below was fixed and now has a regression test.

| # | Finding | Severity | Fix | Regression test |
| --- | --- | --- | --- | --- |
| 1 | A deeply nested JSON body crashed the parser and the shield failed open, letting a SQL injection in the query string through | critical | Bodies that fail to parse are inspected as raw text; JSON is flattened iteratively; `fail_open=False` option | `test_unparseable_body_never_switches_inspection_off` |
| 2a | Multipart field declared as UTF-16: the shield and Flask decoded it differently | critical | Fields decoded as UTF-8 like Werkzeug, plus the declared charset | `test_multipart_charset_trick_and_big_file_before_field` |
| 2b | A file over 1 MB placed before a text field hid that field | critical | Multipart bodies are spooled and streamed field by field up to `max_upload` | same |
| 3 | Classic payloads under the threshold (`x' OR TRUE--`, `&& printf`, `;/usr/bin/id`, decimal-IP SSRF, …) | critical | New signatures; held-out set added to the benchmark | `test_bypasses_found_in_review_are_detected` |
| 4 | SQL variable reassigned: the fixer edited one query and broke the other | high | Fixers require a single binding (`resolve(strict=True)`) | `test_sql_variable_reassigned_is_left_to_a_human` |
| 5 | SQL placeholder guessed as `?` for unknown drivers; `con=` dropped for pandas; `executescript`; swapped `{1} {0}` holes | high | Known-driver rule (Django included), keywords kept, no-params calls refused, numbered holes mapped | `test_sql_*` (5 tests) |
| 6 | `open(UP / name)` became `basename(UP / name)`, dropping the base folder | high | Only the attacker-controlled operand is wrapped | `test_path_fix_keeps_the_base_folder` |
| 7 | `shlex.split(cmd)` let a value add arguments; `PORT = 8080` passed raw; globs stopped expanding | high | Argument list built at the assignment; constants wrapped in `str()`; globs refused | `test_command_in_variable_becomes_an_argument_list`, property test |
| 8 | `f"{amount:.2f}"` escaped before formatting; SSTI kwarg `source=` clashed; trusted HTML got escaped | high | Format, then escape; reserved names; trusted values rendered with `|safe` | `test_xss_fix_formats_before_escaping`, `test_ssti_fix_avoids_parameter_names_and_keeps_trusted_html` |
| 9 | An AI reply with an extra module-level route and `from builtins import repr as int` passed every gate; `--test` ran the candidate in the real file | high | One-function rule, import allow-list, capability check; tests run in a temporary copy | `test_ai_guardrails_reject_extra_power`, `test_test_gate_runs_on_a_copy` |
| 10 | Blueprint under `/api`: the healer patched the wrong handler by guessing from the parameter name | high | No guessing; prefix matching only when exactly one route fits | `test_blueprint_prefix_maps_to_the_right_handler`, `test_ambiguous_request_is_never_guessed` |
| 11 | `exploit_replay: True` recorded when no replay ran | high | Recorded only when a replay ran; docs corrected | `test_replay_check_only_recorded_when_a_replay_ran` |
| 12 | Healer thread died on its first error; every blocked request re-ran the fixer (3 Claude calls each) | high | Worker survives errors; bounded queue; 10-minute cooldown | `test_worker_survives_errors`, `test_unfixable_incident_is_not_reanalysed_per_request` |
| 13 | `aegis demo --workdir DIR` deleted an existing folder | high | Refuses folders it did not create | `test_demo_refuses_to_delete_a_foreign_folder` |
| 14 | Scanner misses: `q += f"..."`, SQLAlchemy `text()`, aliased imports, `yaml.unsafe_load`, `return body, 200`, Django/FastAPI responses, annotated secrets; FPs on `st.text()` and `md5(usedforsecurity=False)` | medium | Import-alias resolution, new sinks, tainted-variable rule | `test_review_false_negatives_are_found`, `test_review_false_positives_are_quiet` |
| 15 | Shield false positives (`Order (2 items) #4521`, `Name \| ID \| Email`, `Hi {{first_name}}`, …) | medium | Case-sensitive word commands, stricter comment and template rules | `test_false_positives_found_in_review_pass` |
| 16 | `skip_paths` prefix also skipped `/healthcare`; left-most `X-Forwarded-For` trusted; unbounded memory | medium | Segment matching; `proxy_hops` from the right; caps on incidents, strikes, records | `test_skip_paths_*`, `test_forwarded_for_*`, `test_incident_memory_is_bounded` |
| 17 | `str.splitlines` broke on form feed / U+2028, shifting every position after it | medium | Lines split as Python's tokenizer does | `test_form_feed_and_line_separator_do_not_shift_positions` |
| 18 | Test-gate timeout aborted the whole run | medium | Timeout is a failed gate | covered by `run_tests_on_copy` |

Also fixed: non-numeric `Retry-After` and non-JSON API responses now raise `AIError` instead of crashing.

**Not fixed, documented as limitations:** argument injection through values starting with `-`; `basename` dropping legitimate sub-folders; Django URLconf mapping; two held-out shield misses. See README → Limitations.

## Round 2: real data, real apps, real tools (v1.1.0)

Running Aegis against third-party data and tools found more problems than any test written by us. Each is fixed and has a regression test.

| Found by | Problem | Fix |
| --- | --- | --- |
| sqlmap `--level 3` | `Referer: http://127.0.0.1/...` scored as SSRF, so normal navigation on a local app was blocked | Referer/Origin excluded from the SSRF class (`test_local_referer_is_not_ssrf`) |
| CSIC 2010, SecLists | CRLF header injection, XXE, format strings, absolute system paths, backup-file probes, `xp_cmdshell`/`load_file`, JS-context XSS were not detected | New signals and classes, checked against 36,000 normal training requests (0 false alarms); the 36,000 test requests were never looked at |
| SecLists | Fullwidth/`%u` encodings and `/* */` around an XSS payload hid it | NFKC + IIS `%u` decoding; payload scored with and without comments and null bytes |
| DSVW | `http.server` handlers had no route table, so incidents could not be traced | `do_GET`/`do_POST` of a `BaseHTTPRequestHandler` is the handler; `self.path`, `self.headers` are taint sources |
| vulpy | Blueprint prefix set in `register_blueprint(url_prefix=...)` in another file; sink in a helper module | Prefixes resolved across files; the healer follows the handler's direct calls into project modules |

## Round 3: a second independent reviewer (v1.2.0)

A fresh reviewer, who had not seen the code being written, attacked v1.1 through the gateway with the
range running. Every finding was reproduced before it was fixed; the fixes were then re-measured on CSIC
2010 and SecLists: detection numbers and false alarms (0 of 72,000) came out identical to v1.1.

| # | Problem | Severity | Fix | Regression test |
| --- | --- | --- | --- | --- |
| 1 | Parameter pollution: `?id=5/*&id=*/UNION/*&id=*/SELECT...` passed, because each value was scored alone and DSVW joins repeats with `,`. Verified end to end against DSVW in block mode | high | Repeated query/form names are also scored joined with `,` and concatenated; password-like fields excluded | `test_comment_split_repeated_parameter_is_reassembled`, `test_repeated_benign_parameters_stay_clean`, `test_relaxed_fields_are_not_reassembled` |
| 2 | Regex blow-up: 50,000 `{{`, newlines or `'on` made three signatures take 7–30 s per request; one client could stall the shield | high | Every unbounded span in the signatures bounded; values over 8 KB scored in overlapping windows (nothing is skipped). Worst case for a 60 KB value went from 15 s to 81 ms | `test_long_adversarial_values_are_scored_quickly`, `test_payload_past_the_first_window_is_found` |
| 3 | Dashboard reachable without a token | medium | Already fixed in v1.1 (loopback only, or `--dashboard-token`); the reviewer had an older copy | `test_dashboard_*` |
| 4 | A 1 MB body with no `Content-Type` was neither inspected past the limit nor refused; the ASGI shield did not inspect bodies of unlisted types at all | low | No type and unknown types now count as form-like; only binary media (`image/*`, archives, `octet-stream`) may exceed the limit, and `binary_uploads = false` closes that too. WSGI and ASGI share one policy | `test_oversized_body_policy` |

**Method note.** Every signature is now timed against 39 adversarial repeats in the test suite
(`test_every_signature_is_linear_on_adversarial_repeats`): a new signature with an unbounded `.*` or `\s*`
after a separator is how this class of bug comes back, and CI now catches it.

## Round 4: outside review of Aegis Edge (v1.3.0)

A fresh reviewer attacked the new managed-protection service with a harness of its own (real `Edge`,
echo origin). Every finding was reproduced, fixed with a regression test, and then re-tested on the
real WordPress lab in block mode: the owner session still passed 21 of 21 steps with 0 of 2,249
requests blocked, and every bypass below now gets 403 (or 429) from the live site.

| # | Problem | Severity | Fix | Regression test |
| --- | --- | --- | --- | --- |
| 1 | `/health/../anything` skipped inspection: the skip list was matched on the raw path, and the origin collapses `..` | critical | Skips, routes and virtual patches use the path the server will run (`normalize_path`: decoding, `..`, `//`, `;params`, trailing dots); a path with `..` or `%` is never skipped | `test_skip_paths_cannot_be_used_as_a_tunnel`, `test_patches_see_the_path_the_server_runs` |
| 2 | A forged `wordpress_logged_in_` cookie switched off the user-enumeration and wp-includes patches | high | Those patches are unconditional; the editor's own author list passes because it uses `who=authors`, which WordPress refuses to anyone not signed in (checked live: 401 `rest_forbidden_who`) | `test_wordpress_virtual_patches` |
| 3 | X-Forwarded-For was honoured from any peer when `trust_proxy` is on | medium | Honoured only when the connection comes from `trusted_proxies` (loopback and private networks by default: Caddy on the host or in Docker), and only if the hop is an IP | `test_forwarded_for_is_only_trusted_from_our_proxies` |
| 4 | Chunked request bodies were neither inspected nor forwarded (wsgiref does not de-chunk) | medium | The server de-chunks (up to 100 MB, 400 on a malformed body) before the shield and the proxy see the request | `test_chunked_request_body_is_inspected_and_forwarded` |
| 5 | Markup trust relies on a client-supplied marker | low | Accepted by design and documented: it only relaxes XSS on editor fields of admin endpoints, which the CMS refuses without a real login (live: forged-cookie post gets 401 from WordPress) | `test_trust_is_per_field_and_per_class` |
| 6 | No client socket timeout (slowloris) | low | 30 s per read, at most 1,024 open connections, and Caddy header/body timeouts in the shipped Caddyfile | `test_silent_clients_are_dropped` |

Found while fixing #1 (not in the report): `/index.php?rest_route=/wp/v2/users` and `/wp/v2/users/1`
also enumerated users, and `/wp-login.php/x.css` was counted as a static file by the rate limit.
All three are closed and tested. The reviewer also checked Telegram authorization, the control
endpoints, cross-site routing, report escaping, stats paths and payload masking, and found no issue.
