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
