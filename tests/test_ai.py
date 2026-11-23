"""AI engine: Claude proposes, the verifier decides. Uses a scripted fake model (no network)."""
import io
import json
import textwrap
import urllib.error

import pytest

from aegis.ai import AIFixer, ClaudeClient, parse_json_reply, triage
from aegis.ai.client import AIError
from aegis.patcher import fix_file
from aegis.scanner import scan_source

PICKLE_APP = textwrap.dedent("""
    import base64
    import pickle

    from flask import Flask, request

    app = Flask(__name__)


    @app.route("/cart")
    def cart():
        raw = request.cookies.get("cart")
        items = pickle.loads(base64.b64decode(raw)) if raw else []
        return f"{len(items)} items"
""")

GOOD_FIX = textwrap.dedent("""
    @app.route("/cart")
    def cart():
        raw = request.cookies.get("cart")
        try:
            items = json.loads(base64.b64decode(raw)) if raw else []
        except (ValueError, TypeError):
            items = []
        return f"{len(items)} items"
""")


class ScriptedModel:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.prompts = []

    def complete(self, system, prompt, max_tokens=4096):
        self.prompts.append(prompt)
        return self.replies.pop(0)


def _reply(code=None, imports=(), explanation="fixed", needs_human=False):
    return json.dumps({"needs_human": needs_human, "patched_code": code, "imports": list(imports),
                       "explanation": explanation})


def test_ai_patch_is_verified_and_applied(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(PICKLE_APP)
    model = ScriptedModel("```json\n" + _reply(GOOD_FIX, ["import json"], "Use JSON instead of pickle.") + "\n```")
    report = fix_file(str(path), ai_fixer=AIFixer(model))
    out = path.read_text(encoding="utf-8")
    assert report.patches and report.patches[0].engine == "ai" and report.patches[0].verified
    assert "pickle.loads" not in out and "json.loads" in out and "import json" in out
    assert not [f for f in scan_source(str(path)) if f.rule_id == "AEG004"]


def test_ai_gets_feedback_and_retries(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(PICKLE_APP)
    bad_signature = GOOD_FIX.replace("def cart():", "def cart(user):")
    still_vulnerable = PICKLE_APP[PICKLE_APP.index("@app.route"):]
    model = ScriptedModel(_reply(bad_signature), _reply(still_vulnerable), _reply(GOOD_FIX, ["import json"]))
    report = fix_file(str(path), ai_fixer=AIFixer(model, max_attempts=3))
    assert report.patches and report.patches[0].attempts == 3
    assert "signature" in model.prompts[1]          # guardrail feedback was sent back
    assert "still detected" in model.prompts[2]     # verifier feedback was sent back


def test_ai_cannot_sneak_in_unverified_code(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(PICKLE_APP)
    broken = GOOD_FIX.replace("return f", "return (")
    model = ScriptedModel(_reply(broken), _reply(broken), _reply(broken))
    report = fix_file(str(path), ai_fixer=AIFixer(model, max_attempts=3))
    assert not report.patches and path.read_text(encoding="utf-8") == PICKLE_APP
    assert "not valid Python" in report.escalated[0].reason or "verification" in report.escalated[0].reason


def test_ai_can_ask_for_a_human(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(PICKLE_APP)
    model = ScriptedModel(_reply(needs_human=True, explanation="Existing carts are pickled; needs a data migration."))
    report = fix_file(str(path), ai_fixer=AIFixer(model))
    assert not report.patches and "data migration" in report.escalated[0].reason


def test_rules_run_before_ai(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("API_KEY = 'sk_live_abcdef123456'\n")
    model = ScriptedModel()   # would raise if called
    report = fix_file(str(path), ai_fixer=AIFixer(model))
    assert report.patches[0].engine == "rules" and not model.prompts


def test_triage_annotates_findings(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(PICKLE_APP)
    findings = scan_source(str(path))
    model = ScriptedModel(json.dumps([{"id": 0, "verdict": "confirmed", "explanation": "Атакующий может выполнить код."}]))
    triage(findings, model, "ru")
    assert findings[0].ai_verdict == "confirmed" and "выполнить" in findings[0].ai_explanation


def test_parse_json_reply_tolerates_noise():
    assert parse_json_reply('Sure! Here it is:\n```json\n{"a": "x}y", "b": [1, 2]}\n```') == {"a": "x}y", "b": [1, 2]}
    assert parse_json_reply('[{"id": 0}]') == [{"id": 0}]
    with pytest.raises(AIError):
        parse_json_reply("no json here")


def test_client_requires_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client = ClaudeClient()
    assert not client.available
    with pytest.raises(AIError):
        client.complete("s", "p")


def test_client_request_shape_and_retry(monkeypatch):
    calls = []

    class Resp:
        def __init__(self, data):
            self.data = data

        def read(self):
            return json.dumps(self.data).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout):
        calls.append(req)
        if len(calls) == 1:
            raise urllib.error.HTTPError(req.full_url, 529, "overloaded", {"retry-after": "0"}, io.BytesIO(b"{}"))
        return Resp({"content": [{"type": "text", "text": "hello"}], "usage": {"input_tokens": 3, "output_tokens": 1}})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr("time.sleep", lambda s: None)
    client = ClaudeClient(api_key="test-key", model="claude-test")
    assert client.complete("sys", "hi") == "hello"
    body = json.loads(calls[-1].data)
    assert body["model"] == "claude-test" and body["system"] == "sys"
    assert body["messages"] == [{"role": "user", "content": "hi"}]
    assert calls[-1].get_header("X-api-key") == "test-key"
    assert calls[-1].get_header("Anthropic-version") == "2023-06-01"
    assert client.usage == {"input_tokens": 3, "output_tokens": 1, "requests": 1}


def test_ai_must_keep_route_decorator(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(PICKLE_APP)
    no_decorator = GOOD_FIX.replace('@app.route("/cart")\n', "")
    model = ScriptedModel(_reply(no_decorator, ["import json"]), _reply(GOOD_FIX, ["import json"]))
    report = fix_file(str(path), ai_fixer=AIFixer(model))
    assert report.patches and "decorators" in model.prompts[1]
    assert '@app.route("/cart")' in path.read_text(encoding="utf-8")


def test_ai_code_block_fallback(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(PICKLE_APP.replace("import pickle", "import json\nimport pickle"))
    model = ScriptedModel("Here is the fix:\n```python\n" + GOOD_FIX.strip() + "\n```")
    report = fix_file(str(path), ai_fixer=AIFixer(model))
    assert report.patches and report.patches[0].engine == "ai"


@pytest.mark.parametrize("code,imports,why", [
    (GOOD_FIX + '\napp.add_url_rule("/__env", "env", lambda: str(dict(os.environ)))\n', ["import json"], "capabilities"),
    (GOOD_FIX + '\nDEBUG_TOKEN = "x"\n', ["import json"], "only the function"),
    (GOOD_FIX, ["import json", "from builtins import repr as int"], "shadow a Python builtin"),
    (GOOD_FIX, ["import json", "import ctypes"], "not needed for a security fix"),
    (GOOD_FIX.replace("return f", "__import__('os').system('id')\n    return f"), ["import json"], "capabilities"),
    (GOOD_FIX.replace("        items = json.loads", "        import socket\n        items = json.loads"), ["import json"], "not needed"),
])
def test_ai_guardrails_reject_extra_power(tmp_path, code, imports, why):
    """Found in review: module-level code and shadowing imports passed every gate."""
    path = tmp_path / "app.py"
    path.write_text(PICKLE_APP)
    model = ScriptedModel(*[_reply(code, imports)] * 3)
    ai = AIFixer(model, max_attempts=3)
    report = fix_file(str(path), ai_fixer=ai)
    assert path.read_text(encoding="utf-8") == PICKLE_APP and not report.patches
    assert why in report.escalated[0].reason


def test_test_gate_runs_on_a_copy(tmp_path):
    """The candidate is tested in a temporary copy; the real file changes only after every gate passes."""
    path = tmp_path / "app.py"
    path.write_text(PICKLE_APP)
    probe = tmp_path / "test_probe.py"
    probe.write_text("import pathlib\n\ndef test_probe():\n    assert 'json.loads' in pathlib.Path('app.py').read_text(encoding='utf-8')\n"
                     "    pathlib.Path(__file__).with_name('RAN_IN').write_text(str(pathlib.Path.cwd()))\n")
    model = ScriptedModel(_reply(GOOD_FIX, ["import json"]))
    import sys
    report = fix_file(str(path), ai_fixer=AIFixer(model), test_cmd=f"{sys.executable} -m pytest -q -p no:cacheprovider",
                      cwd=str(tmp_path), write=False)
    assert report.patches and report.patches[0].checks.get("tests") is True
    assert path.read_text(encoding="utf-8") == PICKLE_APP and not (tmp_path / "RAN_IN").exists()


# ------------------------------------------------------------------ spending guard --

def _fake_api(monkeypatch, usage):
    calls = []

    class Resp:
        def read(self):
            return json.dumps({"content": [{"type": "text", "text": "ok"}], "usage": usage}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout):
        calls.append(json.loads(req.data)["model"])
        return Resp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return calls


def test_prices_follow_the_model():
    from aegis.ai.client import price
    assert price("claude-sonnet-5-5", 1_000_000, 0) == 2.0 and price("claude-sonnet-5-5", 0, 1_000_000) == 10.0
    assert round(price("claude-haiku-5-5", 50_000, 50_000), 6) == 0.03
    assert price("claude-haiku-5-5", 200_000, 0) == 0.1  # long prompts cost more on Haiku 5.5
    assert price("some-new-model", 1_000_000, 0) == 10.0  # unknown: priced high on purpose


def test_budget_stops_before_overspending(monkeypatch):
    from aegis.ai.client import BudgetExceeded, Spending
    calls = _fake_api(monkeypatch, {"input_tokens": 2000, "output_tokens": 1000})
    client = ClaudeClient(api_key="k", model="claude-sonnet-5-5", spending=Spending(budget=0.10))
    done = 0
    with pytest.raises(BudgetExceeded):
        for _ in range(20):
            client.complete("sys", "x" * 3000, max_tokens=2000)
            done += 1
    # each call really costs $0.014; the worst case (2,000 output tokens) must still fit before calling
    assert done == len(calls) and 3 <= done <= 6
    assert client.spending.spent <= 0.10


def test_total_cap_across_runs_uses_the_ledger(monkeypatch, tmp_path):
    from aegis.ai.client import BudgetExceeded, Spending
    _fake_api(monkeypatch, {"input_tokens": 100_000, "output_tokens": 10_000})
    ledger = str(tmp_path / "spend.json")
    first = ClaudeClient(api_key="k", model="claude-sonnet-5-5", spending=Spending(budget=1, total_cap=0.5, ledger=ledger))
    first.complete("s", "p", 100)
    first.complete("s", "p", 100)
    assert round(first.spending.total(), 3) == 0.6  # 2 x (100k in x $2 + 10k out x $10 per million)
    second = ClaudeClient(api_key="k", model="claude-sonnet-5-5", spending=Spending(budget=1, total_cap=0.5, ledger=ledger))
    with pytest.raises(BudgetExceeded, match="total AI cap"):
        second.complete("s", "p", 100)


def test_triage_uses_the_cheap_model_and_the_same_budget(monkeypatch):
    calls = _fake_api(monkeypatch, {"input_tokens": 10, "output_tokens": 10})
    main = ClaudeClient(api_key="k")
    cheap = main.cheaper()
    cheap.complete("s", "p", 10)
    assert calls == ["claude-haiku-5-5"] and cheap.spending is main.spending and main.spending.calls == 1
    assert "1 request" in main.spending.summary()
