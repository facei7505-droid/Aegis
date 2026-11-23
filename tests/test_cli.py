"""CLI behaviour that CI pipelines rely on."""
import json
import shutil
from pathlib import Path

from aegis.cli import main

DEMO = Path(__file__).parents[1] / "aegis" / "demo_app" / "vulnshop"


def project(tmp_path):
    shutil.copytree(DEMO, tmp_path / "p")
    return tmp_path / "p"


def test_scan_exit_codes(tmp_path, capsys):
    p = project(tmp_path)
    assert main(["scan", str(p)]) == 1
    assert main(["scan", str(p), "--fail-on", "never"]) == 0
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "ok.py").write_text("print('hello')\n")
    assert main(["scan", str(clean)]) == 0


def test_scan_json_and_sarif(tmp_path):
    p = project(tmp_path)
    main(["scan", str(p), "-f", "json", "-o", str(tmp_path / "r.json")])
    data = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert len(data["findings"]) == 13 and data["findings"][0]["file"] == "app.py"
    main(["scan", str(p), "-f", "sarif", "-o", str(tmp_path / "r.sarif")])
    sarif = json.loads((tmp_path / "r.sarif").read_text(encoding="utf-8"))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and len(run["results"]) == 13
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} >= {r["ruleId"] for r in run["results"]}
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"


def test_html_and_markdown(tmp_path):
    p = project(tmp_path)
    main(["scan", str(p), "-f", "html", "-o", str(tmp_path / "r.html"), "--lang", "ru"])
    html = (tmp_path / "r.html").read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html and "Отчёт по безопасности" in html and "<script" not in html.split("<style>")[0]
    main(["scan", str(p), "-f", "markdown", "-o", str(tmp_path / "r.md")])
    assert "| Severity |" in (tmp_path / "r.md").read_text(encoding="utf-8")


def test_report_escapes_attacker_content(tmp_path):
    p = tmp_path / "x"
    p.mkdir()
    (p / "app.py").write_text("API_KEY = '<img src=x onerror=alert(1)>abcdef'\n")
    main(["scan", str(p), "-f", "html", "-o", str(tmp_path / "r.html")])
    assert "<img src=x" not in (tmp_path / "r.html").read_text(encoding="utf-8")


def test_baseline_hides_known_findings(tmp_path, capsys):
    p = project(tmp_path)
    base = tmp_path / "base.json"
    main(["baseline", str(p), "-o", str(base)])
    assert main(["scan", str(p), "--baseline", str(base)]) == 0
    app = p / "app.py"
    app.write_text(app.read_text(encoding="utf-8") + "\nTOKEN = 'ghp_newly_leaked_token_123'\n")
    assert main(["scan", str(p), "--baseline", str(base)]) == 1
    out = capsys.readouterr().out
    assert "ghp_newly_leaked_token_123" in out and "13 known finding(s) hidden" in out


def test_config_from_pyproject(tmp_path):
    p = project(tmp_path)
    (p / "pyproject.toml").write_text('[tool.aegis]\ndisable = ["AEG010", "AEG006"]\nfail_on = "critical"\n')
    main(["scan", str(p), "-f", "json", "-o", str(tmp_path / "r.json")])
    ids = {f["rule_id"] for f in json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["findings"]}
    assert "AEG010" not in ids and "AEG006" not in ids


def test_fix_dry_run_and_apply(tmp_path, capsys):
    p = project(tmp_path)
    before = (p / "app.py").read_text(encoding="utf-8")
    main(["fix", str(p), "--dry-run"])
    assert (p / "app.py").read_text(encoding="utf-8") == before
    assert "10 verified patch(es) proposed" in capsys.readouterr().out
    main(["fix", str(p), "--diff", str(tmp_path / "all.diff"), "--report", str(tmp_path / "fix.html")])
    assert (p / "app.py").read_text(encoding="utf-8") != before
    assert "+++ b/app.py" in (tmp_path / "all.diff").read_text(encoding="utf-8")
    assert "Verified patches" in (tmp_path / "fix.html").read_text(encoding="utf-8")


def test_ai_flag_requires_key(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    p = project(tmp_path)
    try:
        main(["fix", str(p), "--ai"])
    except SystemExit as exc:
        assert exc.code == 2
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err


def test_rules_command(capsys):
    main(["rules"])
    out = capsys.readouterr().out
    assert "AEG001" in out and "CWE-89" in out and len(out.strip().splitlines()) == 11
