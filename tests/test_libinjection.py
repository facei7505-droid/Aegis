"""libinjection: the optional second detector. Tests that need the compiled engine skip without it."""
from __future__ import annotations

import shutil
import sys

import pytest

from aegis.cli import main
from aegis.shield import detectors, libinjection
from aegis.shield.detectors import analyze

needs_engine = pytest.mark.skipif(not libinjection.available(), reason="libinjection not built (aegis build-engine)")
needs_cc = pytest.mark.skipif(sys.platform == "win32" or not (shutil.which("cc") or shutil.which("gcc")),
                              reason="no C compiler")


def _query(value: str):
    return analyze([("query", "q", value)], 0.8)


@needs_engine
@pytest.mark.parametrize("value, fingerprint", [
    ("1' or '1'='1", "s&sos"),
    ("1 union select 1", "1UE1"),
])
def test_engine_fingerprints(value, fingerprint):
    assert libinjection.is_sqli(value) == (True, fingerprint)


@needs_engine
@pytest.mark.parametrize("value", ["", "hello", "Москва, ул. Абая 12", "размер 48 or 50", "price < 10000 and > 5000"])
def test_engine_ignores_normal_text(value):
    assert libinjection.is_sqli(value)[0] is False
    assert libinjection.is_xss(value) is False


@needs_engine
def test_engine_xss():
    assert libinjection.is_xss("<img src=x onerror=alert(1)>")
    assert not libinjection.is_xss("a < b and c > d")


@needs_engine
def test_second_opinion_is_a_named_signal():
    detection = _query("1 union select 1")
    assert detection and detection.attack_type == "sqli"
    assert "libinjection sqli 1UE1" in detection.signals


@needs_engine
def test_arithmetic_fingerprint_alone_does_not_block():
    """'2 < 3 and 5 > 4' is the same fingerprint (1&1) as '1 and 1=1': it may only add to a signature."""
    assert libinjection.is_sqli("2 < 3 and 5 > 4")[0]
    assert _query("2 < 3 and 5 > 4") is None
    assert _query("1 and 1=1").attack_type == "sqli"


ONLY_ENGINE = [  # from SecLists XSS-RSNAKE and quick-SQLi: signatures alone let these through
    ("<DIV STYLE=\"width: expression(alert('XSS'));\">", "xss"),
    ("<LINK REL=\"stylesheet\" HREF=\"http://ha.ckers.org/xss.css\">", "xss"),
    ("' or ''-'", "sqli"),
]


@needs_engine
@pytest.mark.parametrize("vector, attack", ONLY_ENGINE)
def test_engine_adds_what_signatures_miss(monkeypatch, vector, attack):
    detection = _query(vector)
    assert detection is not None and detection.attack_type == attack
    monkeypatch.setattr(detectors.libinjection, "available", lambda: False)
    assert _query(vector) is None


def test_disabled_engine_means_signatures_only(monkeypatch):
    monkeypatch.setattr(detectors.libinjection, "available", lambda: False)
    detection = _query("1' or '1'='1")
    assert detection and detection.attack_type == "sqli"
    assert not any(s.startswith("libinjection") for s in detection.signals)


def test_missing_library_is_not_an_error(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_LIBINJECTION", str(tmp_path / "nope.so"))
    monkeypatch.setattr(libinjection, "SOURCES", tmp_path / "native" / "libinjection")
    monkeypatch.setattr(libinjection.Path, "home", lambda: tmp_path)
    engine = libinjection._Engine()
    assert engine.load() is None


def test_no_libinjection_env(monkeypatch):
    monkeypatch.setenv("AEGIS_NO_LIBINJECTION", "1")
    assert libinjection._Engine().load() is None


def test_build_without_compiler(monkeypatch, tmp_path):
    monkeypatch.delenv("CC", raising=False)
    monkeypatch.setattr(libinjection.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="no C compiler"):
        libinjection.build(tmp_path / "x.so")


@needs_cc
def test_build_engine_command(tmp_path, capsys, monkeypatch):
    out = tmp_path / ("_li" + libinjection.SUFFIX)
    monkeypatch.delenv("AEGIS_NO_LIBINJECTION", raising=False)
    try:
        assert main(["build-engine", "--output", str(out)]) == 0
        assert out.exists()
        assert "self-test: ok" in capsys.readouterr().out
        assert main(["build-engine", "--check"]) == 0
    finally:
        libinjection.ENGINE.reset()  # back to the default search for the other tests
