"""OWASP CRS phrase lists, used with context so shop URLs are not mistaken for system files."""
from __future__ import annotations

import pytest

from aegis.shield import crs
from aegis.shield.detectors import analyze


def query(value):
    return analyze([("query", "file", value)], 0.8)


@pytest.mark.parametrize("path, entry", [
    ("/wp-content/debug.log", "/debug.log"), ("/.env", ".env"), ("/shop/.git/config", ".git/"),
    ("/composer.lock", "/composer.lock"), ("/proc/self/environ", "proc/self"), ("/wp-config.php.save", "wp-config."),
])
def test_restricted_files_in_the_path(path, entry):
    assert crs.restricted_path(path) == entry
    assert analyze([("path", "path", path)], 0.8).attack_type == "recon"


@pytest.mark.parametrize("path", ["/my.environment", "/upload/tmp/photo.jpg", "/sys/login", "/catalog/phones/",
                                  "/bitrix/admin/index.php", "/.well-known/acme-challenge/abc", "/robots.txt"])
def test_ordinary_paths_pass(path):
    assert crs.restricted_path(path) is None


@pytest.mark.parametrize("value", ["/usr/local/cpanel/logs/access_log", "/opt/xampp/logs/error.log",
                                   "C:\\Windows\\win.ini", "php://filter/resource=/etc/passwd", "/.netrc",
                                   "..\\..\\boot.ini"])
def test_system_files_in_a_file_parameter(value):
    det = query(value)
    assert det is not None and det.attack_type == "path_traversal"


@pytest.mark.parametrize("value", ["/upload/tmp/photo.jpg", "perl/python books", "learn etc/hosts",
                                   "price $PATH", "cabin/at the lake",
                                   "usr/bin/env python"])
def test_words_that_merely_look_like_paths(value):
    assert query(value) is None


def test_shell_after_a_separator():
    assert query(";/bin/busybox wget x").attack_type == "command_injection"
