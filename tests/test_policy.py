"""Site presets, virtual patches, login and rate limits, and what the logs keep."""
from __future__ import annotations

import json

import pytest

import aegis.shield.core as core_mod
from aegis.shield.core import ShieldConfig, ShieldCore, Verdict, block_response, mask
from aegis.shield.detectors import analyze
from aegis.shield.policy import PRESETS, Request, preset

WP_COOKIE = "wordpress_logged_in_a2c6=admin%7C1%7Cx%7Cy"


def shield(**options) -> ShieldCore:
    return ShieldCore(ShieldConfig(mode=options.pop("mode", "block"), ban_after=options.pop("ban_after", 0), **options))


def check(core: ShieldCore, method: str, target: str, body: bytes = b"", ctype: str = "",
          cookie: str = "", client: str = "203.0.113.7") -> Verdict:
    path, _, query = target.partition("?")
    headers = {"cookie": cookie} if cookie else {}
    return core.inspect(client, method, path, core.collect_inputs(path, query, headers, body, ctype))


# ------------------------------------------------------------- WordPress --

POST = json.dumps({"title": "Скидки до 50%", "status": "publish",
                   "content": '<p>Скидки!</p><a href="https://kaspi.kz/pay" onclick="ym(1,\'reachGoal\',\'kaspi\')">Kaspi</a>'
                              '<script>ym(98765432, "init", {webvisor:true});</script>'}).encode()


def test_editor_html_passes_only_with_the_editor_cookie():
    core = shield(preset="wordpress")
    assert not check(core, "POST", "/?rest_route=/wp/v2/posts", POST, "application/json", WP_COOKIE).blocked
    assert not check(core, "POST", "/wp-json/wp/v2/posts/12", POST, "application/json", WP_COOKIE).blocked
    anonymous = check(core, "POST", "/wp-json/wp/v2/posts", POST, "application/json")
    assert anonymous.blocked and anonymous.incident.attack_type == "xss"


def test_trust_is_per_field_and_per_class():
    core = shield(preset="wordpress")
    # Markup in the post body is fine for an editor; SQL injection in another field still is not.
    body = json.dumps({"content": "<script>x()</script>", "slug": "a' UNION SELECT user_pass FROM wp_users--"}).encode()
    verdict = check(core, "POST", "/wp-json/wp/v2/posts", body, "application/json", WP_COOKIE)
    assert verdict.blocked and verdict.incident.attack_type == "sqli"
    # ...and SQL injection inside the trusted field is not covered by a markup-only trust.
    body = json.dumps({"content": "1' UNION SELECT user_pass FROM wp_users--"}).encode()
    assert check(core, "POST", "/wp-json/wp/v2/posts", body, "application/json", WP_COOKIE).blocked


def test_comment_blocklist_setting_takes_attack_strings_from_the_owner():
    core = shield(preset="wordpress")
    form = b"option_page=discussion&disallowed_keys=%3Cscript%3E%0D%0Aunion+select%0D%0A%27+or+1%3D1"
    ctype = "application/x-www-form-urlencoded"
    assert not check(core, "POST", "/wp-admin/options.php", form, ctype, WP_COOKIE).blocked
    assert check(core, "POST", "/wp-admin/options.php", form, ctype).blocked


def test_visitor_comment_is_inspected_fully():
    core = shield(preset="wordpress")
    form = "comment=<img src=x onerror=alert(1)>&author=x&email=x@x.kz&comment_post_ID=1".encode()
    assert check(core, "POST", "/wp-comments-post.php", form, "application/x-www-form-urlencoded", WP_COOKIE).blocked


@pytest.mark.parametrize("method,target,body,cookie,blocked", [
    ("GET", "/?author=1", b"", "", True),
    ("GET", "/?author=1", b"", WP_COOKIE, False),
    ("GET", "/?rest_route=/wp/v2/users", b"", "", True),
    ("GET", "/wp-json/wp/v2/users?who=authors", b"", WP_COOKIE, False),
    ("GET", "/wp-content/uploads/2026/11/shell.php", b"", "", True),
    ("GET", "/wp-content/uploads/2026/11/photo.jpg", b"", "", False),
    ("GET", "/wp-content/debug.log", b"", "", True),
    ("POST", "/xmlrpc.php", b"<methodCall><methodName>system.multicall</methodName></methodCall>", "", True),
    ("POST", "/xmlrpc.php", b"<methodCall><methodName>wp.getUsersBlogs</methodName></methodCall>", "", False),
])
def test_wordpress_virtual_patches(method, target, body, cookie, blocked):
    verdict = check(shield(preset="wordpress"), method, target, body, "text/xml" if body else "", cookie)
    assert verdict.blocked is blocked
    if blocked:
        assert verdict.incident.attack_type == "virtual_patch"


# ---------------------------------------------------------------- Bitrix --

@pytest.mark.parametrize("method,target,blocked", [
    ("POST", "/bitrix/tools/vote/uf.php?attachId[ENTITY_TYPE]=CFileUploader&attachId[ENTITY_ID][events]"
             "[onFileIsStarted][]=CAllAgent&action=vote", True),
    ("POST", "/bitrix/tools/vote/uf.php", True),
    ("GET", "/bitrix/tools/vote/uf.php", False),
    ("POST", "/bitrix/tools/html_editor_action.php", True),
    ("GET", "/bitrix/components/x/ajax.php?attachId[ENTITY_ID][events][x][]=CAllAgent", True),
    ("GET", "/bitrix/.settings.php", True),
    ("GET", "/bitrix/backup/site_20261101.tar.gz", True),
    ("GET", "/upload/iblock/1a2/x.php", True),
    ("GET", "/upload/iblock/1a2/photo.webp", False),
    ("GET", "/catalog/jeans/?PAGEN_1=2&sort=price", False),
])
def test_bitrix_virtual_patches(method, target, blocked):
    assert check(shield(preset="bitrix"), method, target).blocked is blocked


def test_bitrix_admin_editor_html_with_sessid():
    core = shield(preset="bitrix")
    form = "sessid=abc123&DETAIL_TEXT=<p>Новинка</p><script src=\"https://mc.yandex.ru/metrika/tag.js\"></script>".encode()
    ctype = "application/x-www-form-urlencoded"
    assert not check(core, "POST", "/bitrix/admin/iblock_element_edit.php", form, ctype).blocked
    assert check(core, "POST", "/catalog/", form, ctype).blocked


def test_opencart_patches():
    core = shield(preset="opencart")
    assert check(core, "GET", "/install/index.php").blocked
    assert check(core, "GET", "/system/storage/logs/error.log").blocked
    assert not check(core, "GET", "/index.php?route=product/product&product_id=42").blocked


# ---------------------------------------------------------------- limits --

def test_login_flood_is_cut_but_the_site_stays_open(monkeypatch):
    clock = [1_000_000.0]
    monkeypatch.setattr(core_mod.time, "time", lambda: clock[0])
    core = shield(preset="wordpress", login_limit=10, login_window=600, login_lockout=1800)
    form = b"log=admin&pwd=guess&wp-submit=Log+In"
    ctype = "application/x-www-form-urlencoded"
    answers = [check(core, "POST", "/wp-login.php", form, ctype) for _ in range(14)]
    assert [v.blocked for v in answers[:10]] == [False] * 10
    tripped = answers[10]
    assert tripped.blocked and tripped.status == 429 and tripped.incident.attack_type == "brute_force"
    assert all(v.blocked and v.status == 429 and v.incident is None for v in answers[11:])
    assert len([i for i in core.incidents if i.attack_type == "brute_force"]) == 1
    assert not check(core, "GET", "/?p=1").blocked                   # the rest of the site stays open
    assert not check(core, "POST", "/wp-login.php", form, ctype, client="203.0.113.8").blocked  # others unaffected
    clock[0] += 1801
    assert not check(core, "POST", "/wp-login.php", form, ctype).blocked


def test_generic_logins_count_any_password_form():
    core = shield(preset="generic", login_limit=3)
    form, ctype = b"email=a@b.kz&password=x", "application/x-www-form-urlencoded"
    results = [check(core, "POST", "/account/sign-in", form, ctype).status for _ in range(5)]
    assert results[3] == 429


def test_rate_limit_counts_pages_not_files(monkeypatch):
    monkeypatch.setattr(core_mod.time, "time", lambda: 2_000_000.0)
    core = shield(preset="generic", rate_limit=20)
    assert not any(check(core, "GET", f"/static/app.{i}.js").blocked for i in range(100))
    pages = [check(core, "GET", f"/catalog?page={i}") for i in range(25)]
    assert [v.blocked for v in pages].index(True) == 20 and pages[20].status == 429 and pages[20].retry_after > 0


def test_monitor_mode_records_limits_without_blocking():
    core = shield(preset="wordpress", login_limit=2, mode="monitor")
    form, ctype = b"log=admin&pwd=x", "application/x-www-form-urlencoded"
    assert not any(check(core, "POST", "/wp-login.php", form, ctype).blocked for _ in range(6))
    assert [i.attack_type for i in core.incidents] == ["brute_force"]


def test_unlock_lifts_every_block():
    core = shield(preset="wordpress", login_limit=1)
    form, ctype = b"log=admin&pwd=x", "application/x-www-form-urlencoded"
    for _ in range(3):
        check(core, "POST", "/wp-login.php", form, ctype)
    assert check(core, "POST", "/wp-login.php", form, ctype).blocked
    assert core.unlock("203.0.113.7")
    assert not check(core, "POST", "/wp-login.php", form, ctype).blocked


def test_unknown_preset_is_refused():
    with pytest.raises(ValueError):
        preset("joomla3000")
    assert set(PRESETS) == {"generic", "wordpress", "bitrix", "opencart"}


def test_rest_route_in_the_query_is_the_route():
    req = Request.build("GET", "/", [("query", "rest_route", "/wp/v2/users")])
    assert req.route == "/wp-json/wp/v2/users"


# ------------------------------------------------------- privacy and pages --

def test_logs_keep_the_attack_not_the_visitor():
    assert mask("password", "hunter2' OR 1=1") == "[15 символов скрыто]"
    masked = mask("comment", "<script>x</script> card 4400 4302 1234 5678, aigerim@mail.kz, +7 (701) 123-45-67")
    assert "4400" not in masked and "aigerim" not in masked and "701" not in masked and "<script>" in masked
    core = shield()
    verdict = check(core, "GET", "/?q=%3Cscript%3Ealert(1)%3C/script%3E%20aigerim@mail.kz")
    assert "aigerim" not in verdict.incident.payload


def test_block_page_for_browsers_json_for_scripts():
    core = shield()
    verdict = check(core, "GET", "/?q=1'+UNION+SELECT+password+FROM+users--")
    ctype, page = block_response(verdict, "text/html,application/xhtml+xml")
    assert ctype.startswith("text/html") and "Запрос остановлен" in page.decode() and verdict.incident.id in page.decode()
    ctype, body = block_response(verdict, "*/*")
    assert ctype == "application/json" and json.loads(body)["reason"] == "sqli"
    ctype, body = block_response(Verdict(True, status=429, reason="brute_force"), "")
    assert json.loads(body)["reason"] == "brute_force"


# ------------------------------------------------- signatures from the lab --

ATTACKS = [" or 'a'='a", " or 2 > 1", " or '7659'='7659", "admin' or '", "x' AND members.email IS NULL; --",
           "%20or%20''='", " or 'whatever' in ('whatever')", "or isNULL(1/0) /*", "\\x27UNION SELECT",
           "||(elt(-3+5,bin(15),ord(10),hex(char(45))))", "exec(@s)", "@var select @var as var into temp end --",
           "0x77616974666F722064656C61792027303A303A313027", "/%25%5c..%25%5c..%25%5c..boot.ini",
           "c:\\apache\\logs\\access.log", "C:/inetpub/wwwroot/global.asa", "/boot/grub/grub.conf", "/.bash_profile"]

BENIGN = ["джинсы levi's 501", "O'Stin куртка", "rock 'n' roll or 'pop'", "Levi's or Wrangler", "размер 48 or 50",
          "select size: M", "update: новая коллекция", "like", "it's 'cool' or 'not'", "'Ромашка' или 'Лютик'",
          "кабель ВВГ 3*2.5 \"ГОСТ\"", "price < 10000 and > 5000", "my id is 0xDEADBEEFDEADBEEF",
          "C:/Users/aigerim/Documents/резюме.docx", "Гүлнұр Әбілқасымқызы", "ул. Тауке хана, 12/3, ТЦ «Мега»",
          "скидка 50% & доставка", "<3 подарок для мамы", "Скидка 30% != 50%", "+7 (701) 123-45-67"]


@pytest.mark.parametrize("value", ATTACKS)
def test_lab_misses_are_now_caught(value):
    assert analyze([("query", "s", value)], 0.8) is not None


@pytest.mark.parametrize("value", BENIGN)
def test_shop_text_is_not_an_attack(value):
    assert analyze([("query", "s", value)], 0.8) is None
