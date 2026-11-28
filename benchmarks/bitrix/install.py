"""Install 1C-Bitrix (Enterprise for PostgreSQL, trial) through its own web wizard, in real Chrome.

usage: python benchmarks/bitrix/install.py http://bx.localhost:8093 [screenshot dir]

Walks the wizard the way a person would: agree to the licence, skip registration (trial), pass the
system check, connect PostgreSQL (DB settings from env BX_DB_*), wait for the module installation,
create the administrator, pick the online-shop solution. Prints one JSON line per wizard step.
"""
import json
import os
import re
import sys
import time

from playwright.sync_api import Error as PlaywrightError, sync_playwright

BASE = sys.argv[1].rstrip("/")
SHOTS = sys.argv[2] if len(sys.argv) > 2 else None
DB = {"host": os.environ.get("BX_DB_HOST", "127.0.0.1"), "user": os.environ.get("BX_DB_USER", "bitrix"),
      "password": os.environ.get("BX_DB_PASSWORD", "bxlab-pass"), "name": os.environ.get("BX_DB_NAME", "bitrix")}
ADMIN = {"login": "admin", "password": os.environ.get("BX_ADMIN_PASSWORD", "Aegis-lab-2026!"),
         "email": "admin@bx.localhost"}


def log(**kw):
    print(json.dumps(kw, ensure_ascii=False), flush=True)


def field(page, name, value=None):
    """Wizard fields are named __wiz_<name>; radios also need the value."""
    for sel in (f"[name=__wiz_{name}]", f"[name={name}]", f"#{name}"):
        sel = sel + (f"[value='{value}']" if value is not None and not sel.startswith("#") else "")
        if page.query_selector(sel):
            return sel
    return f"[name=__wiz_{name}]"


def uncheck_if(page, selector):
    el = page.query_selector(selector)
    if el and el.is_visible() and el.is_checked():
        el.uncheck()


def dump(page):
    fields = []
    for el in page.query_selector_all("#__wizard_form input, #__wizard_form select"):
        if el.get_attribute("type") != "hidden":
            fields.append([el.get_attribute("type"), el.get_attribute("name"), el.get_attribute("value"), el.is_visible()])
    return fields


def fill_if(page, selector, value):
    el = page.query_selector(selector)
    if el and el.is_visible():
        tag = el.evaluate("e => e.tagName + ':' + (e.type || '')")
        if tag.startswith("SELECT"):
            el.select_option(value)
        elif tag.endswith("checkbox") or tag.endswith("radio"):
            if not el.is_checked():
                el.check()
        else:
            el.fill(value)
        return True
    return False


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path="/usr/bin/google-chrome",
                                    args=["--no-sandbox", "--disable-background-networking", "--disable-sync"])
        state = os.environ.get("BX_RESUME")  # storage state saved by an earlier run: continue that wizard
        ctx = browser.new_context(locale="ru-RU", viewport={"width": 1280, "height": 900},
                                  storage_state=state if state and os.path.exists(state) else None)
        local = re.compile(r"^https?://(bx\.localhost|127\.0\.0\.1|localhost)(:\d+)?/")
        ctx.route("**/*", lambda r: r.continue_() if local.match(r.request.url) else r.abort())
        page = ctx.new_page()
        page.set_default_timeout(120_000)
        page.goto(BASE + "/")
        state = {"last": None, "same": 0}
        for n in range(400):
            try:
                if step_once(page, n, state):
                    break
            except PlaywrightError as exc:  # the wizard navigated while we looked: look again
                log(n=n, retry=str(exc)[:120])
                time.sleep(3)
        ctx.storage_state(path="/tmp/bxlab/admin-state.json")
        browser.close()


def step_once(page, n, state):
    """One look at the wizard and one action. True when the installation is finished or stuck."""
    page.wait_for_load_state("load")
    step = page.eval_on_selector("input[name=CurrentStepID]", "e => e.value") \
        if page.query_selector("input[name=CurrentStepID]") else ""
    text = re.sub(r"\s+", " ", page.inner_text("body"))[:300]
    log(n=n, step=step, url=page.url, text=text)
    if SHOTS:
        page.screenshot(path=f"{SHOTS}/{n:02d}-{step or 'page'}.png")
    if step == state["last"]:
        state["same"] += 1
        if state["same"] >= 3 and step not in ("create_modules", "install_modules", "create_modules_db", "data_install"):
            err = page.query_selector(".inst-note-block-red, .instal-error, .error, font.errortext")
            log(stuck=step, error=err.inner_text()[:500] if err else text)
            return True
    else:
        state["last"], state["same"] = step, 0
    if state["same"] == 0:
        log(fields=dump(page))
    if step == "agreement":
        fill_if(page, "#agree_license_id", "")
    if step == "check_license_key":
        uncheck_if(page, "#lic_key_variant")  # registering needs the internet: trial instead
    if step in ("select_database", "create_database"):
        fill_if(page, field(page, "dbType", "pgsql"), "")
    if step == "create_database":
        fill_if(page, field(page, "host"), DB["host"])
        fill_if(page, field(page, "user"), DB["user"])
        fill_if(page, field(page, "password"), DB["password"])
        fill_if(page, field(page, "database"), DB["name"])
        fill_if(page, field(page, "create_database", "N"), "")
        fill_if(page, field(page, "create_user", "N"), "")
    if step == "select_wizard":
        radios = page.query_selector_all("#__wizard_form input[type=radio]")
        if radios and not any(r.is_checked() for r in radios):
            radios[0].click()  # "Интернет-магазин": the online-shop solution
    if step == "create_admin":
        fill_if(page, field(page, "login"), ADMIN["login"])
        fill_if(page, field(page, "admin_password"), ADMIN["password"])
        fill_if(page, field(page, "admin_password_confirm"), ADMIN["password"])
        fill_if(page, field(page, "email"), ADMIN["email"])
        fill_if(page, field(page, "user_name"), "Магжан")
        fill_if(page, field(page, "user_surname"), "Админ")
    if step in ("create_modules", "install_modules", "data_install") or "Установка модулей" in text:
        time.sleep(5)  # the wizard installs modules with its own AJAX loop and moves on by itself
        return False
    if "/bitrix/admin" in page.url or (not step and "wizard" not in page.url and n > 3):
        log(done=True, url=page.url)
        return True
    button = page.query_selector("input.wizard-next-button:visible, button.wizard-next-button:visible, "
                                 "input[name=StepNext]:visible, .wizard-next-button:visible")
    if button is None:
        log(no_button=True)
        time.sleep(5)
        return False
    button.click()
    time.sleep(1)
    return False


if __name__ == "__main__":
    main()
