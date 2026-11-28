"""A day at a 1C-Bitrix online shop, in real Chrome, through Aegis: shoppers and the shop's own staff.

usage: python benchmarks/bitrix/session.py http://bx.localhost:8092
Prints JSON: every step with ok/error, and every request Aegis refused (403/429/503): those are false
alarms, since nothing here is an attack.
"""
import json
import os
import re
import sys
import time
import traceback
from urllib.parse import quote

from playwright.sync_api import sync_playwright

BASE = sys.argv[1].rstrip("/")
ADMIN_PASSWORD = os.environ.get("BX_ADMIN_PASSWORD", "Aegis-lab-2026!")
PRODUCT = "/catalog/dresses/dress-fashionista-on-a-walk/"
PRODUCT_ID, IBLOCK_ID = os.environ.get("BX_PRODUCT_ID", "7"), os.environ.get("BX_IBLOCK_ID", "2")
IBLOCK_TYPE = os.environ.get("BX_IBLOCK_TYPE", "catalog")
results, refused = [], []


SHOTS = os.environ.get("BX_SHOTS")
PAGES = []


def step(name):
    def wrap(fn):
        def run(*a):
            t0 = time.time()
            try:
                fn(*a)
                results.append({"step": name, "ok": True, "ms": int((time.time() - t0) * 1000)})
            except Exception as exc:
                results.append({"step": name, "ok": False, "error": f"{exc.__class__.__name__}: {str(exc)[:300]}",
                                "where": traceback.format_exc().splitlines()[-3][:200]})
                if SHOTS:
                    for i, page in enumerate(PAGES):
                        try:
                            page.screenshot(path=f"{SHOTS}/{len(results):02d}-{i}.png")
                        except Exception:
                            pass
        run.step_name = name
        return run
    return wrap


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path="/usr/bin/google-chrome",
                                    args=["--no-sandbox", "--disable-background-networking", "--disable-sync"])
        local = re.compile(r"^https?://(bx\.localhost|127\.0\.0\.1)(:\d+)?/")

        def context():
            c = browser.new_context(locale="ru-RU", viewport={"width": 1366, "height": 900})
            c.route("**/*", lambda r: r.continue_() if local.match(r.request.url) else r.abort())
            c.on("response", lambda r: refused.append({"status": r.status, "method": r.request.method,
                                                       "url": r.url[:160]}) if r.status in (403, 429, 503)
                 and r.url.startswith(BASE) else None)
            return c

        shopper = context().new_page()
        shopper.set_default_timeout(60_000)
        PAGES.append(shopper)

        @step("home page")
        def home():
            shopper.goto(BASE + "/")
            assert "Одежда" in shopper.title()

        @step("catalog section and smart filter")
        def catalog():
            shopper.goto(BASE + "/catalog/dresses/")
            shopper.goto(BASE + "/catalog/dresses/filter/price-base-from-1000-to-5000/apply/")

        @step("search with quotes and symbols")
        def search():
            for q in ['платье "летнее"', "O'Neill", "футболка 100% хлопок", "размер 42-44 & скидка", "<b>акция</b>"]:
                shopper.goto(BASE + "/search/?q=" + quote(q))

        @step("product page, pick a size, add to cart")
        def product():
            shopper.goto(BASE + PRODUCT)
            sizes = shopper.query_selector_all(".product-item-scu-item-text-container:not(.notallowed)")
            if len(sizes) > 1:
                sizes[1].click()
            shopper.click(".product-item-detail-buy-button:visible")
            shopper.wait_for_timeout(1500)

        @step("cart: change quantity")
        def cart():
            shopper.goto(BASE + "/personal/cart/")
            plus = shopper.query_selector(".basket-item-amount-btn-plus")
            if plus:
                plus.click()
                shopper.wait_for_timeout(1500)
            assert shopper.query_selector(".basket-item-block-info, .basket-items-list-item-container"), "cart is empty"

        @step("checkout with a Kazakh address and a comment")
        def checkout():
            shopper.goto(BASE + "/personal/order/make/")
            shopper.wait_for_timeout(2500)
            values = [(r"Ф\.?\s?И\.?\s?О|Имя", "Айгерим Сейтказы-О'Нил"), (r"E-?Mail|почт", "aigerim+shop@mail.kz"),
                      (r"Телефон", "+7 (701) 123-45-67"), (r"Адрес", 'г. Шымкент, мкр. Нурсат, д. 12, кв. 5; подъезд "Б"'),
                      (r"Индекс", "160000")]
            for _ in range(8):  # the shop's checkout goes block by block ("Далее"), then "Оформить заказ"
                for field in shopper.query_selector_all("#bx-soa-order input[type=text]:visible, "
                                                        "#bx-soa-order input[type=email]:visible, "
                                                        "#bx-soa-order input[type=tel]:visible, "
                                                        "#bx-soa-order textarea:visible:not([name=ORDER_DESCRIPTION])"):
                    label = field.evaluate("e => (e.closest('.form-group, .bx-soa-customer-field') || e.parentElement)"
                                           ".innerText") or ""
                    for pattern, value in values:
                        if re.search(pattern, label, re.I) and not field.input_value():
                            field.fill(value)
                comment = shopper.query_selector("textarea[name=ORDER_DESCRIPTION]:visible")
                if comment and not comment.input_value():
                    comment.fill("Позвоните до 18:00, код домофона #12. Если нет дома — оставьте у соседей (кв. 6)")
                done = shopper.query_selector("a:visible:has-text('Оформить заказ'), button:visible:has-text('Оформить заказ')")
                if done:
                    done.click()
                    shopper.wait_for_timeout(5000)
                    break
                nxt = shopper.query_selector("#bx-soa-order a:visible:has-text('Далее'), #bx-soa-order button:visible:has-text('Далее')")
                if nxt is None:
                    break
                nxt.click()
                shopper.wait_for_timeout(1500)
            assert "ORDER_ID" in shopper.url or shopper.query_selector("text=Заказ сформирован, text=Ваш заказ"), \
                "order was not placed: " + shopper.url

        @step("register an account")
        def register():
            reg = context().new_page()
            reg.goto(BASE + "/login/?register=yes")
            fields = {"REGISTER[NAME]": "Ерлан", "REGISTER[LAST_NAME]": "Ахметов", "REGISTER[LOGIN]": "erlan_shop",
                      "REGISTER[EMAIL]": "erlan@mail.kz", "REGISTER[PASSWORD]": "Pa$$w0rd'2026",
                      "REGISTER[CONFIRM_PASSWORD]": "Pa$$w0rd'2026"}
            for name, value in fields.items():
                el = reg.query_selector(f"input[name='{name}']")
                if el:
                    el.fill(value)
            reg.click("input[name=register_submit_button], input[type=submit][value*='Регистр']")
            reg.wait_for_timeout(2000)

        admin = context().new_page()
        admin.set_default_timeout(30_000)
        PAGES.append(admin)

        def code_editor(text):
            """Bitrix's code editor: click into it and paste, as a person would."""
            admin.click(".bxce-scroller")
            admin.keyboard.press("Control+A")
            admin.keyboard.insert_text(text)
            admin.wait_for_timeout(300)

        @step("admin: sign in")
        def login():
            admin.goto(BASE + "/bitrix/admin/")
            admin.fill("input[name=USER_LOGIN]", "admin")
            admin.fill("input[name=USER_PASSWORD]", ADMIN_PASSWORD)
            admin.click("input[name=Login], button[name=Login], .login-btn")
            admin.wait_for_selector("#bx-panel, .adm-main-wrap, .adm-workarea", timeout=90_000)

        def save_form(selector="input[name=save], input[name=apply]"):
            admin.click(selector)
            admin.wait_for_load_state("load")
            admin.wait_for_timeout(1000)
            err = admin.query_selector(".adm-info-message-red, .adm-info-message-wrap .errortext")
            assert not err, err.inner_text()[:200] if err else ""

        @step("admin: product description with table, Kaspi button and inline styles")
        def product_edit():
            admin.goto(f"{BASE}/bitrix/admin/iblock_element_edit.php?IBLOCK_ID={IBLOCK_ID}&type={IBLOCK_TYPE}"
                       f"&ID={PRODUCT_ID}&lang=ru&find_section_section=-1")
            html = ('<p style="color:#c00"><b>Хит сезона!</b> Платье из хлопка, <a href="/catalog/dresses/">все платья</a></p>'
                    '<table border="1"><tr><th>Размер</th><th>Обхват</th></tr><tr><td>42</td><td>84-88</td></tr></table>'
                    '<button onclick="window.open(\'https://kaspi.kz/shop/p/123\')">Купить в Kaspi</button>'
                    '<iframe src="https://yandex.ru/map-widget/v1/?um=constructor%3Aabc" width="500" height="300"></iframe>')
            admin.evaluate("""(html) => {
                const f = [...document.forms].find(f => f.querySelector('[name=NAME]') && f.querySelector('[name=ID]'));
                for (const n of ['DETAIL_TEXT', 'PREVIEW_TEXT']) {
                    let t = f.querySelector('[name=' + n + ']');
                    if (!t) { t = document.createElement('textarea'); t.name = n; t.style.display = 'none'; f.appendChild(t); }
                    t.value = n === 'DETAIL_TEXT' ? html : 'Лёгкое платье «Модница» — 100% хлопок';
                    const type = f.querySelector('[name=' + n + '_TYPE]');
                    if (type) { type.value = 'html'; }
                }
            }""", html)
            save_form("input[name=apply]:visible")

        @step("admin: new page in Site Explorer (page source) with a Yandex.Metrika counter")
        def new_page():
            admin.goto(f"{BASE}/bitrix/admin/fileman_file_edit.php?lang=ru&site=s1&path=%2Fabout&full_src=Y&new=Y")
            admin.fill("input[name=filename]", "promo.php")
            page_src = ('<?require($_SERVER["DOCUMENT_ROOT"]."/bitrix/header.php");$APPLICATION->SetTitle("Акция «Чёрная пятница»");?>'
                        '<h2>Скидки до 50%</h2><p>Только 27–29 ноября: <a href="/catalog/">весь каталог</a>.</p>'
                        '<script type="text/javascript">(function(m,e,t,r,i,k,a){m[i]=m[i]||function(){(m[i].a=m[i].a||[])'
                        '.push(arguments)};m[i].l=1*new Date();k=e.createElement(t),a=e.getElementsByTagName(t)[0],'
                        'k.async=1,k.src=r,a.parentNode.insertBefore(k,a)})(window, document, "script", '
                        '"https://mc.yandex.ru/metrika/tag.js", "ym");ym(98765432, "init", {clickmap:true});</script>'
                        '<?require($_SERVER["DOCUMENT_ROOT"]."/bitrix/footer.php");?>')
            code_editor(page_src)
            save_form("input[name=save]:visible")
            assert "ym(98765432" in open(os.environ.get("BX_SITE", "/tmp/bxlab/site") + "/about/promo.php",
                                         encoding="utf-8").read()

        @step("admin: shop settings with quotes and an e-mail")
        def settings():
            admin.goto(f"{BASE}/bitrix/admin/settings.php?lang=ru&mid=main&mid_menu=1")
            admin.fill("input[name=site_name]", 'ИП «Ромашка» — "Одежда"')
            admin.click("form[name=main_options] input[name=Apply]")
            admin.wait_for_load_state("load")
            assert admin.input_value("input[name=site_name]") == 'ИП «Ромашка» — "Одежда"' 

        @step("admin: SQL console query")
        def sql_console():
            admin.goto(f"{BASE}/bitrix/admin/sql.php?lang=ru")
            code_editor("SELECT id, name FROM b_iblock_element WHERE name LIKE '%Платье%' ORDER BY id LIMIT 5")
            admin.click("input[name=execute]:visible")
            admin.wait_for_timeout(3000)
            assert "Платье" in admin.inner_text("body"), "no query result"

        @step("admin: PHP command line")
        def php_console():
            admin.goto(f"{BASE}/bitrix/admin/php_command_line.php?lang=ru")
            code_editor('echo "Заказов: " . CSaleOrder::GetList([], [], []); echo date("d.m.Y");')
            admin.click("input[name=execute]:visible")
            admin.wait_for_timeout(3000)
            assert "Заказов" in admin.inner_text("body"), "no PHP result"

        @step("admin: orders list with a filter")
        def orders():
            admin.goto(f"{BASE}/bitrix/admin/sale_order.php?lang=ru&filter_user_name=%D0%90%D0%B9%D0%B3%D0%B5%D1%80%D0%B8%D0%BC"
                       "&set_filter=Y")

        @step("admin: users search")
        def users():
            admin.goto(f"{BASE}/bitrix/admin/user_admin.php?lang=ru&find=O%27Brien&find_type=login&set_filter=Y")

        @step("admin: clear the cache")
        def cache():
            admin.goto(f"{BASE}/bitrix/admin/cache.php?lang=ru&tabControl_active_tab=fedit2")
            tab = admin.query_selector("text=Очистка файлов кеша")
            if tab:
                tab.click()
            admin.check("input[name=cachetype][value=all]")
            admin.click("input[type=submit][value*='Начать']:visible, input[type=button][value*='Начать']:visible")
            admin.wait_for_timeout(3000)

        @step("shopper: the new promo page and the edited product")
        def check_pages():
            shopper.goto(BASE + "/about/promo.php")
            shopper.goto(BASE + PRODUCT)

        for fn in (home, catalog, search, product, cart, checkout, register, login, product_edit, new_page,
                   settings, sql_console, php_console, orders, users, cache, check_pages):
            fn()
        browser.close()
    print(json.dumps({"steps": results, "refused": refused}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
