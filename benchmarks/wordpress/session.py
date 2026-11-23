"""A day of ordinary WordPress work, driven in real Chrome through Aegis.

Every step is something a small-shop owner or editor does. Afterwards the gateway's incident log
says which of these requests the shield would have blocked: each one is a false alarm.
Usage: python session.py BASE_URL [install]
"""
import base64
import json
import sys
import time

from playwright.sync_api import sync_playwright

BASE = sys.argv[1].rstrip("/")
INSTALL = len(sys.argv) > 2 and sys.argv[2] == "install"
USER, PASS = "admin", "Shymkent-2026!Strong"
results = []

METRIKA = """<!-- Yandex.Metrika counter -->
<script type="text/javascript">
   (function(m,e,t,r,i,k,a){m[i]=m[i]||function(){(m[i].a=m[i].a||[]).push(arguments)};
   m[i].l=1*new Date();k=e.createElement(t),a=e.getElementsByTagName(t)[0],k.async=1,k.src=r,a.parentNode.insertBefore(k,a)})
   (window, document, "script", "https://mc.yandex.ru/metrika/tag.js", "ym");
   ym(98765432, "init", { clickmap:true, trackLinks:true, accurateTrackBounce:true, webvisor:true });
</script>
<noscript><div><img src="https://mc.yandex.ru/watch/98765432" style="position:absolute; left:-9999px;" alt="" /></div></noscript>
<!-- /Yandex.Metrika counter -->"""

POST_HTML = """<!-- wp:paragraph -->
<p>Друзья, с 25 ноября по 1 декабря — <strong>скидки до 50%</strong> на джинсы Levi's 501 и O'Stin. Адрес: г. Шымкент, ул. Тауке хана, 12/3, ТЦ «Мега», 2 этаж.</p>
<!-- /wp:paragraph -->
<!-- wp:list --><ul><li>Размеры 28–36</li><li>Цена от 9 990 ₸ (было 19 990 ₸)</li><li>Оплата Kaspi QR или «Kaspi Red»</li></ul><!-- /wp:list -->
<!-- wp:table --><figure class="wp-block-table"><table><thead><tr><th>Модель</th><th>Было</th><th>Стало</th></tr></thead><tbody><tr><td>501 Original</td><td>19 990 ₸</td><td>9 990 ₸</td></tr><tr><td>512 Slim Taper</td><td>24 990 ₸</td><td>14 990 ₸</td></tr></tbody></table></figure><!-- /wp:table -->
<!-- wp:embed {"url":"https://www.youtube.com/watch?v=dQw4w9WgXcQ","type":"video","providerNameSlug":"youtube"} -->
<figure class="wp-block-embed is-type-video is-provider-youtube"><div class="wp-block-embed__wrapper">https://www.youtube.com/watch?v=dQw4w9WgXcQ</div></figure>
<!-- /wp:embed -->
<!-- wp:html -->
<div class="kaspi-button"><a href="https://kaspi.kz/pay/romashka?amount=9990&ref=post'50" onclick="ym(98765432,'reachGoal','kaspi'); return true;" target="_blank" rel="noopener">Оплатить через Kaspi</a></div>
<iframe src="https://yandex.ru/map-widget/v1/?ll=69.5901%2C42.3417&z=16" width="560" height="400" frameborder="0"></iframe>
<!-- /wp:html -->
<!-- wp:code --><pre class="wp-block-code"><code>SELECT name, price FROM products WHERE price &lt; 10000 AND category = 'jeans' ORDER BY price;</code></pre><!-- /wp:code -->
<!-- wp:paragraph --><p>Вопросы? Пишите в WhatsApp: +7 (701) 123-45-67 или на <a href="mailto:shop@romashka.kz">shop@romashka.kz</a>. Режим работы 10:00–21:00, без выходных. 5 > 3, а 50% < 100% :)</p><!-- /wp:paragraph -->"""


def step(name):
    def wrap(fn):
        def run(*a, **kw):
            t = time.time()
            try:
                fn(*a, **kw)
                results.append({"step": name, "ok": True, "ms": round((time.time() - t) * 1000)})
            except Exception as exc:
                results.append({"step": name, "ok": False, "error": f"{exc.__class__.__name__}: {str(exc)[:300]}"})
        return run
    return wrap


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox", "--disable-background-networking", "--disable-sync",
                                                                  "--no-first-run", "--disable-component-update"])
        def local_only(route):
            host = route.request.url.split("/")[2].split(":")[0]
            return route.continue_() if host in ("wp.localhost", "127.0.0.1", "localhost") else route.abort()

        def new_context():
            c = browser.new_context(locale="ru-RU")
            c.route("**/*", local_only)
            return c

        ctx = new_context()
        page = ctx.new_page()
        page.set_default_timeout(30000)
        statuses = []
        page.on("response", lambda r: statuses.append((r.status, r.request.method, r.url[:160]))
                if r.status in (403, 429, 501, 502) else None)

        @step("install WordPress")
        def install():
            page.goto(f"{BASE}/wp-admin/install.php")
            if page.locator("#language-continue").count():
                page.click("#language-continue")
            page.fill("#weblog_title", "Магазин «Ромашка» — Шымкент")
            page.fill("#user_login", USER)
            page.fill("#pass1", PASS)
            if page.locator(".pw-checkbox").is_visible():
                page.check(".pw-checkbox")
            page.fill("#admin_email", "owner@romashka.kz")
            page.click("#submit")
            page.wait_for_selector("text=Log In", timeout=60000)

        @step("log in")
        def login():
            page.goto(f"{BASE}/wp-login.php")
            page.fill("#user_login", USER)
            page.fill("#user_pass", PASS)
            page.click("#wp-submit")
            page.wait_for_url("**/wp-admin/**", wait_until="domcontentloaded")

        @step("quick draft on the dashboard")
        def quick_draft():
            page.goto(f"{BASE}/wp-admin/index.php")
            page.fill("#title", "Новогодняя акция: «-30%» на всё!")
            page.fill("#content", "Не забыть: обновить цены в 1С и выгрузить на сайт до 20.12. Скидка 30% != 50%.")
            page.click("#save-post")
            page.wait_for_timeout(1500)

        @step("open the block editor")
        def editor():
            page.goto(f"{BASE}/wp-admin/post-new.php")
            page.wait_for_selector(".editor-styles-wrapper, iframe[name='editor-canvas']", timeout=60000)
            page.wait_for_timeout(2500)

        def rest(method, route, data=None):
            return page.evaluate("""async ([method, route, data]) => {
                const nonce = (window.wpApiSettings && wpApiSettings.nonce) ||
                              (await (await fetch('/wp-admin/admin-ajax.php?action=rest-nonce')).text());
                const r = await fetch('/?rest_route=' + encodeURIComponent(route).replace(/%2F/g, '/'), {
                    method, headers: {'Content-Type': 'application/json', 'X-WP-Nonce': nonce},
                    body: data ? JSON.stringify(data) : undefined, credentials: 'same-origin'});
                const text = await r.text(); let id = null;
                try { id = JSON.parse(text).id; } catch (e) {}
                return {status: r.status, body: text.slice(0, 300), id};
            }""", [method, route, data])

        @step("publish a sale post with table, embed, Kaspi button, map and SQL sample (REST)")
        def publish():
            r = rest("POST", "/wp/v2/posts", {"title": "Скидки до 50% на Levi's 501 — только до 1 декабря!",
                                             "content": POST_HTML, "status": "publish",
                                             "excerpt": "Скидки на джинсы: 501, 512 и O'Stin. Оплата Kaspi."})
            assert r["status"] in (200, 201), r

        @step("page with Yandex.Metrika counter in a Custom HTML block (REST)")
        def metrika():
            r = rest("POST", "/wp/v2/pages", {"title": "Контакты", "status": "publish",
                                             "content": "<!-- wp:html -->" + METRIKA + "<!-- /wp:html -->"})
            assert r["status"] in (200, 201), r

        @step("autosave and revision of a draft (REST)")
        def autosave():
            r = rest("POST", "/wp/v2/posts", {"title": "Черновик: доставка по Казахстану", "status": "draft",
                                             "content": "<!-- wp:paragraph --><p>Доставка: Алматы 1–2 дня, Астана 2–3 дня; "
                                                        "до 5 кг — 2 000 ₸, свыше — по тарифу «Казпочты».</p><!-- /wp:paragraph -->"})
            assert r["status"] in (200, 201), r
            post_id = r["id"]
            if post_id:
                r2 = rest("POST", f"/wp/v2/posts/{post_id}/autosaves",
                          {"title": "Черновик: доставка", "content": "<p>Обновлено: сроки 1–3 дня &amp; трекинг.</p>"})
                assert r2["status"] in (200, 201), r2

        @step("create category and tags with Cyrillic slugs (REST)")
        def taxonomy():
            assert rest("POST", "/wp/v2/categories", {"name": "Джинсы & брюки", "slug": "джинсы-брюки",
                                                       "description": "Мужские и женские <b>джинсы</b>"})["status"] in (200, 201)
            assert rest("POST", "/wp/v2/tags", {"name": "Чёрная пятница"})["status"] in (200, 201)

        @step("general settings with quotes and HTML entities")
        def settings():
            page.goto(f"{BASE}/wp-admin/options-general.php")
            page.fill("#blogname", "Ромашка — магазин одежды в Шымкенте")
            page.fill("#blogdescription", "Джинсы, куртки & обувь. Доставка по РК — «быстро и честно»")
            page.click("#submit")
            page.wait_for_selector("#setting-error-settings_updated, .notice-success")

        @step("reading and discussion settings")
        def discussion():
            page.goto(f"{BASE}/wp-admin/options-discussion.php")
            page.fill("#moderation_keys", "casino\nкредит онлайн\nhttp://\nviagra")
            page.fill("#disallowed_keys", "<script>\nunion select\n' or 1=1")
            page.click("#submit")
            page.wait_for_selector("#setting-error-settings_updated, .notice-success")

        @step("add a user named O'Brien with a bio")
        def add_user():
            page.goto(f"{BASE}/wp-admin/user-new.php")
            page.fill("#user_login", "manager")
            page.fill("#email", "a.obrien@romashka.kz")
            page.fill("#first_name", "Айдана")
            page.fill("#last_name", "O'Brien-Сейткали")
            page.fill("#pass1", "Another-Strong-2026!")
            page.select_option("#role", "editor")
            page.click("#createusersub")
            page.wait_for_url("**/users.php**", wait_until="domcontentloaded")

        @step("edit own profile: bio with links and markup")
        def profile():
            page.goto(f"{BASE}/wp-admin/profile.php")
            page.fill("#description", "Владелец «Ромашки». <a href=\"https://instagram.com/romashka.kz\">Instagram</a> — "
                                      "пишите в директ. Работаем с 2015 г.; 4.9★ на 2ГИС")
            page.fill("#url", "https://romashka.kz/?utm_source=wp&utm_medium=profile")
            page.click("#submit")
            page.wait_for_selector("#message, .notice-success, .updated")

        @step("upload a product photo")
        def upload():
            png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgYGD4DwABBAEAwS2OUAAAAABJRU5ErkJggg==")
            page.goto(f"{BASE}/wp-admin/media-new.php?browser-uploader")
            page.set_input_files("#async-upload", files=[{"name": "джинсы-501.png", "mimeType": "image/png", "buffer": png}])
            page.click("#html-upload")
            page.wait_for_url("**/upload.php**", wait_until="domcontentloaded")

        @step("activate and deactivate a plugin")
        def plugins():
            page.goto(f"{BASE}/wp-admin/plugins.php")
            link = page.locator("tr[data-slug='hello-dolly'] .activate a, tr[data-slug='hello'] .activate a")
            if link.count():
                link.first.click()
                page.wait_for_selector(".notice-success, #message")
                page.locator("tr[data-slug='hello-dolly'] .deactivate a, tr[data-slug='hello'] .deactivate a").first.click()
                page.wait_for_selector(".notice-success, #message")

        @step("navigation menu for a block theme (REST)")
        def menus():
            r = rest("POST", "/wp/v2/navigation", {"title": "Главное меню (шапка)", "status": "publish",
                     "content": '<!-- wp:navigation-link {"label":"Скидки -50%","url":"/?cat=2","kind":"custom"} /-->'
                                '<!-- wp:navigation-link {"label":"Контакты & доставка","url":"/?page_id=5"} /-->'})
            assert r["status"] in (200, 201), r

        @step("export content")
        def export():
            page.goto(f"{BASE}/wp-admin/export.php")
            with page.expect_download(timeout=30000):
                page.click("#submit")

        @step("visitor: front page, post, search with quotes and symbols")
        def visitor():
            guest = new_context().new_page()
            guest.on("response", lambda r: statuses.append((r.status, r.request.method, r.url[:160]))
                     if r.status in (403, 429, 501, 502) else None)
            guest.goto(f"{BASE}/")
            for q in ["джинсы levi's 501", "кабель ВВГ 3*2.5 \"ГОСТ\"", "куртка -кожа размер 48/50",
                      "скидка 50% & доставка", "<3 подарок для мамы", "select size: M", "O'Stin куртка"]:
                guest.goto(f"{BASE}/?s=" + __import__("urllib.parse").parse.quote(q))
            guest.goto(f"{BASE}/?p=1")
            guest.close()

        @step("visitor: comment in Russian with emoji and a link")
        def comment():
            guest = new_context().new_page()
            guest.on("response", lambda r: statuses.append((r.status, r.request.method, r.url[:160]))
                     if r.status in (403, 429, 501, 502) else None)
            guest.goto(f"{BASE}/?p=1")
            guest.fill("#comment", "Здравствуйте! Есть ли размер 32/34? Брала у вас в прошлом году — супер 😍 "
                                   "Подруга советовала: https://romashka.kz/sale?utm=ig. Цена 9 990 ₸ — это с НДС?")
            guest.fill("#author", "Гүлнұр Әбілқасымқызы")
            guest.fill("#email", "gulnur.a@mail.kz")
            guest.click("#submit")
            guest.wait_for_timeout(1500)
            guest.close()

        @step("moderate: reply to the comment from the admin")
        def reply():
            page.goto(f"{BASE}/wp-admin/edit-comments.php")
            page.wait_for_timeout(1000)
            row = page.locator("#the-comment-list tr").first
            row.hover()
            if row.locator(".reply button, .reply a").count():
                row.locator(".reply button, .reply a").first.click()
                page.fill("#replycontent", "Добрый день! Да, 32/34 есть в наличии. Ждём вас в ТЦ «Мега» 🙂 "
                                           "<a href=\"https://2gis.kz/shymkent\">Как добраться</a>")
                page.click("#replysubmit .save, #replybtn")
                page.wait_for_timeout(2000)

        @step("customizer: change site title live")
        def customizer():
            page.goto(f"{BASE}/wp-admin/customize.php")
            page.wait_for_selector("#customize-controls", timeout=60000)
            page.wait_for_timeout(3000)

        @step("log out")
        def logout():
            page.goto(f"{BASE}/wp-admin/")
            page.goto(page.locator("#wp-admin-bar-logout a").get_attribute("href"))

        if INSTALL:
            install()
        for fn in (login, quick_draft, editor, publish, metrika, autosave, taxonomy, settings, discussion, add_user,
                   profile, upload, plugins, menus, export, visitor, comment, reply, customizer, logout):
            fn()
        browser.close()
        print(json.dumps({"steps": results, "refused": statuses}, ensure_ascii=False, indent=1))


main()
