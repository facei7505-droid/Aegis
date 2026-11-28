"""Site policies: what is normal for a given CMS, what is closed off, and what counts as a login.

Signatures alone break real sites. On a measured WordPress session (2,239 requests of ordinary
admin work in real Chrome) they flagged 3: a post with a Kaspi button and a map iframe, a page with
a Yandex.Metrika counter, and the comment blocklist the owner filled with attack strings. All three
are editors doing their job, so a preset says where markup is the content, and only while the
request carries the CMS's sign of a logged-in editor. Everything else stays fully inspected.

A preset also carries:
  * virtual patches: requests that are never legitimate on that CMS (exploited endpoints, PHP in
    upload folders, user enumeration), refused outright;
  * login endpoints: failed-password floods are cut per client address, without banning the
    address from the rest of the site (mobile carriers in Kazakhstan put many people behind one IP).
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from urllib.parse import unquote

ALL = frozenset({"*"})
MARKUP = frozenset({"xss"})
STATIC = re.compile(r"\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|mp3|"
                    r"ogg|wav|pdf|zip|txt|xml|json)$", re.I)
SCRIPT_IN_PATH = re.compile(r"\.(?:php\d?|phtml|asp|aspx|jsp|cgi|pl)(?:/|$)", re.I)  # /wp-login.php/x.css runs PHP


def is_static(path: str) -> bool:
    return bool(STATIC.search(path)) and not SCRIPT_IN_PATH.search(path)
PASSWORD_FIELDS = {"password", "pass", "pwd", "passwd", "user_password", "login_password", "password[]",
                   "loginform[password]", "customer[password]"}


@dataclass(frozen=True)
class Marker:
    """A hint that the request comes from a signed-in editor. Anyone can send it, so it only ever
    relaxes markup checks on admin endpoints the CMS itself refuses without a real login; it never
    switches a virtual patch off."""
    cookie_prefix: str | None = None
    param: str | None = None          # query or form field, e.g. Bitrix `sessid`, OpenCart `user_token`

    def present(self, req: "Request") -> bool:
        if self.cookie_prefix and any(n.startswith(self.cookie_prefix) for n in req.cookies):
            return True
        return bool(self.param and self.param in req.params)


@dataclass(frozen=True)
class Trust:
    """On these paths, these fields may contain what the listed attack classes look like."""
    path: re.Pattern
    fields: tuple[str, ...]
    ignore: frozenset[str] = MARKUP
    markers: tuple[Marker, ...] = ()

    def applies(self, req: "Request") -> bool:
        if not self.path.search(req.route):
            return False
        if self.markers and req.editor is not None:  # the site's connector signs editors: only that counts
            return req.editor
        return not self.markers or any(m.present(req) for m in self.markers)

    def covers(self, name: str) -> bool:
        low = name.lower()
        return any(fnmatch.fnmatchcase(low, f) for f in self.fields)


@dataclass(frozen=True)
class Patch:
    """A request that is never legitimate on this CMS."""
    name: str
    reason: str                        # shown to the owner (Russian)
    path: re.Pattern
    methods: frozenset[str] | None = None
    param: re.Pattern | None = None    # some query/form field name must match
    value: re.Pattern | None = None    # some body or field value must match (e.g. an XML-RPC method)
    unless_param: re.Pattern | None = None  # ...not when a field with this name...
    unless_value: re.Pattern | None = None  # ...has this value (filters the CMS only allows signed-in users)

    def matches(self, req: "Request") -> bool:
        if self.methods and req.method not in self.methods:
            return False
        if not self.path.search(req.route):
            return False
        if self.param and not any(self.param.search(n) for n in req.params):
            return False
        if self.value and not any(self.value.search(t) for t in req.texts):
            return False
        if self.unless_param and any(self.unless_param.search(n) and (self.unless_value is None or
                                                                      self.unless_value.search(v or ""))
                                     for n, v in req.params.items()):
            return False
        return True


@dataclass(frozen=True)
class Login:
    path: re.Pattern
    methods: frozenset[str] = frozenset({"POST"})
    field: str | None = None           # a field that must be present (e.g. WordPress `log`)

    def matches(self, req: "Request") -> bool:
        return (req.method in self.methods and bool(self.path.search(req.route))
                and (self.field is None or self.field in req.params))


@dataclass
class Request:
    method: str
    path: str
    params: dict[str, str]             # query and form fields, first value
    cookies: set[str]
    route: str                         # path, or the REST route a CMS reads from the query
    texts: list[str] = field(default_factory=list)  # body and field values (first 64 KB)
    editor: bool | None = None         # signed editor pass verified (None: the site has no connector)

    @classmethod
    def build(cls, method: str, path: str, inputs: list[tuple[str, str, str]]) -> "Request":
        params: dict[str, str] = {}
        cookies: set[str] = set()
        texts: list[str] = []
        budget = 64 * 1024
        for location, name, value in inputs:
            if location in ("query", "form", "json", "multipart"):
                params.setdefault(name, value)
            elif location == "cookie":
                cookies.add(name)
            if location in ("form", "json", "body") and budget > 0:
                texts.append(value[:budget])
                budget -= len(value)
        route = normalize_path(path)
        rest = params.get("rest_route")
        if rest:  # WordPress serves ?rest_route= on any front-end URL, not only on /
            route = "/wp-json" + normalize_path(rest)
        return cls(method.upper(), path, params, cookies, route, texts)

    def has_password(self) -> bool:
        return any(n.lower() in PASSWORD_FIELDS or n.lower().endswith(("[password]", "_password"))
                   for n in self.params)


@dataclass
class Preset:
    name: str
    title: str
    trust: list[Trust] = field(default_factory=list)
    patches: list[Patch] = field(default_factory=list)
    logins: list[Login] = field(default_factory=list)
    generic_logins: bool = True        # also count any POST carrying a password field

    def ignored(self, req: Request) -> dict[str, frozenset[str]]:
        """Field name -> attack classes not to block on this request."""
        rules = [t for t in self.trust if t.applies(req)]
        if not rules:
            return {}
        out: dict[str, frozenset[str]] = {}
        for name in req.params:
            for t in rules:
                if t.covers(name):
                    out[name] = out.get(name, frozenset()) | t.ignore
        return out

    def patch(self, req: Request) -> Patch | None:
        return next((p for p in self.patches if p.matches(req)), None)

    def is_login(self, req: Request) -> bool:
        if any(lg.matches(req) for lg in self.logins):
            return True
        return self.generic_logins and req.method == "POST" and req.has_password()


def normalize_path(path: str) -> str:
    """The path a web server will actually serve, for matching rules against it.

    Percent-decoding (up to three layers), backslashes, `;params`, repeated slashes and `.`/`..`
    segments are all resolved, so `/health/../x`, `//bitrix//tools/vote/uf.php` and
    `/a/%2e%2e/wp-content/uploads/x.php` are judged as the path the origin will run."""
    out = path or "/"
    for _ in range(3):
        decoded = unquote(out)
        if decoded == out:
            break
        out = decoded
    out = out.replace("\\", "/").split("?", 1)[0]
    parts: list[str] = []
    for seg in out.split("/"):
        seg = seg.split(";", 1)[0].rstrip(" .") if seg not in (".", "..") else seg
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    trailing = "/" if (out.endswith("/") and parts) else ""
    return "/" + "/".join(parts) + trailing


def _re(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.I)


# ---------------------------------------------------------------- generic --

UPLOAD_PHP = Patch("php-in-uploads", "запуск PHP-файла из папки загрузок (типичный веб-шелл)",
                   _re(r"/(?:upload|uploads|files|images|image|media|userfiles|wp-content/uploads)/.*\.(?:php\d?|phtml|phar|pht|shtml)(?:$|[/?])"))
SHELLS = Patch("webshell-names", "обращение к известному веб-шеллу",
               _re(r"/(?:wso|c99|r57|b374k|alfa|shell|cmd|adminer)\d*\.php$"))

GENERIC = Preset("generic", "Любой сайт", patches=[UPLOAD_PHP, SHELLS])

# -------------------------------------------------------------- WordPress --

WP_EDITOR = Marker(cookie_prefix="wordpress_logged_in_")
WP_CONTENT_FIELDS = ("content", "content.raw", "title", "title.raw", "excerpt", "excerpt.raw", "description",
                     "caption", "caption.raw", "meta.*", "styles.*", "settings.*", "post_content", "post_title",
                     "post_excerpt", "excerpt", "newcontent_disabled", "data[wp_autosave][*]", "replycontent",
                     "customized", "widget-*", "sidebars[*]", "nav_menu*", "menu-item-*", "attachments[*]")

WORDPRESS = Preset(
    "wordpress", "WordPress",
    trust=[
        Trust(_re(r"/wp-json/wp/v2/(?:posts|pages|blocks|templates|template-parts|navigation|global-styles|"
                  r"widgets|sidebars|menu-items|menus|comments|media|users/(?:me|\d+)|wp_block|font-families|"
                  r"wp_pattern_category)"), WP_CONTENT_FIELDS, MARKUP, (WP_EDITOR,)),
        Trust(_re(r"/wp-admin/(?:post|post-new|edit|admin-ajax|async-upload|media|upload|profile|user-edit|"
                  r"customize|widgets|nav-menus|admin-post|edit-comments|comment)\.php"),
              WP_CONTENT_FIELDS + ("comment", "content", "description", "blogname", "blogdescription"),
              MARKUP, (WP_EDITOR,)),
        # Settings where owners type the very strings they want to keep out (comment blocklists).
        Trust(_re(r"/wp-admin/options(?:-discussion)?\.php"), ("moderation_keys", "disallowed_keys", "blacklist_keys"),
              ALL, (WP_EDITOR,)),
        Trust(_re(r"/wp-admin/options(?:-general)?\.php"), ("blogname", "blogdescription"), MARKUP, (WP_EDITOR,)),
    ],
    patches=[
        UPLOAD_PHP, SHELLS,
        # A cookie name proves nothing to a proxy (anyone can send one), so these are unconditional.
        Patch("wp-user-enum", "перебор имён пользователей WordPress (?author=N)", _re(r"^/(?:index\.php/?)?$"),
              frozenset({"GET", "HEAD"}), _re(r"^author$")),
        # The block editor lists authors with ?who=authors or context=edit: WordPress itself refuses
        # those filters to anyone who is not signed in, so they may pass.
        Patch("wp-rest-users", "выгрузка пользователей через REST API", _re(r"^/wp-json/wp/v2/users(?:/\d+)?/?$"),
              frozenset({"GET", "HEAD"}), None, unless_param=_re(r"^(?:who|capabilities(?:\[\])?)$|^context$"),
              unless_value=_re(r"^(?:authors|edit|edit_posts)$")),
        Patch("wp-xmlrpc-multicall", "подбор паролей пачками и pingback-атаки через xmlrpc.php",
              _re(r"/xmlrpc\.php$"), frozenset({"POST"}),
              value=_re(r"<methodName>\s*(?:system\.multicall|pingback\.ping)\s*</methodName>")),
        Patch("wp-debug-log", "чтение журнала ошибок WordPress", _re(r"/wp-content/debug\.log$")),
        Patch("wp-includes-php", "прямой запуск служебных файлов WordPress", _re(r"^/wp-includes/(?!js/tinymce/).+\.php$")),
    ],
    logins=[Login(_re(r"/wp-login\.php(?:/|$)"), field="log"), Login(_re(r"/xmlrpc\.php(?:/|$)"))],
)

# ---------------------------------------------------------------- Bitrix --

BX_SESSION = Marker(param="sessid")
BX_CONTENT_FIELDS = ("detail_text", "preview_text", "description", "content", "text", "body", "filesrc", "message",
                     "prop[*]", "property_*", "settings[*]", "ufcrm_*", "template", "code")

BITRIX = Preset(
    "bitrix", "1С-Битрикс",
    trust=[Trust(_re(r"^/bitrix/admin/.+\.php"), BX_CONTENT_FIELDS, MARKUP, (BX_SESSION,))],
    patches=[
        UPLOAD_PHP, SHELLS,
        # CVE-2022-27228 (vote module, unauthenticated RCE, mass defacements in 2023) and the
        # html_editor_action.php file write: 1C-Bitrix advises blocking POST to both when unpatched.
        Patch("bx-cve-2022-27228", "эксплойт CVE-2022-27228 (модуль опросов Битрикса, удалённое выполнение кода)",
              _re(r"^/bitrix/tools/vote/uf\.php$"), frozenset({"POST"})),
        Patch("bx-html-editor-write", "запись файлов через html_editor_action.php (взломы сайтов на Битриксе)",
              _re(r"^/bitrix/tools/html_editor_action\.php$"), frozenset({"POST"})),
        Patch("bx-attach-events", "подмена обработчиков загрузки Битрикса (attachId[...][events])",
              _re(r"^/bitrix/"), None, _re(r"\[events\]")),
        Patch("bx-known-backdoors", "обращение к известному бэкдору Битрикса",
              _re(r"^/bitrix/tools/(?:spread|send_trait_imap|\.cas|\.cas\.tmp)\.php$")),
        Patch("bx-config", "чтение настроек Битрикса", _re(r"^/bitrix/(?:\.settings(?:_extra)?\.php|php_interface/dbconn\.php)"
                                                          r"(?:\.|~|$)")),
        Patch("bx-backup", "скачивание резервной копии сайта", _re(r"^/bitrix/backup/")),
    ],
    logins=[Login(_re(r"."), field="USER_PASSWORD"), Login(_re(r"/bitrix/admin/"), field="AUTH_FORM")],
)

# -------------------------------------------------------------- OpenCart --

OC_ADMIN = Marker(param="user_token")
OPENCART = Preset(
    "opencart", "OpenCart",
    trust=[Trust(_re(r"/admin/index\.php"), ("*_description[*][description]", "*description*", "config_*",
                                               "module_*", "*[description]"), MARKUP, (OC_ADMIN,))],
    patches=[
        UPLOAD_PHP, SHELLS,
        Patch("oc-install", "обращение к установщику OpenCart, оставленному на сервере", _re(r"^/install/")),
        Patch("oc-storage", "чтение служебных файлов OpenCart", _re(r"^/system/(?:storage|config|logs)/")),
    ],
    logins=[Login(_re(r"/admin/(?:index\.php)?$"), field="password")],
)

PRESETS = {p.name: p for p in (GENERIC, WORDPRESS, BITRIX, OPENCART)}


def preset(name: str | None) -> Preset | None:
    if not name:
        return None
    try:
        return PRESETS[name.lower()]
    except KeyError:
        raise ValueError(f"unknown preset {name!r}; choose from {', '.join(PRESETS)}") from None
