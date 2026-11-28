"""Siege mode: a proof-of-work gate in front of a site under a bot flood (the idea of Anubis, by Xe Iaso).

When a site is under siege, a visitor without a pass gets a small page whose script finds a number
`n` such that SHA-256(challenge + n) starts with `bits` zero bits (2^18 tries on average: measured in
Chrome, about a second on a laptop and under four seconds with the CPU slowed 4x like a budget phone). The answer earns a signed cookie for two hours and
PASS_PAGES page views; then the browser solves again, invisibly short. Bots that do not run JavaScript
never get through. Honest limit: a bot with native SHA-256 solves in tens of milliseconds, so the gate
taxes a determined attacker rather than stopping one; rate limits and bans still apply behind it.

Nothing is stored: the challenge is an HMAC of the visitor's address, browser and a five-minute
window, and the pass is an HMAC too.

Never gated: the gate's own URL and paths that are server-to-server by nature: payment callbacks,
1C exchange, cron, REST/webhooks (per CMS preset, plus the site's own list), matched only on
requests without repeated query fields (PHP reads the last `route=`, so a second one must not ride
on an exempt first). Files that look static are not exempt (a CMS answers /any/page.css with a full
dynamic 404): without a pass they get a short 503. Search engine crawlers get 503 + Retry-After:
"come back later", which does not hurt rankings during a short siege.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
import threading
from urllib.parse import parse_qs, quote, unquote_plus

from .policy import is_static, normalize_path, php_name

GATE_PATH = "/_aegis/gate"
PASS_COOKIE = "aegis_pass"
WINDOW = 300
PASS_SECONDS = 2 * 3600
PASS_PAGES = 300  # page views per pass, then the browser solves again
DEFAULT_BITS = 18

END = r"(?=$|\?)"  # end of the path, with or without a query
EXEMPT = {
    "generic": [r"^/(?:api|webhook|webhooks|callback|cron)(?:/|" + END + ")", r"^/robots\.txt" + END,
                r"^/favicon\.ico" + END],
    "wordpress": [r"^/wp-cron\.php" + END, r"^/wc-api/", r"^/wp-json/(?:wc|wp-site-health)/", r"^/\?wc-api="],
    "bitrix": [r"^/bitrix/tools/", r"^/bitrix/admin/1c_exchange\.php" + END, r"^/bitrix/services/",
               r"^/bitrix/spread\.php" + END],
    "opencart": [r"^/index\.php\?route=extension/payment/", r"^/index\.php\?route=(?:api|payment)/"],
}


def leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        return bits + 8 - byte.bit_length()
    return bits


class Gate:
    def __init__(self, secret: str | None = None, bits: int = DEFAULT_BITS, preset: str | None = None,
                 exempt: list[str] | tuple[str, ...] = ()):
        self.secret = secret or secrets.token_hex(32)
        self.bits = bits
        patterns = EXEMPT["generic"] + EXEMPT.get(preset or "", []) + list(exempt)
        self._exempt = re.compile("|".join(f"(?:{p})" for p in patterns), re.I)
        self.stats = {"challenged": 0, "passed": 0, "failed": 0}
        self._uses: dict[str, int] = {}  # pass -> page views (bounded below)
        self._lock = threading.Lock()

    # --------------------------------------------------------- crypto --
    def _mac(self, message: str) -> str:
        return hmac.new(self.secret.encode(), message.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def _browser(environ) -> str:
        return hashlib.sha256(environ.get("HTTP_USER_AGENT", "").encode()).hexdigest()[:16]

    def challenge(self, client: str, environ, now: float | None = None, back: int = 0) -> str:
        window = int((now if now is not None else time.time()) // WINDOW) - back
        return self._mac(f"challenge|{window}|{client}|{self._browser(environ)}")[:32]

    def issue_pass(self, client: str, environ, now: float | None = None) -> str:
        expires = int((now if now is not None else time.time()) + PASS_SECONDS)
        return f"v1.{expires}.{self._mac(f'pass|{expires}|{client}|{self._browser(environ)}')}"

    def has_pass(self, client: str, environ, now: float | None = None, count: bool = False) -> bool:
        cookies = environ.get("HTTP_COOKIE", "")
        match = re.search(rf"(?:^|;\s*){PASS_COOKIE}=v1\.(\d{{1,12}})\.([0-9a-f]{{64}})", cookies)
        if not match or int(match.group(1)) < (now if now is not None else time.time()):
            return False
        expected = self._mac(f"pass|{match.group(1)}|{client}|{self._browser(environ)}")
        if not hmac.compare_digest(expected, match.group(2)):
            return False
        if not count:
            return True
        with self._lock:
            if len(self._uses) > 200_000:
                self._uses.clear()  # at worst every holder gets a fresh budget once
            used = self._uses[expected] = self._uses.get(expected, 0) + 1
        return used <= PASS_PAGES

    def solved(self, client: str, environ, challenge: str, nonce: str, now: float | None = None) -> bool:
        if not nonce.isdigit() or len(nonce) > 12:
            return False
        if not any(hmac.compare_digest(challenge, self.challenge(client, environ, now, back)) for back in (0, 1)):
            return False
        return leading_zero_bits(hashlib.sha256(f"{challenge}{nonce}".encode()).digest()) >= self.bits

    # ----------------------------------------------------------- WSGI --
    def exempt(self, environ) -> bool:
        path = environ.get("PATH_INFO", "/") or "/"
        query = environ.get("QUERY_STRING", "")
        if query:
            names = [php_name(unquote_plus(part.split("=", 1)[0])) for part in query.split("&") if part]
            if len(names) != len(set(names)):
                return False  # a repeated field: PHP uses the last one, the exemption looked at the first
        target = normalize_path(path) + ("?" + query if query else "")
        return bool(self._exempt.search(target))

    def __call__(self, environ, start_response, client: str):
        """Answer the request if the gate must; None when the visitor may go on to the site."""
        path = environ.get("PATH_INFO", "/")
        if path == GATE_PATH:
            return self._verify(environ, start_response, client)
        if self.exempt(environ):
            return None
        static = is_static(normalize_path(path or "/"))
        if self.has_pass(client, environ, count=not static):
            return None
        self.stats["challenged"] += 1
        if static or environ.get("REQUEST_METHOD", "GET") not in ("GET", "HEAD") or not _browser_like(environ):
            body = json.dumps({"error": "site under attack, retry shortly",
                               "error_ru": "сайт отражает атаку, повторите чуть позже"}).encode()
            start_response("503 Service Unavailable", [("Content-Type", "application/json"),
                                                       ("Content-Length", str(len(body))), ("Retry-After", "30"),
                                                       ("Cache-Control", "no-store")])
            return [body]
        back = path + ("?" + environ["QUERY_STRING"] if environ.get("QUERY_STRING") else "")
        safe_back = json.dumps(back).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
        page = CHALLENGE_PAGE.format(challenge=self.challenge(client, environ), bits=self.bits,
                                     back=safe_back, gate=GATE_PATH).encode()
        start_response("503 Service Unavailable", [("Content-Type", "text/html; charset=utf-8"),
                                                   ("Content-Length", str(len(page))), ("Retry-After", "5"),
                                                   ("Cache-Control", "no-store"), ("X-Robots-Tag", "noindex")])
        return [page]

    def _verify(self, environ, start_response, client: str):
        q = {k: v[0] for k, v in parse_qs(environ.get("QUERY_STRING", "")).items()}
        back = q.get("r", "/")
        if not back.startswith("/") or back.startswith("//") or "\\" in back:
            back = "/"
        if not self.solved(client, environ, q.get("c", ""), q.get("n", "")):
            self.stats["failed"] += 1
            start_response("303 See Other", [("Location", quote(back, safe="/?&=%#:+,;@!$'()*~.-_")),
                                             ("Content-Length", "0"), ("Cache-Control", "no-store")])
            return [b""]
        self.stats["passed"] += 1
        secure = "; Secure" if (environ.get("HTTP_X_FORWARDED_PROTO") or environ.get("wsgi.url_scheme")) == "https" else ""
        cookie = f"{PASS_COOKIE}={self.issue_pass(client, environ)}; Path=/; Max-Age={PASS_SECONDS}; HttpOnly; " \
                 f"SameSite=Lax{secure}"
        start_response("303 See Other", [("Location", quote(back, safe="/?&=%#:+,;@!$'()*~.-_")),
                                         ("Set-Cookie", cookie), ("Content-Length", "0"), ("Cache-Control", "no-store")])
        return [b""]


def _browser_like(environ) -> bool:
    accept = environ.get("HTTP_ACCEPT", "")
    return "text/html" in accept or accept in ("", "*/*")


# The page: no external resources, works without crypto.subtle (plain http) thanks to a compact SHA-256.
CHALLENGE_PAGE = """<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Проверка браузера</title>
<style>
body{{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.55 system-ui,-apple-system,sans-serif;
background:#f4f6f5;color:#16241d}}
main{{max-width:30em;padding:2em 1.6em;text-align:center}}
.ring{{width:44px;height:44px;margin:0 auto 1.2em;border-radius:50%;border:4px solid #d5ded9;border-top-color:#1f7a55;
animation:s 0.9s linear infinite}}
@keyframes s{{to{{transform:rotate(360deg)}}}}
@media (prefers-reduced-motion:reduce){{.ring{{animation:none;border-top-color:#d5ded9}}}}
h1{{font-size:22px;font-weight:600;margin:0 0 .3em}} p{{margin:.3em 0;color:#4a5a52}} small{{color:#7a8a82}}
</style></head><body><main>
<div class="ring" aria-hidden="true"></div>
<h1>Проверяем, что вы не робот</h1>
<p id="msg">Сайт сейчас отражает атаку ботов. Это займёт пару секунд и больше не повторится сегодня.</p>
<p><small>The site is under a bot attack. Your browser is doing a quick check; this takes a second or two.</small></p>
<noscript><p><b>Включите JavaScript, чтобы продолжить.</b> Please enable JavaScript.</p></noscript>
</main>
<script>
(function(){{
var C="{challenge}",B={bits},BACK={back};
var K=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,
607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,
1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,
338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,
2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,
958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,
3204031479,3329325298];
function sha(s){{var m=[],i,l=s.length;for(i=0;i<l;i++)m[i>>2]|=(s.charCodeAt(i)&255)<<(24-(i%4)*8);
m[l>>2]|=128<<(24-(l%4)*8);m[((l+8>>6)+1)*16-1]=l*8;
var h=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225],w=[],a,b,c,d,e,f,g,k,j,t1,t2;
for(i=0;i<m.length;i+=16){{a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];k=h[7];
for(j=0;j<64;j++){{if(j<16)w[j]=m[i+j]|0;else{{var x=w[j-15],y=w[j-2];
w[j]=(((x>>>7|x<<25)^(x>>>18|x<<14)^(x>>>3))+w[j-7]+((y>>>17|y<<15)^(y>>>19|y<<13)^(y>>>10))+w[j-16])|0;}}
t1=(k+((e>>>6|e<<26)^(e>>>11|e<<21)^(e>>>25|e<<7))+((e&f)^(~e&g))+K[j]+w[j])|0;
t2=(((a>>>2|a<<30)^(a>>>13|a<<19)^(a>>>22|a<<10))+((a&b)^(a&c)^(b&c)))|0;
k=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;}}
h[0]=(h[0]+a)|0;h[1]=(h[1]+b)|0;h[2]=(h[2]+c)|0;h[3]=(h[3]+d)|0;h[4]=(h[4]+e)|0;h[5]=(h[5]+f)|0;h[6]=(h[6]+g)|0;h[7]=(h[7]+k)|0;}}
return h;}}
function zeros(h){{var n=0;for(var i=0;i<8;i++){{var v=h[i]>>>0;if(v===0){{n+=32;continue;}}return n+Math.clz32(v);}}return n;}}
var n=0,t0=Date.now();
function work(){{var end=Date.now()+50;while(Date.now()<end){{for(var r=0;r<500;r++,n++){{if(zeros(sha(C+n))>=B){{
location.replace("{gate}?c="+C+"&n="+n+"&r="+encodeURIComponent(BACK));return;}}}}}}setTimeout(work,0);}}
work();
}})();
</script></body></html>"""
