"""Attack the WordPress lab through Aegis. Each scenario uses its own client address (X-Forwarded-For)."""
import json
import os
import random
import sys
from pathlib import Path

import requests

GW = "http://127.0.0.1:8090"
HOST = {"Host": "wp.localhost:8090"}
out = {}


def client(n):
    s = requests.Session()
    s.headers.update({**HOST, "X-Forwarded-For": f"198.51.100.{n}", "User-Agent": "Mozilla/5.0 (X11; Linux) Chrome/130"})
    return s


def status(r):
    return r.status_code


# 1. Password guessing on wp-login.php, then the same address reads the site.
s = client(1)
codes = [status(s.post(GW + "/wp-login.php", data={"log": "admin", "pwd": f"guess{i}", "wp-submit": "Log In"},
                       allow_redirects=False)) for i in range(40)]
out["brute_force"] = {"attempts": 40, "answered_by_wordpress": sum(c in (200, 302) for c in codes),
                      "refused_429": codes.count(429), "first_refused_at": codes.index(429) + 1 if 429 in codes else None,
                      "site_still_readable": status(s.get(GW + "/?p=1")) == 200}

# 2. XML-RPC system.multicall (hundreds of passwords in one request) and pingback.
s = client(2)
multi = "<?xml version='1.0'?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>" + \
        "".join(f"<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>"
                f"<member><name>params</name><value><array><data><value><string>admin</string></value><value><string>pw{i}"
                f"</string></value></data></array></value></member></struct></value>" for i in range(200)) + \
        "</data></array></value></param></params></methodCall>"
out["xmlrpc_multicall"] = status(s.post(GW + "/xmlrpc.php", data=multi, headers={"Content-Type": "text/xml"}))
ping = "<?xml version='1.0'?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>" \
       "http://169.254.169.254/latest/meta-data/</string></value></param><param><value><string>http://wp.localhost:8090/?p=1" \
       "</string></value></param></params></methodCall>"
out["xmlrpc_pingback"] = status(client(3).post(GW + "/xmlrpc.php", data=ping, headers={"Content-Type": "text/xml"}))

# 3. User enumeration.
out["author_enum"] = status(client(4).get(GW + "/?author=1", allow_redirects=False))
out["rest_users"] = status(client(5).get(GW + "/?rest_route=/wp/v2/users"))
out["rest_users_pretty"] = status(client(6).get(GW + "/wp-json/wp/v2/users"))

# 4. Web shell in uploads, debug log, wp-includes, backups, scanner.
out["upload_shell"] = status(client(7).get(GW + "/wp-content/uploads/2026/11/x.php?cmd=id"))
out["debug_log"] = status(client(8).get(GW + "/wp-content/debug.log"))
out["wp_config_backup"] = status(client(9).get(GW + "/wp-config.php.bak"))
out["wpscan_agent"] = status(client(10).get(GW + "/", headers={"User-Agent": "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)"}))

# 5. Spoofed editor cookie + script in a post (Aegis lets markup through for editors; WordPress must refuse).
s = client(11)
r = s.post(GW + "/?rest_route=/wp/v2/posts", json={"title": "x", "content": "<script>alert(1)</script>", "status": "publish"},
           cookies={"wordpress_logged_in_fake": "admin|1|x|y"})
out["spoofed_editor_post"] = {"status": status(r), "wordpress_answer": r.text[:120]}

# 5b. Bypass attempts from the outside review (round 4): every one must be refused.
forged = {"wordpress_logged_in_x": "admin|1|x|y"}
bypass = {
    "/health/../?author=1": client(13).get(GW + "/health/../?author=1", allow_redirects=False).status_code,
    "?author=1 + forged editor cookie": client(14).get(GW + "/?author=1", cookies=forged, allow_redirects=False).status_code,
    "REST users + forged cookie": client(15).get(GW + "/wp-json/wp/v2/users", cookies=forged).status_code,
    "/index.php?rest_route=/wp/v2/users": client(16).get(GW + "/index.php?rest_route=/wp/v2/users").status_code,
    "/wp-json/wp/v2/users/1": client(17).get(GW + "/wp-json/wp/v2/users/1").status_code,
    "//wp-content//uploads/x.php": client(18).get(GW + "//wp-content//uploads/x.php").status_code,
    "/a/%2e%2e/wp-content/debug.log": client(19).get(GW + "/a/%2e%2e/wp-content/debug.log").status_code,
}
# Filters only signed-in users may use: Aegis lets them through, WordPress itself must refuse them.
r = client(20).get(GW + "/wp-json/wp/v2/users?who=authors", cookies=forged)
bypass["users?who=authors + forged cookie (answered by WordPress)"] = f"{r.status_code} {r.json().get('code', '')}"
s = client(21)
codes = [s.post(GW + "/wp-login.php/x.css", data={"log": "admin", "pwd": f"g{i}"}, allow_redirects=False).status_code
         for i in range(14)]
bypass["password guessing via /wp-login.php/x.css"] = f"refused from attempt {codes.index(429) + 1}" if 429 in codes else "never refused"
import socket as _socket
with _socket.create_connection(("127.0.0.1", 8090), timeout=10) as sock:
    body = b"comment=%3Cscript%3Ealert(1)%3C/script%3E&author=x&email=x@x.kz&comment_post_ID=1"
    chunked = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)
    sock.sendall(b"POST /wp-comments-post.php HTTP/1.1\r\nHost: wp.localhost:8090\r\nX-Forwarded-For: 198.51.100.22\r\n"
                 b"Content-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                 + chunked)
    bypass["chunked comment with <script>"] = int(sock.recv(64).split()[1])
out["bypass_attempts"] = bypass

# 6. Flood: 400 page requests in a minute from one address.
s = client(12)
codes = [status(s.get(GW + f"/?p=1&n={i}")) for i in range(400)]
out["flood"] = {"requests": 400, "ok": codes.count(200), "refused_429": codes.count(429),
                "first_refused_at": codes.index(429) + 1 if 429 in codes else None}

# 7. Real payloads (SecLists) in the search box and the comment form, one address each so bans don't mix.
lists = {
    "sqli": os.environ.get("SECLISTS", "/tmp/realapps/seclists") + "/Fuzzing/Databases/SQLi/Generic-SQLi.txt",
    "xss": os.environ.get("SECLISTS", "/tmp/realapps/seclists") + "/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt",
    "traversal": os.environ.get("SECLISTS", "/tmp/realapps/seclists") + "/Fuzzing/LFI/LFI-Jhaddix.txt",
    "cmd": os.environ.get("SECLISTS", "/tmp/realapps/seclists") + "/Fuzzing/command-injection-commix.txt",
}
random.seed(7)
payload_results = {}
n = 20
for kind, path in lists.items():
    p = Path(path)
    if not p.exists():
        payload_results[kind] = "list missing"
        continue
    lines = [x for x in p.read_text(errors="ignore").splitlines() if x.strip()]
    sample = random.sample(lines, min(150, len(lines)))
    blocked = 0
    for i, payload in enumerate(sample):
        n += 1
        s = client(n % 250 + 1)  # fresh-ish address per payload: measures detection, not bans
        s.headers["X-Forwarded-For"] = f"203.0.113.{n % 250}"
        if i % 2:
            r = s.get(GW + "/", params={"s": payload})
        else:
            r = s.post(GW + "/wp-comments-post.php", data={"comment": payload, "author": "Тест", "email": "t@t.kz",
                                                           "comment_post_ID": "1"}, allow_redirects=False)
        blocked += r.status_code == 403
    payload_results[kind] = {"sent": len(sample), "blocked": blocked, "rate": round(blocked / len(sample), 3)}
out["payloads"] = payload_results
print(json.dumps(out, ensure_ascii=False, indent=1))
