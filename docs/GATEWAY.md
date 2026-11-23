# Aegis Gateway: protect any HTTP apps from one server

The gateway is a reverse proxy with an Aegis shield (and, for Python apps, a healer) per application.
Apps in any language can sit behind it. Code healing needs the app's Python source.

```
browser / attacker ──► Aegis Gateway :8080 ──► shop   http://127.0.0.1:5101
                                         ├─► dsvw   http://127.0.0.1:5102
                                         └─► legacy http://127.0.0.1:3000  (Node, PHP… shield only)
dashboard: http://localhost:8080/
```

## Config

```toml
# gateway.toml
[[app]]
name = "shop"
upstream = "http://127.0.0.1:5101"   # where the app really listens (keep it on 127.0.0.1)
hosts = ["shop.localhost"]           # route by Host header
listen = 8081                        # and/or give it its own gateway port
source = "./shop"                    # Python source: enables healing
shield = "block"                     # block | monitor
heal = "propose"                     # propose (write .diff) | auto (patch the file) | off

[[app]]
name = "legacy"
upstream = "http://127.0.0.1:3000"
listen = 8082
heal = "off"                         # not Python: the shield still protects it
options = { ban_after = 5 }          # any ShieldConfig setting
```

```bash
aegis gateway -c gateway.toml --port 8080 --log-dir logs
```

- `*.localhost` names resolve to 127.0.0.1 in Chrome, Edge, Firefox and curl, so `http://shop.localhost:8080` works without editing hosts files. On a server, point real DNS names at the gateway and list them in `hosts`.
- The gateway forwards the request target byte for byte, adds `X-Forwarded-For/Host/Proto`, rewrites redirects that point at the hidden upstream, and answers 502 if an app is down.
- In `auto` mode the patch is written to the source file; the app process must be restarted to run it (`aegis range` does that for you). In production keep `propose` and ship the `.diff` like any other change.
- Bind the gateway to `127.0.0.1` (default) unless it sits behind your TLS proxy. If it does, set `options = { trust_proxy = true }` so the real client address is used.
- Bodies over 1 MB are refused unless they are binary media (images, archives, `octet-stream`), so uploads keep working. If an app reads every body as a form whatever its type, set `options = { binary_uploads = false }`.

## Learning normal traffic

```toml
options = { learn = 2000 }          # learn 2,000 clean requests, then also flag what is unusual for this app
# options = { learn = 2000, strict_paths = true }   # APIs and closed apps: unknown paths too
```

The profile is kept in `--log-dir` (`<app>.profile.json`) and survives restarts. Delete it after a big release so the
gateway relearns. On CSIC 2010 this took anomaly detection from 30% to 72% (84% with strict paths) for 2 false alarms
in 36,000 normal requests; a changing real site will see more false alarms than that closed test shop.

## Canary: patches must keep real traffic working

For every app the gateway can start (`command`, with `{port}` where the port goes, and `cwd`), a patch is accepted only
after a canary run: the app folder is copied, the patch is written into the copy, the copy starts on a free port, and
the last 30 distinct clean GET/HEAD requests are replayed against the copy and the live app. A server error, a new
4xx or a page that changed beyond small differences rejects the patch. If the live app answered the attack itself
(monitor mode), the attack is replayed against the copy only, and the dashboard says whether the answer changed.

```
search() patched (AEG001) in 478 ms · canary: 5 real request(s) replayed, all as before; the attack now gets a different answer
```

The copy works on copies of the app's files, so replays never touch real data. Apps whose state lives elsewhere (a
shared database) should keep `heal = "propose"`: they get no canary and the diff goes to a human.

## Aegis Range: the ready-made lab

```bash
aegis range            # clones DSVW and vulpy (pinned commits), starts all apps and the gateway
```

| App | URL through the gateway | Try |
| --- | --- | --- |
| VulnShop | http://shop.localhost:8080 or http://localhost:8081 | `/search?q=zzz' UNION SELECT username, password_hash FROM users --` |
| DSVW | http://dsvw.localhost:8080 or http://localhost:8082 | `/?id=2 UNION ALL SELECT NULL, NULL, NULL, (SELECT password FROM users WHERE username='admin')` |
| vulpy | http://vulpy.localhost:8080 or http://localhost:8083 | log in at `/user/login` as `admin' --` with any password |

The range starts in `monitor` + `auto`: the first attack goes through so you can see it work, Aegis patches the code and restarts that app, and the same attack fails from then on. `aegis range --shield block` blocks from the first request. vulpy's MFA pages need `pip install pyotp qrcode`; everything else runs on Flask alone.
