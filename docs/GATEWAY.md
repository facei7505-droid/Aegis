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
