"""Siege mode in real Google Chrome: how long a person waits at the gate, and that the page they wanted opens.

usage: python benchmarks/gate_chrome.py [bits=16] [runs=5]
Needs Playwright and Chrome. Prints JSON: seconds per pass, and whether a script without a browser got in.
"""
import http.client
import json
import socket
import statistics
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from playwright.sync_api import sync_playwright  # noqa: E402

from aegis.gateway import AppSpec, Gateway, serve  # noqa: E402

BITS = int(sys.argv[1]) if len(sys.argv) > 1 else 16
RUNS = int(sys.argv[2]) if len(sys.argv) > 2 else 5


class Shop(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"<html><title>Ромашка</title><h1 id=shop>Каталог {self.path}</h1></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def main():
    origin = ThreadingHTTPServer(("127.0.0.1", 0), Shop)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    gw = Gateway([AppSpec("shop.localhost", f"http://127.0.0.1:{origin.server_address[1]}", ["shop.localhost"],
                          heal="off", options={"preset": "generic", "siege_bits": BITS})])
    serve(gw, port)
    gw.siege("shop.localhost", 30, "lab")
    times = []
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path="/usr/bin/google-chrome",
                                    args=["--no-sandbox", f"--host-resolver-rules=MAP shop.localhost 127.0.0.1"])
        for _ in range(RUNS):
            ctx = browser.new_context()
            page = ctx.new_page()
            t0 = time.time()
            page.goto(f"http://shop.localhost:{port}/catalog/?sort=price")
            page.wait_for_selector("#shop", timeout=120_000)
            times.append(time.time() - t0)
            assert page.inner_text("#shop") == "Каталог /catalog/?sort=price"
            again = time.time()
            page.goto(f"http://shop.localhost:{port}/other/")
            page.wait_for_selector("#shop")
            second = time.time() - again
            ctx.close()
        browser.close()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", "/catalog/", headers={"Host": "shop.localhost", "User-Agent": "python-requests/2.32"})
    script_status = conn.getresponse().status
    print(json.dumps({"bits": BITS, "runs": RUNS, "seconds_median": round(statistics.median(times), 2),
                      "seconds_max": round(max(times), 2), "next_page_seconds": round(second, 3),
                      "script_without_browser": script_status, "gate": gw.gates["shop.localhost"].stats}))


if __name__ == "__main__":
    main()
