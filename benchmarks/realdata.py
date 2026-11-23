"""Shield benchmark on public, third-party data (nothing here was written by the Aegis authors).

    python benchmarks/realdata.py --csic PATH/csic_2010 --seclists PATH/SecLists [--json out.json]

Data (not bundled, fetch it yourself):
  * HTTP DATASET CSIC 2010 (Spanish National Research Council): 36,000 normal and 25,065
    anomalous HTTP requests to an e-commerce app. A public mirror:
    https://github.com/msudol/Web-Application-Attack-Datasets (OriginalDataSets/csic_2010)
  * SecLists (Daniel Miessler et al.), Fuzzing/: payload lists used by pentesters.
    https://github.com/danielmiessler/SecLists

Every request goes through the same code path as production: ShieldCore.collect_inputs()
then ShieldCore.inspect() in block mode, with banning switched off so one request cannot
affect the next.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegis.shield.core import ShieldConfig, ShieldCore  # noqa: E402

SECLISTS = {
    "sqli": ["Fuzzing/Databases/SQLi/Generic-SQLi.txt", "Fuzzing/Databases/SQLi/quick-SQLi.txt",
             "Fuzzing/Databases/SQLi/sqli.auth.bypass.txt", "Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt",
             "Fuzzing/Databases/SQLi/SQLi-Polyglots.txt", "Fuzzing/Databases/SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt"],
    "xss": ["Fuzzing/XSS/human-friendly/XSS-Jhaddix.txt", "Fuzzing/XSS/human-friendly/XSS-BruteLogic.txt",
            "Fuzzing/XSS/human-friendly/XSS-Cheat-Sheet-PortSwigger.txt", "Fuzzing/XSS/Polyglots/XSS-Polyglots.txt"],
    "path_traversal": ["Fuzzing/LFI/LFI-Jhaddix.txt"],
    "command_injection": ["Fuzzing/command-injection-commix.txt", "Fuzzing/UnixAttacks.fuzzdb.txt"],
}


def core() -> ShieldCore:
    return ShieldCore(ShieldConfig(mode="block", ban_after=0, max_incidents=10))


def judge(c: ShieldCore, method: str, path: str, query: str, headers: dict, body: bytes, ctype: str, n: int):
    inputs = c.collect_inputs(path, query, headers, body, ctype)
    t0 = time.perf_counter()
    verdict = c.inspect(f"10.0.{n // 250 % 250}.{n % 250}", method, path, inputs)
    return verdict, (time.perf_counter() - t0) * 1e6


# ------------------------------------------------------------------ CSIC 2010 --

def parse_csic(path: Path):
    """Yield (method, path, query, headers, body) for every request in a CSIC 2010 file."""
    import re

    start = re.compile(r"^(GET|POST|PUT) http")
    block: list[str] = []

    def emit(lines):
        method, url, _ = lines[0].split(" ", 2)
        headers, body, in_body = {}, [], False
        for line in lines[1:]:
            if not in_body and not line.strip():
                in_body = True
                continue
            if in_body:
                if line.strip():
                    body.append(line.strip())
            else:
                k, sep, v = line.partition(": ")
                if sep:
                    headers[k] = v
        parts = urlsplit(url)
        return method, parts.path, parts.query, headers, "".join(body).encode("latin-1")

    for line in path.read_text(encoding="latin-1").splitlines():
        if start.match(line) and block:
            yield emit(block)
            block = []
        if start.match(line) or block:
            block.append(line)
    if block:
        yield emit(block)


CATEGORY_ORDER = ["attack syntax in a value", "backup / config file probe", "renamed parameter",
                  "unusual value, no attack syntax"]
SYNTAX = None


def categorise(root: Path):
    """Label each anomalous CSIC request by what makes it anomalous, using the normal training set."""
    import re

    global SYNTAX
    SYNTAX = re.compile(r"""['"<>;|`$(){}\\]|\.\./|%0[ad]|[\r\n]|--|/\*|\b(select|union|script)\b""", re.I)
    names, paths, values = set(), set(), {}
    for _, path, query, _, body in parse_csic(root / "normalTrafficTraining.txt"):
        paths.add(path)
        for k, v in parse_qsl(query or body.decode("latin-1"), encoding="latin-1"):
            names.add(k)
            values.setdefault(k, set()).add(v)

    def label(path, query, body):
        pairs = parse_qsl(query or body.decode("latin-1"), encoding="latin-1")
        if any(SYNTAX.search(v) for _, v in pairs):
            return "attack syntax in a value"
        if path not in paths:
            return "backup / config file probe"
        if any(k not in names for k, _ in pairs):
            return "renamed parameter"
        return "unusual value, no attack syntax"
    return label


def run_csic(root: Path) -> dict:
    out = {}
    for name, label in (("normalTrafficTraining.txt", "normal_training"), ("normalTrafficTest.txt", "normal_test")):
        c, total, flagged, times, examples = core(), 0, 0, [], []
        for i, (method, path, query, headers, body) in enumerate(parse_csic(root / name)):
            verdict, us = judge(c, method, path, query, {k.lower(): v for k, v in headers.items()}, body,
                                headers.get("Content-Type", ""), i)
            total += 1
            times.append(us)
            if verdict.blocked:
                flagged += 1
                if verdict.incident and len(examples) < 20:
                    examples.append(f"{verdict.incident.param}={verdict.incident.payload[:90]}")
        out[label] = {"requests": total, "flagged": flagged, "examples": examples,
                      "median_us": statistics.median(times), "p99_us": sorted(times)[int(len(times) * 0.99)]}
    label = categorise(root)
    c, cats, hits, classes = core(), Counter(), Counter(), Counter()
    for i, (method, path, query, headers, body) in enumerate(parse_csic(root / "anomalousTrafficTest.txt")):
        cat = label(path, query, body)
        verdict, _ = judge(c, method, path, query, {k.lower(): v for k, v in headers.items()}, body,
                           headers.get("Content-Type", ""), i)
        cats[cat] += 1
        if verdict.blocked:
            hits[cat] += 1
            if verdict.incident:
                classes[verdict.incident.attack_type] += 1
    out["anomalous"] = {"requests": sum(cats.values()), "flagged": sum(hits.values()),
                        "by_category": {k: [hits[k], cats[k]] for k in CATEGORY_ORDER}, "classes": dict(classes)}
    return out


def run_csic_profile(root: Path, strict: bool) -> dict:
    """Learn the normal training half through the shield, then judge the held-out test half and the anomalies."""
    from aegis.shield.core import ShieldConfig, ShieldCore

    def requests(name):
        for method, path, query, headers, body in parse_csic(root / name):
            hdrs = {k.lower(): v for k, v in headers.items()}
            yield method, path, ShieldCore.collect_inputs(path, query, hdrs, body, headers.get("Content-Type", ""))

    training = list(requests("normalTrafficTraining.txt"))
    c = ShieldCore(ShieldConfig(mode="block", ban_after=0, max_incidents=10, learn=len(training), strict_paths=strict))
    for i, (method, path, inputs) in enumerate(training):
        c.inspect(f"10.1.{i // 250 % 250}.{i % 250}", method, path, inputs)
    flagged = sum(c.inspect("10.2.0.1", m, p, inp).blocked for m, p, inp in requests("normalTrafficTest.txt"))
    label = categorise(root)
    cats, hits = Counter(), Counter()
    for i, (method, path, query, headers, body) in enumerate(parse_csic(root / "anomalousTrafficTest.txt")):
        cat = label(path, query, body)
        inputs = ShieldCore.collect_inputs(path, query, {k.lower(): v for k, v in headers.items()}, body,
                                           headers.get("Content-Type", ""))
        cats[cat] += 1
        hits[cat] += c.inspect(f"10.3.{i // 250 % 250}.{i % 250}", method, path, inputs).blocked
    return {"normal_test_flagged": flagged, "normal_test": 36000, "endpoints": len(c.profile.endpoints),
            "by_category": {k: [hits[k], cats[k]] for k in CATEGORY_ORDER},
            "flagged": sum(hits.values()), "requests": sum(cats.values())}


HELDOUT = {
    "sqli": ["Fuzzing/Databases/SQLi/MSSQL.fuzzdb.txt", "Fuzzing/Databases/SQLi/MySQL.fuzzdb.txt",
             "Fuzzing/Databases/SQLi/Oracle.fuzzdb.txt"],
    "xss": ["Fuzzing/XSS/human-friendly/XSS-OFJAAAH.txt", "Fuzzing/XSS/human-friendly/XSS-Bypass-Strings-BruteLogic.txt",
            "Fuzzing/XSS/human-friendly/XSS-EnDe-evation.txt", "Fuzzing/XSS/human-friendly/XSS-payloadbox.txt",
            "Fuzzing/XSS/human-friendly/XSS-RSNAKE.txt",
            "Fuzzing/XSS/human-friendly/xss-without-parentheses-semi-colons-portswigger.txt",
            "Fuzzing/XSS/human-friendly/XSS-Somdev.txt"],
    "path_traversal": ["Fuzzing/LFI/LFI-LFISuite-pathtotest.txt", "Fuzzing/LFI/LFI-linux-and-windows_by-1N3@CrowdShield.txt"],
}


def run_lists(root: Path, lists: dict) -> dict:
    out = {}
    for attack, files in lists.items():
        for rel in files:
            path = root / rel
            if not path.exists():
                continue
            payloads = [p for p in path.read_text(encoding="utf-8", errors="replace").splitlines() if p.strip()]
            c, hit = core(), 0
            for i, payload in enumerate(payloads):
                verdict, _ = judge(c, "GET", "/search", urlencode({"q": payload}), {}, b"", "", i)
                hit += verdict.blocked
            out[rel.split("/")[-1]] = {"class": attack, "payloads": len(payloads), "detected": hit}
    return out


def pct(a, b):
    return f"{a / b:.1%}" if b else "n/a"


def markdown(result: dict, baseline: dict) -> str:
    L = ["# Aegis Shield on real, third-party data", "",
         "Nothing below was written by the Aegis authors. Reproduce with "
         "`python benchmarks/realdata.py --csic ... --seclists ... --markdown REAL_WORLD.md`.", ""]
    csic, bcsic = result.get("csic_2010"), baseline.get("csic_2010")
    if csic and bcsic:
        nt, ns = csic["normal_training"], csic["normal_test"]
        L += ["## 1. CSIC 2010: false alarms on 72,000 normal requests", "",
              "HTTP DATASET CSIC 2010 (Spanish National Research Council): traffic to an e-commerce app with Spanish",
              "names, addresses, passwords and product names. The training half was used to check new signatures for",
              "false alarms. **The test half was never looked at while tuning.**", "",
              "| Set | v1.0 (before) | Now |", "| --- | --- | --- |",
              f"| Normal, training (36,000) | {bcsic['normal_training']['flagged']} flagged | **{nt['flagged']} flagged** |",
              f"| Normal, test (36,000, held out) | {bcsic['normal_test']['flagged']} flagged | **{ns['flagged']} flagged** |",
              f"| Inspection time per request | | median {ns['median_us']:.0f} µs, p99 {ns['p99_us']:.0f} µs |", ""]
        a, ba = csic["anomalous"], bcsic["anomalous"]
        L += ["## 2. CSIC 2010: 25,065 anomalous requests", "",
              "CSIC labels a request anomalous for many reasons, not only injections. Aegis splits them by what is",
              "anomalous (labels derived from the normal training set). These requests were used while tuning, so",
              "the \"now\" column is not a held-out number.", "",
              "| What is anomalous | Requests | v1.0 | Now |", "| --- | --- | --- | --- |"]
        for cat in CATEGORY_ORDER:
            hit, total = a["by_category"][cat]
            L.append(f"| {cat} | {total:,} | {pct(*ba['by_category'][cat])} | **{pct(hit, total)}** |")
        L += [f"| **All anomalous** | {a['requests']:,} | {pct(ba['flagged'], ba['requests'])} | "
              f"**{pct(a['flagged'], a['requests'])}** |", "",
              "\"Renamed parameter\" and \"unusual value\" requests mostly carry no attack syntax (`idA=2` instead of",
              "`id=2`, a password that is merely odd). Catching those needs a model of the app's normal traffic, which",
              "is anomaly detection, not signatures. Aegis does not try, so it does not block real users for them either.", ""]
    prof = result.get("csic_profile")
    if prof:
        d, st = prof["default"], prof["strict_paths"]
        L += ["## 2b. CSIC 2010 with a learned traffic profile", "",
              "Signatures only know attack syntax. With `learn=N` the shield also learns, per endpoint, which",
              "parameters arrive, which characters each one holds and how long it gets, then flags what is unusual",
              "(a positive security model). Here it learned the 36,000 requests of the **training** half and was then",
              "judged on the **test** half and on the anomalies, which it never saw.", "",
              "| | Signatures only | + learned profile | + strict paths |", "| --- | --- | --- | --- |",
              f"| Normal test requests flagged (of 36,000) | {csic['normal_test']['flagged']} | "
              f"**{d['normal_test_flagged']}** | **{st['normal_test_flagged']}** |"]
        for cat in CATEGORY_ORDER:
            L.append(f"| {cat} | {pct(*csic['anomalous']['by_category'][cat])} | **{pct(*d['by_category'][cat])}** | "
                     f"**{pct(*st['by_category'][cat])}** |")
        L += [f"| **All anomalous (25,065)** | {pct(csic['anomalous']['flagged'], csic['anomalous']['requests'])} | "
              f"**{pct(d['flagged'], d['requests'])}** | **{pct(st['flagged'], st['requests'])}** |", "",
              "CSIC is a closed, generated shop, which is the best case for a learned profile: every legitimate page and",
              "parameter shows up during learning. A real site changes, so the profile is per app, kept on disk, and",
              "relearned after deploys; password fields keep their relaxed threshold, and tracking parameters",
              "(`utm_*`, `fbclid`…) are ignored. `strict_paths` suits APIs and closed apps, not sites that add pages often.", ""]
    for key, title, note in (("seclists_dev", "## 3. SecLists payload lists used while tuning",
                              "Misses in these lists were studied, so these numbers are an upper bound."),
                             ("seclists_heldout", "## 4. SecLists payload lists held out",
                              "Measured once before tuning, then once after. Their misses were never looked at.")):
        rows = result.get(key)
        if not rows:
            continue
        L += [title, "", note, "", "| List | Class | Payloads | v1.0 | Now |", "| --- | --- | --- | --- | --- |"]
        for name, r in rows.items():
            before = baseline.get(key, {}).get(name)
            L.append(f"| {name} | {r['class']} | {r['payloads']:,} | {pct(before['detected'], before['payloads']) if before else ''} | "
                     f"**{pct(r['detected'], r['payloads'])}** |")
        L.append("")
    extra = Path(__file__).parent / "data" / "real_apps_results.md"
    if extra.exists():
        L += [extra.read_text(encoding="utf-8").rstrip(), ""]
    L += ["## Reading these numbers", "",
          "- Single-token fuzz entries (`update`, `&`, `!`, `asc`) are in the lists but are not attacks on their own;",
          "  blocking them would block real users. They count as misses here.",
          "- A signature shield is the first layer. The point of Aegis is the second one: the hole in the code is",
          "  patched, so a payload the shield misses still finds nothing to exploit.", ""]
    return "\n".join(L)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csic", type=Path)
    ap.add_argument("--seclists", type=Path)
    ap.add_argument("--json", type=Path)
    ap.add_argument("--markdown", type=Path)
    args = ap.parse_args()
    result = {}
    if args.csic:
        result["csic_2010"] = run_csic(args.csic)
        result["csic_profile"] = {"default": run_csic_profile(args.csic, False),
                                  "strict_paths": run_csic_profile(args.csic, True)}
    if args.seclists:
        result["seclists_dev"] = run_lists(args.seclists, SECLISTS)
        result["seclists_heldout"] = run_lists(args.seclists, HELDOUT)
    print(json.dumps(result, indent=1, ensure_ascii=False)[:4000])
    if args.json:
        args.json.write_text(json.dumps(result, indent=1, ensure_ascii=False))
    if args.markdown:
        baseline = json.loads((Path(__file__).parent / "data" / "realdata_v1_baseline.json").read_text())
        args.markdown.write_text(markdown(result, baseline), encoding="utf-8")


if __name__ == "__main__":
    main()
