"""Client-ready HTML reports (single self-contained file, print friendly)."""
from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from . import __version__
from .models import SEVERITY_ORDER, Escalation, Finding, Patch

T = {
    "en": {
        "title": "Security report", "generated": "Generated", "project": "Project",
        "findings": "Findings", "critical": "Critical", "high": "High", "medium": "Medium", "low": "Low",
        "auto_fixable": "Auto-fixable", "patched": "Verified patches", "escalated": "Needs a human",
        "severity": "Severity", "issue": "Issue", "location": "Location", "fix": "Fix",
        "auto": "Auto-fix", "manual": "Manual", "patches": "Verified patches",
        "escalations": "Escalated to a human", "why": "Why",
        "none": "No vulnerabilities found.",
        "checks": "Checks passed", "method": "How Aegis works",
        "method_text": "Aegis traces attacker-controlled data (HTTP parameters, cookies, headers, path "
                       "parameters) through the code to dangerous operations. Every automatic patch must pass "
                       "four gates before it is accepted: the file compiles, the vulnerability is gone, no new "
                       "issue appeared, and the project's own tests still pass. Patches proposed by AI go "
                       "through exactly the same gates.",
        "selfheal": "Self-healing loop", "attack": "Attack", "payload": "Payload", "detect": "Detect",
        "heal": "Heal", "status": "Result", "proof": "Proof: attacks replayed after healing",
        "before": "Before", "after": "After", "exploitable": "exploitable", "safe": "neutralised",
        "function": "Legitimate requests", "works": "works", "broken": "fails",
        "kpi_blocked": "Attacks blocked", "kpi_heal": "Mean time to heal", "kpi_after": "Exploitable after",
        "kpi_fp": "False positives", "kpi_found": "Vulnerabilities found",
        "pipeline": ["Detect", "Block", "Locate", "Patch", "Verify", "Replay"],
        "engine_rules": "rules", "engine_ai": "Claude", "ai_note": "AI explanation",
        "demo_sub": "Live attacks against VulnShop, a deliberately vulnerable app, with Aegis Shield in front.",
        "engine": "Engine", "run_time": "Run time", "healed": "healed", "gates": "4 gates",
    },
    "ru": {
        "title": "Отчёт по безопасности", "generated": "Создан", "project": "Проект",
        "findings": "Уязвимости", "critical": "Критические", "high": "Высокие", "medium": "Средние", "low": "Низкие",
        "auto_fixable": "Исправимы автоматически", "patched": "Проверенные патчи", "escalated": "Нужен специалист",
        "severity": "Уровень", "issue": "Проблема", "location": "Где", "fix": "Исправление",
        "auto": "Авто", "manual": "Вручную", "patches": "Проверенные патчи",
        "escalations": "Передано специалисту", "why": "Почему",
        "none": "Уязвимости не найдены.",
        "checks": "Проверки", "method": "Как работает Aegis",
        "method_text": "Aegis отслеживает данные, которые контролирует атакующий (параметры запроса, cookies, "
                       "заголовки, части URL), до опасных операций в коде. Каждый автоматический патч проходит "
                       "четыре проверки: файл компилируется, уязвимость исчезла, новых проблем не появилось, "
                       "тесты проекта проходят. Патчи от AI проходят те же самые проверки.",
        "selfheal": "Цикл самовосстановления", "attack": "Атака", "payload": "Нагрузка", "detect": "Обнаружение",
        "heal": "Лечение", "status": "Итог", "proof": "Доказательство: атаки повторены после лечения",
        "before": "До", "after": "После", "exploitable": "работает", "safe": "обезврежена",
        "function": "Обычные запросы", "works": "работает", "broken": "сломан",
        "kpi_blocked": "Атак заблокировано", "kpi_heal": "Среднее время лечения", "kpi_after": "Уязвимо после",
        "kpi_fp": "Ложные срабатывания", "kpi_found": "Найдено уязвимостей",
        "pipeline": ["Обнаружение", "Блокировка", "Поиск строки", "Патч", "Проверка", "Повтор атаки"],
        "engine_rules": "правила", "engine_ai": "Claude", "ai_note": "Пояснение AI",
        "demo_sub": "Живые атаки на VulnShop — специально уязвимое приложение — с Aegis Shield перед ним.",
        "engine": "Движок", "run_time": "Время прогона", "healed": "вылечено", "gates": "4 проверки",
    },
}

CSS = """
:root{--ink:#0b1220;--ink2:#141d30;--paper:#f5f6f8;--card:#fff;--line:#e5e7eb;--text:#0f172a;--muted:#64748b;
--crit:#dc2626;--high:#ea580c;--med:#ca8a04;--low:#2563eb;--ok:#059669;--okbg:#ecfdf5;--badbg:#fef2f2;
--mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
--sans:Inter,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--paper);color:var(--text);font:15px/1.55 var(--sans)}
.wrap{max-width:1080px;margin:0 auto;padding:0 24px}
header{background:radial-gradient(1200px 400px at 85% -20%,#1e3a5f 0,transparent 60%),var(--ink);color:#e2e8f0;padding:40px 0 92px}
.brand{display:flex;align-items:center;gap:12px;font-weight:600;letter-spacing:.2px;color:#fff}
.brand svg{flex:none}.brand small{color:#94a3b8;font-weight:500;margin-left:6px}
h1{font-size:34px;line-height:1.15;margin:28px 0 8px;color:#fff;letter-spacing:-.5px}
.sub{color:#94a3b8;margin:0;max-width:720px}
.meta{display:flex;flex-wrap:wrap;gap:8px 20px;margin-top:18px;color:#94a3b8;font-size:13px}
.meta b{color:#e2e8f0;font-weight:600}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-top:-60px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 18px 16px;box-shadow:0 1px 2px rgba(15,23,42,.04),0 8px 24px rgba(15,23,42,.06)}
.kpi .v{font-size:30px;font-weight:700;letter-spacing:-.5px;line-height:1.1}
.kpi .l{color:var(--muted);font-size:13px;margin-top:4px}
.kpi.good .v{color:var(--ok)}.kpi.bad .v{color:var(--crit)}
section{margin:36px 0}
h2{font-size:20px;margin:0 0 14px;letter-spacing:-.2px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;overflow-x:auto;overflow-y:hidden}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;font-weight:600;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.4px;padding:12px 16px;border-bottom:1px solid var(--line);background:#fafbfc}
td{padding:12px 16px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
code,.mono{font-family:var(--mono);font-size:12.5px}
.snip{display:block;color:#334155;background:#f8fafc;border:1px solid var(--line);border-radius:8px;padding:6px 8px;margin-top:6px;white-space:pre-wrap;word-break:break-all}
.pill{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:600;white-space:nowrap}
.pill:before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor}
.s-critical{color:var(--crit);background:#fef2f2}.s-high{color:var(--high);background:#fff7ed}
.s-medium{color:var(--med);background:#fefce8}.s-low{color:var(--low);background:#eff6ff}
.ok{color:var(--ok);background:var(--okbg)}.bad{color:var(--crit);background:var(--badbg)}.neutral{color:#475569;background:#f1f5f9}
.muted{color:var(--muted)}.small{font-size:13px}
.pipe{display:grid;grid-template-columns:repeat(6,1fr);gap:0;padding:22px 18px}
.step{position:relative;text-align:center;padding:0 6px}
.step .dot{width:38px;height:38px;border-radius:50%;margin:0 auto 10px;display:grid;place-items:center;background:var(--ink);color:#fff;font-weight:700;font-size:14px;position:relative;z-index:1}
.step:not(:last-child):after{content:"";position:absolute;top:19px;left:calc(50% + 22px);right:calc(-50% + 22px);height:2px;background:linear-gradient(90deg,#cbd5e1,#cbd5e1)}
.step .n{font-weight:600;font-size:13px}.step .t{color:var(--muted);font-size:12px;font-family:var(--mono)}
.patch{border-top:1px solid var(--line);padding:18px}
.patch:first-child{border-top:0}
.patch h3{margin:0 0 4px;font-size:15px}
.diff{margin:12px 0 0;border:1px solid var(--line);border-radius:10px;overflow:auto;background:#0b1220;color:#cbd5e1;font:12.5px/1.6 var(--mono)}
.diff div{padding:0 14px;white-space:pre}
.diff .add{background:rgba(16,185,129,.16);color:#a7f3d0}.diff .del{background:rgba(239,68,68,.16);color:#fecaca}
.diff .hunk{color:#7dd3fc;background:rgba(56,189,248,.08)}.diff .hdr{color:#64748b}
.gates{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.ai{margin-top:8px;padding:8px 10px;border-left:3px solid #8b5cf6;background:#f5f3ff;border-radius:6px;font-size:13px}
footer{color:var(--muted);font-size:13px;padding:30px 0 50px;border-top:1px solid var(--line);margin-top:40px}
@media (max-width:760px){h1{font-size:26px}.pipe{grid-template-columns:repeat(3,1fr);row-gap:18px}
.kpis{grid-template-columns:repeat(2,1fr);gap:10px}.kpi{padding:14px}.kpi .v{font-size:24px}
.wrap{padding:0 16px}
.step:nth-child(3):after{display:none}.grid2{grid-template-columns:1fr}td,th{padding:10px 12px}
.hide-sm{display:none}}
@media print{body{background:#fff}header{padding:24px 0 70px}.kpi,.card{box-shadow:none}.diff{white-space:pre-wrap}}
"""

LOGO = ('<svg width="30" height="30" viewBox="0 0 32 32" aria-hidden="true"><defs><linearGradient id="g" x1="0" y1="0" '
        'x2="1" y2="1"><stop offset="0" stop-color="#34d399"/><stop offset="1" stop-color="#0ea5e9"/></linearGradient>'
        '</defs><path d="M16 2 4 6.5v8.2C4 22.3 9.1 28.4 16 30c6.9-1.6 12-7.7 12-15.3V6.5L16 2Z" fill="url(#g)"/>'
        '<path d="m10.5 16.2 3.8 3.8 7.4-8" fill="none" stroke="#0b1220" stroke-width="2.6" stroke-linecap="round" '
        'stroke-linejoin="round"/></svg>')


def _e(text) -> str:
    return html.escape(str(text if text is not None else ""))


def _sev(sev: str, t: dict) -> str:
    return f'<span class="pill s-{_e(sev)}">{_e(t.get(sev, sev))}</span>'


def _diff_html(diff: str) -> str:
    rows = []
    for line in diff.splitlines():
        cls = "add" if line.startswith("+") and not line.startswith("+++") else \
              "del" if line.startswith("-") and not line.startswith("---") else \
              "hunk" if line.startswith("@@") else "hdr" if line.startswith(("+++", "---")) else ""
        rows.append(f'<div class="{cls}">{_e(line) or "&nbsp;"}</div>')
    return '<div class="diff">' + "".join(rows) + "</div>"


def _rel(path: str, root: str | None) -> str:
    if not root:
        return Path(path).name
    try:
        return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return Path(path).name


def _page(title: str, subtitle: str, meta: list[tuple[str, str]], body: str, lang: str) -> str:
    meta_html = "".join(f"<span>{_e(k)}: <b>{_e(v)}</b></span>" for k, v in meta)
    return f"""<!DOCTYPE html>
<html lang="{lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)}</title><style>{CSS}</style></head><body>
<header><div class="wrap"><div class="brand">{LOGO}<span>Aegis</span><small>v{__version__}</small></div>
<h1>{_e(title)}</h1><p class="sub">{_e(subtitle)}</p><div class="meta">{meta_html}</div></div></header>
<main class="wrap">{body}</main>
<footer><div class="wrap">Aegis v{__version__} · self-healing application security ·
generated {datetime.now().strftime('%Y-%m-%d %H:%M')}</div></footer></body></html>"""


def _kpis(items: list[tuple[str, str, str]]) -> str:
    return '<div class="kpis">' + "".join(
        f'<div class="kpi {cls}"><div class="v">{_e(v)}</div><div class="l">{_e(l)}</div></div>' for v, l, cls in items
    ) + "</div>"


def _findings_table(findings: list[Finding], root: str | None, t: dict) -> str:
    if not findings:
        return f'<div class="card"><table><tr><td>{_e(t["none"])}</td></tr></table></div>'
    rows = []
    for f in sorted(findings, key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), x.file, x.line)):
        cwe = f.cwe.split("-")[-1]
        ai = f'<div class="ai"><b>{_e(t["ai_note"])}:</b> {_e(f.ai_explanation)}</div>' if f.ai_explanation else ""
        fix = f'<span class="pill ok">{_e(t["auto"])}</span>' if f.fixable else f'<span class="pill neutral">{_e(t["manual"])}</span>'
        rows.append(
            f"<tr><td>{_sev(f.severity, t)}</td>"
            f"<td><b>{_e(f.title)}</b> <a class='muted small' href='https://cwe.mitre.org/data/definitions/{cwe}.html'>{_e(f.cwe)}</a>"
            f"<div class='small'>{_e(f.message)}</div><code class='snip'>{_e(f.snippet)}</code>{ai}</td>"
            f"<td class='hide-sm'><code>{_e(_rel(f.file, root))}:{f.line}</code>"
            f"<div class='muted small'>{_e(f.function + '()' if f.function else 'module')}</div></td>"
            f"<td>{fix}</td></tr>"
        )
    return (f'<div class="card"><table><thead><tr><th>{_e(t["severity"])}</th><th>{_e(t["issue"])}</th>'
            f'<th class="hide-sm">{_e(t["location"])}</th><th>{_e(t["fix"])}</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table></div>")


def _patches(patches: list[Patch], t: dict) -> str:
    if not patches:
        return ""
    cards = []
    for p in patches:
        gates = "".join(f'<span class="pill {"ok" if v else "bad"}">{_e(k.replace("_", " "))}</span>'
                        for k, v in p.checks.items())
        engine = t["engine_ai"] if p.engine == "ai" else t["engine_rules"]
        cards.append(
            f'<div class="patch"><h3>{_e(p.finding.title)} · <span class="muted">{_e(p.finding.function or "module")}()'
            f'</span></h3><div class="small">{_e(p.description)} <span class="muted">· engine: {_e(engine)}</span></div>'
            f'<div class="gates">{gates}</div>{_diff_html(p.diff)}</div>'
        )
    return f'<section><h2>{_e(t["patches"])}</h2><div class="card">{"".join(cards)}</div></section>'


def _escalations(items: list[Escalation], t: dict) -> str:
    if not items:
        return ""
    rows = "".join(
        f"<tr><td>{_sev(e.finding.severity, t)}</td><td><b>{_e(e.finding.title)}</b> "
        f"<span class='muted small'>{_e(e.finding.function or 'module')}() · line {e.finding.line}</span>"
        f"<code class='snip'>{_e(e.finding.snippet)}</code></td><td class='small'>{_e(e.reason)}</td></tr>"
        for e in items
    )
    return (f'<section><h2>{_e(t["escalations"])}</h2><div class="card"><table><thead><tr><th>{_e(t["severity"])}</th>'
            f'<th>{_e(t["issue"])}</th><th>{_e(t["why"])}</th></tr></thead><tbody>{rows}</tbody></table></div></section>')


def render_scan_report(findings: list[Finding], root: str | None = None, patches: list[Patch] | None = None,
                       escalations: list[Escalation] | None = None, project: str | None = None,
                       lang: str = "en") -> str:
    t = T.get(lang, T["en"])
    patches = patches or []
    escalations = escalations or []
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    kpis = _kpis([
        (str(len(findings)), t["findings"], "bad" if counts["critical"] else ""),
        (str(counts["critical"]), t["critical"], "bad" if counts["critical"] else "good"),
        (str(counts["high"]), t["high"], ""),
        (str(sum(1 for f in findings if f.fixable)), t["auto_fixable"], "good"),
        (str(len(patches)), t["patched"], "good" if patches else ""),
    ])
    body = (kpis + f'<section><h2>{_e(t["findings"])}</h2>{_findings_table(findings, root, t)}</section>'
            + _patches(patches, t) + _escalations(escalations, t)
            + f'<section><h2>{_e(t["method"])}</h2><div class="card"><table><tr><td class="small">'
              f'{_e(t["method_text"])}</td></tr></table></div></section>')
    name = project or (Path(root).resolve().name if root else "project")
    return _page(f'{t["title"]}: {name}', "Static analysis with taint tracking and verified auto-remediation.",
                 [(t["project"], name), (t["generated"], datetime.now().strftime("%Y-%m-%d %H:%M"))], body, lang)


def render_demo_report(result, lang: str = "en") -> str:
    t = T.get(lang, T["en"])
    s = result.summary()
    kpis = _kpis([
        (f'{s["attacks_blocked"]}/{s["attacks_total"]}', t["kpi_blocked"], "good"),
        (f'{s["mean_heal_ms"]:.0f} ms', t["kpi_heal"], "good"),
        (f'{s["exploitable_after"]}/{s["attacks_total"]}', t["kpi_after"], "good" if s["exploitable_after"] == 0 else "bad"),
        (str(s["false_positives"]), t["kpi_fp"], "good" if s["false_positives"] == 0 else "bad"),
        (str(s["vulnerabilities_found"]), t["kpi_found"], ""),
    ])
    healed = [r for r in result.records if r.status == "healed"]
    avg = lambda attr: (sum(getattr(r, attr) for r in healed) / len(healed)) if healed else 0.0
    detect = (sum(r.incident.detect_ms for r in healed) / len(healed)) if healed else 0.0
    timings = [f"{detect:.2f} ms", "403", f'{avg("locate_ms"):.0f} ms', f'{avg("patch_ms"):.0f} ms',
               t["gates"], f'{avg("verify_ms"):.0f} ms']
    pipe = '<div class="card"><div class="pipe">' + "".join(
        f'<div class="step"><div class="dot">{i + 1}</div><div class="n">{_e(n)}</div><div class="t">{_e(tm)}</div></div>'
        for i, (n, tm) in enumerate(zip(t["pipeline"], timings))
    ) + "</div></div>"

    rows = []
    for rec in result.records:
        inc = rec.incident
        case = next((c for c, _ in result.defended if c.path == inc.path and any(str(v) == inc.payload for v in c.params.values())), None)
        label = case.label if case else inc.attack_type
        fixed = ", ".join(sorted({p.finding.rule_id for p in rec.patches})) or "—"
        status = f'<span class="pill ok">{_e(t["healed"])}</span>' if rec.status == "healed" else f'<span class="pill neutral">{_e(rec.status)}</span>'
        rows.append(
            f"<tr><td><b>{_e(label)}</b><div class='muted small'>{_e(inc.method)} {_e(inc.path)} · "
            f"{_e(rec.function or '?')}()</div></td>"
            f"<td class='hide-sm'><code class='snip'>{_e(inc.param)}={_e(inc.payload[:90])}</code></td>"
            f"<td class='mono hide-sm'>{inc.detect_ms:.2f} ms</td><td class='mono'>{rec.total_ms:.0f} ms</td>"
            f"<td>{status}<div class='muted small'>{_e(fixed)}</div></td></tr>"
        )
    loop = (f'<div class="card" style="margin-top:14px"><table><thead><tr><th>{_e(t["attack"])}</th>'
            f'<th class="hide-sm">{_e(t["payload"])}</th><th class="hide-sm">{_e(t["detect"])}</th><th>{_e(t["heal"])}</th>'
            f'<th>{_e(t["status"])}</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>')

    proof_rows = "".join(
        f"<tr><td>{_e(c.label)}<div class='muted small'>{_e(c.name)}</div></td>"
        f"<td><span class='pill {'bad' if before else 'neutral'}'>{_e(t['exploitable'] if before else t['safe'])}</span></td>"
        f"<td><span class='pill {'bad' if after else 'ok'}'>{_e(t['exploitable'] if after else t['safe'])}</span></td></tr>"
        for (c, before), (_, after) in zip(result.baseline, result.proof)
    )
    func_rows = "".join(
        f"<tr><td>{_e(c.name)}</td>"
        f"<td><span class='pill {'ok' if b else 'bad'}'>{_e(t['works'] if b else t['broken'])}</span></td>"
        f"<td><span class='pill {'ok' if a else 'bad'}'>{_e(t['works'] if a else t['broken'])}</span></td></tr>"
        for (c, b), (_, a) in zip(result.checks_before, result.checks_after)
    )
    head = f"<thead><tr><th></th><th>{_e(t['before'])}</th><th>{_e(t['after'])}</th></tr></thead>"
    proof = (f'<section><h2>{_e(t["proof"])}</h2><div class="grid2">'
             f'<div class="card"><table>{head}<tbody>{proof_rows}</tbody></table></div>'
             f'<div class="card"><table><thead><tr><th>{_e(t["function"])}</th><th>{_e(t["before"])}</th>'
             f'<th>{_e(t["after"])}</th></tr></thead><tbody>{func_rows}</tbody></table></div></div></section>')

    patches = [p for r in result.records for p in r.patches]
    escalations: list[Escalation] = []
    if result.fix_report is not None:
        patches += result.fix_report.patches
        escalations = result.fix_report.escalated
    body = (kpis + f'<section><h2>{_e(t["selfheal"])}</h2>{pipe}{loop}</section>' + proof
            + _patches(patches, t) + _escalations(escalations, t)
            + f'<section><h2>{_e(t["findings"])} ({_e(t["before"])})</h2>{_findings_table(result.findings_before, None, t)}</section>'
            + f'<section><h2>{_e(t["method"])}</h2><div class="card"><table><tr><td class="small">{_e(t["method_text"])}'
              f'</td></tr></table></div></section>')
    engine = "rules + Claude" if result.ai_enabled else "rules"
    return _page(f'{t["selfheal"]} — VulnShop', t["demo_sub"],
                 [(t["engine"], engine), (t["run_time"], f"{result.duration_s} s"),
                  (t["generated"], datetime.now().strftime("%Y-%m-%d %H:%M"))], body, lang)
