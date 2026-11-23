"""The monthly report a client gets: one or two A4 pages in Russian, built from the day stats.

What was stopped, when, how, and what the owner should do — with advice chosen from what actually
happened on that site, not a generic checklist. Needs reportlab (`pip install 'aegis-selfheal[edge]'`).
"""
from __future__ import annotations

import calendar
import io
from xml.sax.saxutils import escape as esc
import re
from datetime import date, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from ..shield.core import REASONS_RU

if TYPE_CHECKING:
    from .server import Edge
    from .sites import Site

FONTS = Path(__file__).parent / "fonts"
MONTHS = ["январь", "февраль", "март", "апрель", "май", "июнь", "июль", "август", "сентябрь", "октябрь", "ноябрь",
          "декабрь"]
INK, MUTED, ACCENT, LINE, SOFT = "#16231d", "#5b6b63", "#0f7a55", "#d9e2dd", "#eef4f1"


def cap(text: str) -> str:
    """Capitalise the first letter only (str.capitalize would turn SQL into sql)."""
    return text[:1].upper() + text[1:]


def _month(value: str) -> tuple[date, date]:
    if not re.fullmatch(r"\d{4}-\d{2}", value or ""):
        raise ValueError("Месяц нужен в виде ГГГГ-ММ, например 2026-11")
    year, month = map(int, value.split("-"))
    if not 1 <= month <= 12:
        raise ValueError("Месяц нужен в виде ГГГГ-ММ, например 2026-11")
    return date(year, month, 1), date(year, month, calendar.monthrange(year, month)[1])


def advice(site: "Site", data: dict) -> list[str]:
    """What the owner should do, from what was seen on this site this month."""
    patches, kinds = data["patches"], data["by_type"]
    tips = []
    if site.learning() or site.mode == "monitor":
        tips.append("Защита работала в режиме записи: атаки отмечены, но не блокировались. "
                    "Если сайт работает без сбоев — включите блокировку (/resume в Telegram).")
    if any(p.startswith("bx-cve") or p == "bx-html-editor-write" or p == "bx-attach-events" for p in patches):
        tips.append("Сайт пытались взломать через известные уязвимости «1С-Битрикс» (CVE-2022-27228 и запись файлов "
                    "через визуальный редактор). Обновите Битрикс до актуальной версии: до обновления эти адреса "
                    "закрыты защитой, но обновление — надёжнее.")
    if any(p in patches for p in ("php-in-uploads", "webshell-names", "bx-known-backdoors")):
        tips.append("Кто-то искал на сайте веб-шеллы — файлы, через которые управляют взломанным сайтом. "
                    "Попросите хостинг проверить сайт антивирусом: если взлом был раньше, такой файл мог остаться.")
    if data["brute_force"] or kinds.get("brute_force"):
        tips.append("Были попытки подобрать пароль администратора. Смените простые пароли и включите "
                    "двухфакторный вход для всех, у кого есть доступ к админке.")
    if any(p in patches for p in ("wp-user-enum", "wp-rest-users")):
        tips.append("Боты перебирали имена пользователей WordPress. Сделайте так, чтобы логин для входа "
                    "не совпадал с именем автора, которое видно на сайте.")
    if "wp-xmlrpc-multicall" in patches:
        tips.append("Атаки шли через xmlrpc.php. Если вы не пользуетесь мобильным приложением WordPress "
                    "и Jetpack, xmlrpc можно отключить полностью.")
    if kinds.get("sqli", 0) + kinds.get("xss", 0) + kinds.get("path_traversal", 0) > 50:
        tips.append("Сайт регулярно проверяют на SQL-инъекции, XSS и чтение файлов — это постоянный фон интернета, "
                    "защита их останавливает. Обновляйте CMS и плагины, чтобы не держаться только на защите.")
    if not data["attacks"]:
        tips.append("За месяц атак не было. Хороший повод проверить, что резервные копии сайта делаются и "
                    "восстанавливаются.")
    return tips


def build_report(edge: "Edge", site: "Site", month: str) -> bytes:
    first, last = _month(month)
    if first > date.today():
        raise ValueError("Этот месяц ещё не начался")
    last = min(last, date.today())
    data = edge.stats.period(site.domain, first, last)
    return render(site, data, first, last, edge.settings.brand, edge.settings.contact)


def render(site: "Site", data: dict, first: date, last: date, brand: str = "Aegis Щит", contact: str = "") -> bytes:
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.shapes import Drawing, String
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    if "Aegis" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont("Aegis", str(FONTS / "DejaVuSans.ttf")))
        pdfmetrics.registerFont(TTFont("Aegis-Bold", str(FONTS / "DejaVuSans-Bold.ttf")))

    ink, muted, accent, line, soft = (colors.HexColor(c) for c in (INK, MUTED, ACCENT, LINE, SOFT))
    styles = {
        "kicker": ParagraphStyle("k", fontName="Aegis", fontSize=9, textColor=muted, leading=12),
        "title": ParagraphStyle("t", fontName="Aegis-Bold", fontSize=22, textColor=ink, leading=27, spaceAfter=2),
        "meta": ParagraphStyle("m", fontName="Aegis", fontSize=10, textColor=muted, leading=14),
        "h": ParagraphStyle("h", fontName="Aegis-Bold", fontSize=12.5, textColor=ink, leading=16, spaceBefore=12,
                            spaceAfter=6),
        "body": ParagraphStyle("b", fontName="Aegis", fontSize=10, textColor=ink, leading=14.5, alignment=TA_LEFT),
        "small": ParagraphStyle("s", fontName="Aegis", fontSize=8.5, textColor=muted, leading=11.5),
        "big": ParagraphStyle("g", fontName="Aegis-Bold", fontSize=21, textColor=ink, leading=24),
        "label": ParagraphStyle("l", fontName="Aegis", fontSize=8.5, textColor=muted, leading=11),
        "num": ParagraphStyle("n", fontName="Aegis", fontSize=10, textColor=ink, leading=14.5, alignment=2),
        "numlabel": ParagraphStyle("nl", fontName="Aegis", fontSize=8.5, textColor=muted, leading=11, alignment=2),
    }
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm,
                            bottomMargin=16 * mm, title=f"{brand}: {site.domain}, {first:%m.%Y}", author=brand)
    width = A4[0] - 36 * mm
    period = f"{MONTHS[first.month - 1]} {first.year}" + ("" if last.day == calendar.monthrange(last.year, last.month)[1]
                                                         else f" (по {last:%d.%m})")
    story = [
        Paragraph(f"{brand} · отчёт о защите сайта", styles["kicker"]),
        Paragraph(site.domain, styles["title"]),
        Paragraph(esc(" · ".join(x for x in (site.client, cap(period), site.status_ru()) if x)), styles["meta"]),
        Spacer(1, 10),
    ]

    def fmt(n: int) -> str:
        return f"{n:,}".replace(",", " ")

    stopped = data["blocked"]
    cells = [(fmt(data["requests"]), "запросов к сайту"), (fmt(stopped), "атак остановлено"),
             (fmt(data["attacks"] - stopped), "записано без блокировки"),
             (fmt(data["brute_force"]), "попыток подбора пароля пресечено")]
    tiles = Table([[Paragraph(v, styles["big"]) for v, _ in cells], [Paragraph(t, styles["label"]) for _, t in cells]],
                  colWidths=[width / 4] * 4)
    tiles.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), soft), ("LEFTPADDING", (0, 0), (-1, -1), 8),
                               ("TOPPADDING", (0, 0), (-1, 0), 9), ("BOTTOMPADDING", (0, 1), (-1, 1), 9),
                               ("LINEAFTER", (0, 0), (-2, -1), 0.6, colors.white)]))
    story += [tiles, Spacer(1, 6)]

    series = data["series"]
    if series:
        story.append(Paragraph("Остановленные атаки по дням", styles["h"]))
        drawing = Drawing(width, 120)
        chart = VerticalBarChart()
        chart.x, chart.y, chart.width, chart.height = 28, 18, width - 34, 92
        chart.data = [[s[2] for s in series]]
        chart.bars[0].fillColor = accent
        chart.bars[0].strokeColor = None
        chart.barSpacing = 1
        chart.valueAxis.valueMin = 0
        top = max([s[2] for s in series] + [1])
        step = max(1, round(top / 4))
        chart.valueAxis.valueMax = step * 4 if step * 4 >= top else top
        chart.valueAxis.valueStep = step
        chart.valueAxis.labels.fontName = "Aegis"
        chart.valueAxis.labels.fontSize = 7
        chart.valueAxis.labels.fillColor = muted
        chart.valueAxis.strokeColor = line
        chart.valueAxis.gridStrokeColor = line
        chart.valueAxis.visibleGrid = True
        chart.categoryAxis.categoryNames = [s[0][8:] if i % max(1, len(series) // 10) == 0 else "" for i, s in
                                            enumerate(series)]
        chart.categoryAxis.labels.fontName = "Aegis"
        chart.categoryAxis.labels.fontSize = 7
        chart.categoryAxis.labels.fillColor = muted
        chart.categoryAxis.strokeColor = line
        drawing.add(chart)
        if not stopped:
            drawing.add(String(width / 2, 60, "атак не было", fontName="Aegis", fontSize=9, fillColor=muted,
                               textAnchor="middle"))
        story.append(drawing)

    story.append(Paragraph("Что сделать", styles["h"]))
    for tip in advice(site, data):
        story.append(Paragraph(f"— {esc(tip)}", styles["body"]))
        story.append(Spacer(1, 3))

    def table(rows: list[list[str]], header: list[str], widths: list[float]):
        last = len(header) - 1
        cells = [[Paragraph(h, styles["numlabel" if i == last else "label"]) for i, h in enumerate(header)]] + \
                [[Paragraph(esc(str(c)), styles["num" if i == last else "body"]) for i, c in enumerate(r)] for r in rows]
        t = Table(cells, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, 0), 0.8, ink), ("LINEBELOW", (0, 1), (-1, -1), 0.4, line),
                               ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ALIGN", (-1, 0), (-1, -1), "RIGHT"),
                               ("TOPPADDING", (0, 0), (-1, -1), 3.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
                               ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
        return t

    kinds = sorted(data["by_type"].items(), key=lambda kv: -kv[1])
    if kinds:
        story.append(Paragraph("Что пытались сделать с сайтом", styles["h"]))
        total = sum(v for _, v in kinds) or 1
        rows = [[cap(REASONS_RU.get(k, k)), f"{fmt(v)} · {v * 100 // total}%"] for k, v in kinds[:10]]
        story.append(table(rows, ["Вид атаки", "Сколько"], [width * 0.72, width * 0.28]))
    patches = sorted(data["patches"].items(), key=lambda kv: -kv[1])
    if patches:
        from ..shield.policy import PRESETS
        names = {p.name: p.reason for preset in PRESETS.values() for p in preset.patches}
        story.append(Paragraph("Закрытые слабые места сработали", styles["h"]))
        rows = [[cap(names.get(k, k)), fmt(v)] for k, v in patches[:8]]
        story.append(table(rows, ["Что закрыто", "Раз"], [width * 0.82, width * 0.18]))
    paths = sorted(data["paths"].items(), key=lambda kv: -kv[1])[:8]
    if paths:
        story.append(Paragraph("Куда целились чаще всего", styles["h"]))
        story.append(table([[p[:90], fmt(v)] for p, v in paths], ["Адрес на сайте", "Атак"], [width * 0.82, width * 0.18]))
    clients = sorted(data["clients"].items(), key=lambda kv: -kv[1])[:6]
    if clients:
        story.append(Paragraph("Самые активные источники атак", styles["h"]))
        story.append(table([[ip, fmt(v)] for ip, v in clients], ["IP-адрес", "Атак"], [width * 0.82, width * 0.18]))

    story += [Spacer(1, 12), Paragraph(
        f"Отчёт сформирован автоматически {datetime.now():%d.%m.%Y}. Хранятся только сведения об атаках: "
        f"содержимое форм, пароли и данные посетителей не сохраняются." + (f" Вопросы: {contact}." if contact else ""),
        styles["small"])]
    doc.build(story)
    return buf.getvalue()
