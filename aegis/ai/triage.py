"""AI triage: separates real risk from noise and explains it to non-experts."""
from __future__ import annotations

from pathlib import Path

from ..models import Finding
from .client import LLM, AIError, parse_json_reply
from .prompts import LANGUAGES, TRIAGE_ITEM, TRIAGE_SYSTEM

BATCH = 15


def _context(finding: Finding, radius: int = 6) -> str:
    try:
        lines = Path(finding.file).read_text(encoding="utf-8").splitlines()
    except OSError:
        return finding.snippet
    lo, hi = max(0, finding.line - 1 - radius), min(len(lines), finding.line + radius)
    return "\n".join(f"{n + 1:>4} {'>' if n + 1 == finding.line else ' '} {lines[n]}" for n in range(lo, hi))


def triage(findings: list[Finding], client: LLM, language: str = "en") -> list[Finding]:
    """Annotate findings in place with ai_verdict / ai_explanation. Never drops findings."""
    lang = LANGUAGES.get(language, language)
    for i in range(0, len(findings), BATCH):
        chunk = findings[i:i + BATCH]
        prompt = "\n\n".join(
            TRIAGE_ITEM.format(id=n, title=f.title, cwe=f.cwe, file=Path(f.file).name, line=f.line,
                               message=f.message, context=_context(f))
            for n, f in enumerate(chunk)
        )
        try:
            verdicts = parse_json_reply(client.complete(TRIAGE_SYSTEM.format(language=lang), prompt, 4096))
        except AIError:
            continue
        if not isinstance(verdicts, list):
            continue
        for item in verdicts:
            try:
                f = chunk[int(item["id"])]
            except (KeyError, ValueError, IndexError, TypeError):
                continue
            verdict = item.get("verdict")
            if verdict in ("confirmed", "likely_false_positive"):
                f.ai_verdict = verdict
            f.ai_explanation = str(item.get("explanation", "")).strip() or None
    return findings
