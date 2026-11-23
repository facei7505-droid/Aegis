"""Core data models shared by the scanner, patcher, shield and healer."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Finding:
    """A vulnerability found by static analysis."""

    rule_id: str
    title: str
    cwe: str
    severity: str
    file: str
    line: int
    col: int
    end_line: int
    end_col: int
    function: str | None
    snippet: str
    message: str
    tainted: bool
    fixable: bool
    ai_verdict: str | None = None       # "confirmed" | "likely_false_positive" (AI triage)
    ai_explanation: str | None = None   # plain-language explanation for non-experts

    @property
    def key(self) -> tuple[str, str, str | None]:
        """Identity that survives line shifts caused by earlier patches."""
        return (self.rule_id, self.file, self.function)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Patch:
    """One verified (or rejected) automatic fix."""

    finding: Finding
    description: str
    diff: str
    verified: bool = False
    checks: dict[str, bool] = field(default_factory=dict)
    engine: str = "rules"   # "rules" (deterministic) or "ai" (Claude)
    attempts: int = 1

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["finding"] = self.finding.to_dict()
        return data


@dataclass
class Escalation:
    """A finding Aegis refused to patch automatically, and why."""

    finding: Finding
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"finding": self.finding.to_dict(), "reason": self.reason}


@dataclass
class Incident:
    """An attack observed at runtime by the shield."""

    id: str
    timestamp: float
    client: str
    method: str
    path: str
    location: str
    param: str
    payload: str
    attack_type: str
    score: float
    blocked: bool
    detect_ms: float
    signals: list[str] = field(default_factory=list)
    classes: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HealingRecord:
    """What the self-healing loop did in response to one incident."""

    incident: Incident
    route: str | None
    function: str | None
    root_causes: list[Finding]
    patches: list[Patch]
    status: str  # healed | already_healed | no_root_cause | needs_human
    locate_ms: float = 0.0
    patch_ms: float = 0.0
    verify_ms: float = 0.0
    escalations: list[Escalation] = field(default_factory=list)

    @property
    def total_ms(self) -> float:
        return self.incident.detect_ms + self.locate_ms + self.patch_ms + self.verify_ms

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident": self.incident.to_dict(),
            "route": self.route,
            "function": self.function,
            "root_causes": [f.to_dict() for f in self.root_causes],
            "patches": [p.to_dict() for p in self.patches],
            "escalations": [e.to_dict() for e in self.escalations],
            "status": self.status,
            "locate_ms": self.locate_ms,
            "patch_ms": self.patch_ms,
            "verify_ms": self.verify_ms,
            "total_ms": self.total_ms,
        }
