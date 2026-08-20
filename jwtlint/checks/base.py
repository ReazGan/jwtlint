"""Shared types for check modules.

Every check module in this package exposes a `check(parsed, **kwargs) ->
list[Finding]` function and returns findings shaped like `Finding.to_dict()`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]


@dataclass
class Finding:
    check: str
    title: str
    description: str
    severity: Severity
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
        }
