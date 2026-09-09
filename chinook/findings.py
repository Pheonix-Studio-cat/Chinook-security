"""Das gemeinsame Befund-Format des Chinook-Oekosystems.

Jeder Bot gibt dasselbe aus. Ohne dieses Format waere weder die
Aufseher-Schicht noch die Website baubar: beide lesen Befunde, nicht
Werkzeugausgaben.

Die wichtigste Regel steht in `redact()`: **ein Befund traegt nie den
gefundenen Wert.** Bei einem oeffentlichen Repo liest jeder das Action-Log;
ein Secret-Bot, der den gefundenen Schluessel ausdruckt, waere selbst das Leck.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

SCHEMA_VERSION = "1"

# Von schwer nach leicht. Die Reihenfolge ist die Schwelle fuer --fail-on.
SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")

# Befund-Schweregrad -> SARIF-Stufe, damit GitHubs Code-Scanning-Ansicht passt.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

INFORMATION_URI = "https://github.com/Pheonix-Studio-cat/Chinook-security"


def redact(raw: str, kind: str = "Treffer") -> str:
    """Beschreibt einen Fund, ohne ihn wiederzugeben.

    Kein Zeichen des Werts kommt zurueck -- auch kein Praefix und kein Hash.
    Ein Hash waere bei einem schwachen Passwort ein Orakel, und vier Zeichen
    eines Passworts sind vier Zeichen zu viel. Was bleibt, ist die Laenge:
    genug, um zwei Funde zu unterscheiden, zu wenig, um einen zu benutzen.
    """
    text = "" if raw is None else str(raw)
    return f"{kind}, {len(text)} Zeichen (Wert wird nicht ausgegeben)"


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


@dataclass(frozen=True)
class Finding:
    """Ein einzelner Befund. Unveraenderlich, damit ihn niemand nachtraeglich
    entschaerft -- das Einordnen ist Sache der Aufseher-Schicht, das Loeschen
    Sache eines Menschen."""

    bot: str
    rule: str
    title: str
    severity: str
    confidence: str
    path: str
    line: int
    explanation: str
    remediation: str
    evidence: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unbekannter Schweregrad: {self.severity!r}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"unbekannte Zuversicht: {self.confidence!r}")
        if self.line < 1:
            raise ValueError(f"Zeilennummern beginnen bei 1, nicht {self.line}")
        if not self.bot or not self.rule:
            raise ValueError("bot und rule duerfen nicht leer sein")

    @property
    def rule_id(self) -> str:
        return f"{self.bot}/{self.rule}"

    @property
    def fingerprint(self) -> str:
        """Stabil ueber Laeufe hinweg, damit ein bekannter Befund wiedererkannt
        wird. Bewusst **ohne** den gefundenen Wert."""
        material = "\0".join([self.bot, self.rule, self.path, str(self.line)])
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "id": self.rule_id,
            "bot": self.bot,
            "rule": self.rule,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "location": {"path": self.path, "line": self.line},
            "explanation": self.explanation,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "fingerprint": self.fingerprint,
        }


def sort_findings(findings) -> list:
    return sorted(
        findings,
        key=lambda f: (severity_rank(f.severity), f.path, f.line, f.rule),
    )


def report(bot: str, findings, target: dict | None = None, generated_at: str | None = None) -> dict:
    """Der Bericht, den ein Bot als JSON schreibt."""
    ordered = sort_findings(findings)
    counts = {level: 0 for level in SEVERITIES}
    for finding in ordered:
        counts[finding.severity] += 1
    stamp = generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return {
        "schema_version": SCHEMA_VERSION,
        "bot": bot,
        "generated_at": stamp,
        "target": target or {},
        "summary": {"total": len(ordered), "by_severity": counts},
        "findings": [finding.to_dict() for finding in ordered],
    }


def to_sarif(bot: str, findings) -> dict:
    """SARIF 2.1.0, damit GitHub die Befunde in der Security-Ansicht zeigt."""
    ordered = sort_findings(findings)
    rules: dict[str, dict] = {}
    results = []
    for finding in ordered:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.rule,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.explanation},
                "help": {"text": finding.remediation},
                "properties": {"problem.severity": finding.severity},
            },
        )
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _SARIF_LEVEL[finding.severity],
                "message": {"text": f"{finding.title} -- {finding.explanation} {finding.evidence}".strip()},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": {"startLine": finding.line},
                        }
                    }
                ],
                "partialFingerprints": {"chinookFingerprint/v1": finding.fingerprint},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": f"chinook-{bot}",
                        "informationUri": INFORMATION_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def exceeds(findings, threshold: str) -> bool:
    """Wahr, wenn mindestens ein Befund so schwer ist wie die Schwelle."""
    if threshold == "never":
        return False
    if threshold not in SEVERITIES:
        raise ValueError(f"unbekannte Schwelle: {threshold!r}")
    limit = severity_rank(threshold)
    return any(severity_rank(f.severity) <= limit for f in findings)


def dumps(payload: dict) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False)
