"""Secret-Bot -- sucht Geheimnisse im Arbeitsbaum und wahlweise in der History.

Was er **nicht** tut: den gefundenen Wert ausgeben. Siehe `findings.redact`.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass

from .findings import Finding, redact

BOT = "secret-bot"

# Verzeichnisse, die nie gescannt werden. `.git` waere sonst doppelt drin
# (einmal als Objektdatenbank, einmal ueber die History-Pruefung).
DEFAULT_EXCLUDES = (
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
)

MAX_FILE_BYTES = 2_000_000
BINARY_SNIFF_BYTES = 4096


@dataclass(frozen=True)
class Rule:
    name: str
    title: str
    pattern: re.Pattern
    severity: str
    confidence: str
    remediation: str
    group: int = 0


_ROTATE = (
    "Den Schluessel als kompromittiert behandeln: beim Anbieter widerrufen und "
    "neu ausstellen, dann aus dem Quelltext entfernen und ueber ein Repo-Secret "
    "einspeisen. Ein Commit zu loeschen genuegt nicht -- die History bleibt."
)

RULES: tuple[Rule, ...] = (
    Rule(
        name="aws-access-key-id",
        title="AWS Access Key ID im Quelltext",
        pattern=re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b"),
        severity="critical",
        confidence="high",
        remediation=_ROTATE,
        group=1,
    ),
    Rule(
        name="github-token",
        title="GitHub-Token im Quelltext",
        pattern=re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"),
        severity="critical",
        confidence="high",
        remediation=_ROTATE,
        group=1,
    ),
    Rule(
        name="huggingface-token",
        title="Hugging-Face-Token im Quelltext",
        pattern=re.compile(r"\b(hf_[A-Za-z0-9]{34,})\b"),
        severity="critical",
        confidence="high",
        remediation=_ROTATE,
        group=1,
    ),
    Rule(
        name="anthropic-key",
        title="Anthropic-API-Schluessel im Quelltext",
        pattern=re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{24,})\b"),
        severity="critical",
        confidence="high",
        remediation=_ROTATE,
        group=1,
    ),
    Rule(
        name="openai-key",
        title="OpenAI-API-Schluessel im Quelltext",
        pattern=re.compile(r"\b(sk-(?!ant-)[A-Za-z0-9]{32,})\b"),
        severity="critical",
        confidence="high",
        remediation=_ROTATE,
        group=1,
    ),
    Rule(
        name="slack-token",
        title="Slack-Token im Quelltext",
        pattern=re.compile(r"\b(xox[abprs]-[A-Za-z0-9\-]{10,})\b"),
        severity="critical",
        confidence="high",
        remediation=_ROTATE,
        group=1,
    ),
    Rule(
        name="google-api-key",
        title="Google-API-Schluessel im Quelltext",
        pattern=re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
        severity="critical",
        confidence="high",
        remediation=_ROTATE,
        group=1,
    ),
    Rule(
        name="private-key-block",
        title="Privater Schluessel im Quelltext",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        severity="critical",
        confidence="high",
        remediation=(
            "Das Schluesselpaar neu erzeugen und das alte widerrufen. Private "
            "Schluessel gehoeren nie in ein Repo, auch nicht in ein privates."
        ),
    ),
    Rule(
        name="assigned-credential",
        title="Zugangsdaten an eine Variable zugewiesen",
        pattern=re.compile(
            r"""(?ix)
            \b (?: api[_-]?key | apikey | secret[_-]?key | access[_-]?token
                 | auth[_-]?token | client[_-]?secret | password | passwd )
            \s* [:=] \s*
            ['"] ( [^'"\s]{12,} ) ['"]
            """
        ),
        severity="high",
        confidence="medium",
        remediation=(
            "Den Wert in ein Repo-Secret verschieben und ueber die Umgebung "
            "einlesen. Ist es ein Platzhalter, erkennbar machen "
            "(z. B. `<hier-einsetzen>` oder `${VARIABLE}`)."
        ),
        group=1,
    ),
)

# Was wie ein Geheimnis aussieht, aber keins ist. Bewusst knapp gehalten:
# eine zu grosszuegige Liste ist genau der Weg, auf dem ein Bot gruen wird,
# ohne etwas zu pruefen.
_PLACEHOLDER = re.compile(
    r"""(?ix)
    ^ (?: \s* )
    (?: .*? (?: example | sample | dummy | placeholder | changeme | change_me
              | redacted | your[_-]? | my[_-]?secret | test[_-]?only
              | xxxx | \.\.\. ) .* )
    $
    """
)
_INTERPOLATION = re.compile(r"^\s*(?:\$\{|\$\(|<%|\{\{|%\(|<[a-z_\- ]+>)")


def is_placeholder(value: str) -> bool:
    """Ein Platzhalter ist kein Fund."""
    if _INTERPOLATION.search(value):
        return True
    if _PLACEHOLDER.match(value):
        return True
    # Ein Wert aus einem einzigen wiederholten Zeichen ist Fuellmaterial.
    stripped = value.strip()
    return len(set(stripped)) <= 2


def _is_probably_binary(path: str) -> bool:
    try:
        with open(path, "rb") as handle:
            chunk = handle.read(BINARY_SNIFF_BYTES)
    except OSError:
        return True
    return b"\x00" in chunk


def iter_files(root: str, excludes=()):
    """Alle Textdateien unterhalb von `root`, ohne die ausgeschlossenen Pfade."""
    skip = set(DEFAULT_EXCLUDES) | {e.strip("/") for e in excludes if e.strip()}
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        dirnames[:] = [
            d
            for d in sorted(dirnames)
            if d not in skip
            and os.path.normpath(os.path.join(rel_dir, d)).replace(os.sep, "/") not in skip
        ]
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if rel in skip or any(rel.startswith(f"{s}/") for s in skip):
                continue
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            if _is_probably_binary(full):
                continue
            yield rel, full


def scan_text(text: str, path: str, *, source: str = "Arbeitsbaum") -> list[Finding]:
    """Der eigentliche Musterabgleich. Getrennt vom Dateisystem, damit er auch
    fuer die History-Pruefung wiederverwendbar und einzeln pruefbar ist."""
    findings: list[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if len(line) > 4000:
            continue
        for rule in RULES:
            for match in rule.pattern.finditer(line):
                value = match.group(rule.group) if rule.group else match.group(0)
                if rule.confidence != "high" and is_placeholder(value):
                    continue
                findings.append(
                    Finding(
                        bot=BOT,
                        rule=rule.name,
                        title=rule.title,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        path=path,
                        line=number,
                        explanation=(
                            f"In {path}, Zeile {number} ({source}) steht etwas, das dem "
                            f"Format eines Geheimnisses entspricht."
                        ),
                        remediation=rule.remediation,
                        evidence=redact(value, kind=rule.name),
                    )
                )
    return findings


def scan_tree(root: str, excludes=()) -> list[Finding]:
    findings: list[Finding] = []
    for rel, full in iter_files(root, excludes):
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError:
            continue
        findings.extend(scan_text(text, rel))
    return findings


_DIFF_FILE = re.compile(r"^\+\+\+ b/(.+)$")
_DIFF_COMMIT = re.compile(r"^commit ([0-9a-f]{7,40})")


def scan_history(root: str, max_commits: int = 500) -> list[Finding]:
    """Sucht in dem, was einmal committet war und laengst geloescht scheint.

    Ein Geheimnis, das in einem alten Commit steht, ist nicht weg, nur weil die
    aktuelle Datei sauber ist. Genau deshalb reicht ein Diff-Scan nicht.
    """
    try:
        completed = subprocess.run(
            [
                "git",
                "-C",
                root,
                "log",
                f"--max-count={max_commits}",
                "--no-color",
                "--unified=0",
                "-p",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if completed.returncode != 0:
        return []

    findings: list[Finding] = []
    seen: set[tuple] = set()
    commit = "unbekannt"
    path = "unbekannt"
    for raw_line in completed.stdout.splitlines():
        commit_match = _DIFF_COMMIT.match(raw_line)
        if commit_match:
            commit = commit_match.group(1)[:12]
            continue
        file_match = _DIFF_FILE.match(raw_line)
        if file_match:
            path = file_match.group(1)
            continue
        if not raw_line.startswith("+") or raw_line.startswith("+++"):
            continue
        for finding in scan_text(raw_line[1:], path, source=f"History, Commit {commit}"):
            key = (finding.rule, finding.path, finding.evidence)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    bot=finding.bot,
                    rule=finding.rule,
                    title=finding.title,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    path=finding.path,
                    line=1,
                    explanation=(
                        f"In der History (Commit {commit}) wurde in {finding.path} etwas "
                        f"hinzugefuegt, das dem Format eines Geheimnisses entspricht. "
                        f"Die aktuelle Datei kann sauber sein -- die History ist es nicht."
                    ),
                    remediation=finding.remediation,
                    evidence=finding.evidence,
                )
            )
    return findings


def run(root: str, excludes=(), history: bool = False) -> list[Finding]:
    findings = scan_tree(root, excludes)
    if history:
        findings.extend(scan_history(root))
    return findings
