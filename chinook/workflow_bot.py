"""Workflow-Bot -- prueft die GitHub Actions selbst.

Die Bots laufen als Actions. Eine unsichere Action ist deshalb kein Randthema,
sondern der Weg, auf dem jemand an die Secrets des Repos kommt.

**Bewusst zeilenbasiert, ohne YAML-Parser.** Grund: keine Abhaengigkeit. Der
Preis ist beschrieben, nicht verschwiegen -- die Regeln unten lesen Zeilen und
Einrueckung, keine Dokumentstruktur. Fuer verschachtelte Sonderfaelle (Anker,
mehrzeilige Flow-Maps) ist das zu grob; das steht so auch in `docs/`.
"""

from __future__ import annotations

import os
import re

from .findings import Finding

BOT = "workflow-bot"

WORKFLOW_DIR = os.path.join(".github", "workflows")
WORKFLOW_SUFFIXES = (".yml", ".yaml")

_SHA = re.compile(r"^[0-9a-f]{40}$")
_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^'\"\s#]+)['\"]?")
_RUN_START = re.compile(r"^(\s*)(?:-\s*)?run:\s*(.*)$")
_TOP_LEVEL_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_\-]*):")

# Actions aus diesen Namensraeumen gehoeren GitHub selbst. Ein Tag statt eines
# SHA ist dort eine Empfehlung (info), bei Fremd-Actions eine Warnung (medium):
# wer eine Fremd-Action auf einen beweglichen Tag zeigen laesst, fuehrt aus,
# was der Fremde morgen dorthin schiebt.
FIRST_PARTY = ("actions", "github")

# Kontextwerte, die ein Fremder schreibt. In einem `run:`-Block werden sie vor
# der Ausfuehrung in das Skript eingesetzt -- das ist Command Injection, kein
# Stilproblem.
UNTRUSTED_CONTEXT = (
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.head_commit.author.email",
    "github.event.workflow_run.head_branch",
    "github.head_ref",
)

_EXPRESSION = re.compile(r"\$\{\{([^}]*)\}\}")


def is_pinned(ref: str) -> bool:
    """Nur ein voller Commit-SHA ist eine Festlegung. Ein Tag kann verschoben
    werden, ein Branch sowieso."""
    return bool(_SHA.match(ref))


def untrusted_in(expression: str) -> str | None:
    normalised = expression.replace(" ", "")
    for context in UNTRUSTED_CONTEXT:
        if context.replace(" ", "") in normalised:
            return context
    return None


def iter_workflow_files(root: str):
    directory = os.path.join(root, WORKFLOW_DIR)
    if not os.path.isdir(directory):
        return
    for name in sorted(os.listdir(directory)):
        if name.endswith(WORKFLOW_SUFFIXES):
            rel = f"{WORKFLOW_DIR}/{name}".replace(os.sep, "/")
            yield rel, os.path.join(directory, name)


def _run_block_lines(lines: list[str]) -> set[int]:
    """Zeilennummern (1-basiert), die zu einem `run:`-Block gehoeren."""
    inside: set[int] = set()
    index = 0
    while index < len(lines):
        match = _RUN_START.match(lines[index])
        if not match:
            index += 1
            continue
        indent, rest = len(match.group(1)), match.group(2).strip()
        inside.add(index + 1)
        if rest not in ("|", ">", "|-", ">-", "|+", ">+"):
            index += 1
            continue
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.strip() and (len(line) - len(line.lstrip())) <= indent:
                break
            inside.add(index + 1)
            index += 1
    return inside


def scan_workflow(text: str, path: str) -> list[Finding]:
    lines = text.splitlines()
    findings: list[Finding] = []
    run_lines = _run_block_lines(lines)
    top_level_keys = {
        _TOP_LEVEL_KEY.match(line).group(1) for line in lines if _TOP_LEVEL_KEY.match(line)
    }
    has_pr_target = any(re.search(r"\bpull_request_target\b", line) for line in lines)

    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        uses = _USES.match(line)
        if uses:
            reference = uses.group(1)
            if not reference.startswith("./") and not reference.startswith("docker://"):
                owner = reference.split("/", 1)[0]
                ref = reference.split("@", 1)[1] if "@" in reference else ""
                if not is_pinned(ref):
                    first_party = owner in FIRST_PARTY
                    findings.append(
                        Finding(
                            bot=BOT,
                            rule="unpinned-action",
                            title="Action nicht auf einen Commit festgelegt",
                            severity="info" if first_party else "medium",
                            confidence="high",
                            path=path,
                            line=number,
                            explanation=(
                                f"`{reference}` zeigt auf "
                                + (f"den beweglichen Ref `{ref}`" if ref else "keinen Ref")
                                + ". Wer den Tag verschiebt, aendert damit, was in diesem "
                                "Repo mit dessen Rechten ausgefuehrt wird."
                            ),
                            remediation=(
                                "Auf den vollen 40-stelligen Commit-SHA festlegen und den "
                                "lesbaren Tag als Kommentar dahinterschreiben."
                            ),
                        )
                    )

        if re.match(r"^\s*permissions:\s*write-all\s*$", line):
            findings.append(
                Finding(
                    bot=BOT,
                    rule="permissions-write-all",
                    title="Workflow laeuft mit allen Schreibrechten",
                    severity="high",
                    confidence="high",
                    path=path,
                    line=number,
                    explanation=(
                        "`permissions: write-all` gibt dem GITHUB_TOKEN Schreibrechte auf "
                        "alles -- Inhalte, Pakete, Deployments. Jeder Schritt im Workflow "
                        "erbt sie, auch eine Fremd-Action."
                    ),
                    remediation=(
                        "Auf `permissions: contents: read` setzen und einzelne Rechte nur "
                        "dort erweitern, wo ein Schritt sie tatsaechlich braucht."
                    ),
                )
            )

        if has_pr_target and "github.event.pull_request.head" in line and re.search(r"^\s*ref:", line):
            findings.append(
                Finding(
                    bot=BOT,
                    rule="pull-request-target-checkout",
                    title="pull_request_target checkt fremden Code aus",
                    severity="critical",
                    confidence="high",
                    path=path,
                    line=number,
                    explanation=(
                        "`pull_request_target` laeuft mit den Secrets des Ziel-Repos. Wird "
                        "darin der Kopf des Pull Requests ausgecheckt, fuehrt der Workflow "
                        "fremden Code mit diesen Secrets aus -- jeder, der einen PR oeffnen "
                        "kann, uebernimmt damit den Lauf."
                    ),
                    remediation=(
                        "Entweder `pull_request` verwenden (kein Zugriff auf Secrets) oder "
                        "unter `pull_request_target` ausschliesslich den Basis-Stand "
                        "auschecken und den PR-Inhalt nur als Daten behandeln."
                    ),
                )
            )

        if number in run_lines:
            for expression in _EXPRESSION.findall(line):
                context = untrusted_in(expression)
                if context:
                    findings.append(
                        Finding(
                            bot=BOT,
                            rule="script-injection",
                            title="Fremder Text wird in ein Skript eingesetzt",
                            severity="high",
                            confidence="high",
                            path=path,
                            line=number,
                            explanation=(
                                f"`{context}` wird von dem geschrieben, der den PR oder den "
                                "Kommentar verfasst, und vor der Ausfuehrung direkt in das "
                                "Skript eingesetzt. Ein Backtick oder ein Semikolon darin "
                                "ist dann ein Befehl."
                            ),
                            remediation=(
                                "Den Wert ueber `env:` an den Schritt geben und im Skript "
                                "als Variable in Anfuehrungszeichen benutzen. Dann ist er "
                                "Daten, nicht Quelltext."
                            ),
                        )
                    )

    if "permissions" not in top_level_keys:
        findings.append(
            Finding(
                bot=BOT,
                rule="permissions-missing",
                title="Workflow legt seine Rechte nicht fest",
                severity="medium",
                confidence="high",
                path=path,
                line=1,
                explanation=(
                    "Ohne `permissions:` auf oberster Ebene gelten die Standardrechte des "
                    "Repos. Die koennen weit sein, sind an einer anderen Stelle "
                    "eingestellt und aendern sich, ohne dass diese Datei sich aendert."
                ),
                remediation=(
                    "`permissions: contents: read` auf oberster Ebene setzen und je Job "
                    "nur das erweitern, was gebraucht wird."
                ),
            )
        )
    return findings


def run(root: str, excludes=()) -> list[Finding]:
    skip = {e.strip("/") for e in excludes if e.strip()}
    findings: list[Finding] = []
    for rel, full in iter_workflow_files(root):
        if rel in skip:
            continue
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError:
            continue
        findings.extend(scan_workflow(text, rel))
    return findings
