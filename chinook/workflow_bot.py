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
# `run:` ist die Shell, `script:` ist `actions/github-script` -- beide fuehren
# aus, was in ihnen steht. Ein Wert in `with:` einer anderen Action wird
# dagegen als Eingabe uebergeben und ist nicht von sich aus gefaehrlich;
# deshalb steht der Fall in `docs/grenzen.md` und nicht in dieser Regel.
_RUN_START = re.compile(r"^(\s*)(?:-\s*)?(?:run|script):\s*(.*)$")
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
    """Zeilennummern (1-basiert), die zu einem `run:`- oder `script:`-Block gehoeren."""
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
                            title="Action not pinned to a commit",
                            severity="info" if first_party else "medium",
                            confidence="high",
                            path=path,
                            line=number,
                            explanation=(
                                f"`{reference}` points at "
                                + (f"the movable ref `{ref}`" if ref else "no ref")
                                + ". Whoever moves that tag changes what runs in this "
                                "repository with its permissions."
                            ),
                            remediation=(
                                "Pin the full 40-character commit SHA and put the readable "
                                "tag behind it as a comment."
                            ),
                        )
                    )

        if re.match(r"^\s*permissions:\s*write-all\s*$", line):
            findings.append(
                Finding(
                    bot=BOT,
                    rule="permissions-write-all",
                    title="Workflow runs with every write permission",
                    severity="high",
                    confidence="high",
                    path=path,
                    line=number,
                    explanation=(
                        "`permissions: write-all` gives GITHUB_TOKEN write access to "
                        "everything -- contents, packages, deployments. Every step in the "
                        "workflow inherits it, a third-party action included."
                    ),
                    remediation=(
                        "Set `permissions: contents: read` and widen single permissions "
                        "only where a step actually needs them."
                    ),
                )
            )

        if has_pr_target and "github.event.pull_request.head" in line and re.search(r"^\s*ref:", line):
            findings.append(
                Finding(
                    bot=BOT,
                    rule="pull-request-target-checkout",
                    title="pull_request_target checks out foreign code",
                    severity="critical",
                    confidence="high",
                    path=path,
                    line=number,
                    explanation=(
                        "`pull_request_target` runs with the target repository's secrets. "
                        "Checking out the pull request head inside it runs foreign code "
                        "with those secrets -- anyone who can open a PR takes over the run."
                    ),
                    remediation=(
                        "Either use `pull_request` (no access to secrets), or under "
                        "`pull_request_target` check out the base only and treat the PR "
                        "content as data."
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
                            title="Foreign text is substituted into a script",
                            severity="high",
                            confidence="high",
                            path=path,
                            line=number,
                            explanation=(
                                f"`{context}` is written by whoever wrote the pull request "
                                "or the comment, and is substituted into the script before "
                                "execution -- into the shell in `run:`, into JavaScript in "
                                "`script:`. A backtick or a semicolon in it is a command."
                            ),
                            remediation=(
                                "Pass the value to the step through `env:` and use it in "
                                "the script as a quoted variable. Then it is data, not "
                                "source."
                            ),
                        )
                    )

    if "permissions" not in top_level_keys:
        findings.append(
            Finding(
                bot=BOT,
                rule="permissions-missing",
                title="Workflow does not set its permissions",
                severity="medium",
                confidence="high",
                path=path,
                line=1,
                explanation=(
                    "Without a top-level `permissions:` the repository defaults apply. "
                    "They can be wide, they are configured somewhere else, and they change "
                    "without this file changing."
                ),
                remediation=(
                    "Set `permissions: contents: read` at the top level and widen only "
                    "what a job needs."
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


# Die Regeln dieses Bots stehen in `scan_workflow` verstreut, weil ihre Schwere
# vom Zusammenhang abhaengt. Diese Tabelle beschreibt sie fuer die Website --
# und `checks/test_webseite.py` prueft, dass sie **genau** den Regeln entspricht,
# die der Bot gegen seine Fixtures tatsaechlich meldet. Eine Beschreibung, die
# driften darf, ist eine Beschreibung, die driftet.
REGELN = (
    {
        "name": "pull-request-target-checkout",
        "titel": "pull_request_target checks out foreign code",
        "schwere": "critical",
        "was": (
            "The workflow runs with the target repository's secrets and runs foreign "
            "code inside it. Anyone who can open a pull request takes over the run."
        ),
    },
    {
        "name": "script-injection",
        "titel": "Foreign text is substituted into a script",
        "schwere": "high",
        "was": (
            "A title or comment is substituted into a `run:` or `script:` block "
            "before execution. A backtick in it is then a command."
        ),
    },
    {
        "name": "permissions-write-all",
        "titel": "Workflow runs with every write permission",
        "schwere": "high",
        "was": "Every step inherits it, a third-party action included.",
    },
    {
        "name": "unpinned-action",
        "titel": "Action not pinned to a commit",
        "schwere": "medium",
        "was": (
            "A tag can be moved. Then what runs with this repository's permissions "
            "changes. For `actions/*` this is only an informational note."
        ),
    },
    {
        "name": "permissions-missing",
        "titel": "Workflow does not set its permissions",
        "schwere": "medium",
        "was": (
            "Without `permissions:` the repository defaults apply -- configured "
            "elsewhere and changeable without this file changing."
        ),
    },
)


def regeln() -> list[dict]:
    return [dict(regel) for regel in REGELN]
