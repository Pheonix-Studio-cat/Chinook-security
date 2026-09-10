"""Code-Bot -- Muster im Quelltext, die erfahrungsgemaess Loecher sind.

Musterbasiert und ohne Datenflussanalyse. Das heisst: er sieht, **dass** eine
gefaehrliche Stelle da ist, nicht **ob** an ihr etwas Fremdes ankommt. Regeln
mit mittlerer Zuversicht sind entsprechend gekennzeichnet, und `docs/grenzen.md`
schreibt es aus, statt es zu verschweigen.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .findings import Finding

BOT = "code-bot"

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "vendor"}
MAX_FILE_BYTES = 2_000_000

PYTHON = (".py",)
JAVASCRIPT = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
SHELL = (".sh", ".bash")


@dataclass(frozen=True)
class Rule:
    name: str
    title: str
    pattern: re.Pattern
    suffixes: tuple
    severity: str
    confidence: str
    explanation: str
    remediation: str


RULES: tuple[Rule, ...] = (
    Rule(
        name="python-eval-exec",
        title="Text is executed as a program in Python",
        pattern=re.compile(r"(?<![\w.])(?:eval|exec)\s*\("),
        suffixes=PYTHON,
        severity="high",
        confidence="medium",
        explanation=(
            "`eval` and `exec` run text as a program. If the text comes from a "
            "request, a file or an environment variable, the caller runs whatever "
            "they like."
        ),
        remediation=(
            "Use `json.loads` or `ast.literal_eval` for data. For branching, use a "
            "lookup table instead of generated source."
        ),
    ),
    Rule(
        name="python-subprocess-shell",
        title="subprocess lets the shell assemble the command",
        pattern=re.compile(r"shell\s*=\s*True"),
        suffixes=PYTHON,
        severity="high",
        confidence="medium",
        explanation=(
            "With the `shell` switch on, the command goes through the shell. A "
            "semicolon or a backtick in a substituted value is then a command of "
            "its own."
        ),
        remediation=(
            "Pass the command as a list (`['git', 'log', path]`) and leave the "
            "shell switch out. Then the value is an argument, not source."
        ),
    ),
    Rule(
        name="python-pickle-load",
        title="pickle loads foreign data",
        pattern=re.compile(r"(?<![\w.])pickle\.loads?\s*\("),
        suffixes=PYTHON,
        severity="high",
        confidence="medium",
        explanation=(
            "`pickle` executes source contained in the data while loading. A "
            "pickle file from a stranger is a program from a stranger."
        ),
        remediation="Use JSON, or sign the data and verify the signature before loading.",
    ),
    Rule(
        name="python-yaml-unsafe",
        title="yaml.load without a safe loader",
        pattern=re.compile(r"yaml\.load\s*\((?![^)]*Safe)"),
        suffixes=PYTHON,
        severity="high",
        confidence="high",
        explanation=(
            "`yaml.load` without `Loader=SafeLoader` can construct arbitrary Python "
            "objects and execute source in the process."
        ),
        remediation="Use `yaml.safe_load(...)`, or pass `Loader=yaml.SafeLoader`.",
    ),
    Rule(
        name="python-tls-verify-off",
        title="TLS verification switched off",
        pattern=re.compile(r"verify\s*=\s*False"),
        suffixes=PYTHON,
        severity="high",
        confidence="high",
        explanation=(
            "With `verify` set to false every certificate is accepted. The "
            "connection is encrypted, but the other end is anyone."
        ),
        remediation=(
            "Leave verification on. For a private CA, pass its certificate through "
            "`verify='/path/to/ca.pem'`."
        ),
    ),
    Rule(
        name="python-tempfile-mktemp",
        title="tempfile.mktemp creates a race condition",
        pattern=re.compile(r"tempfile\.mktemp\s*\("),
        suffixes=PYTHON,
        severity="medium",
        confidence="high",
        explanation=(
            "`mktemp` returns only a name. Between the name and the open, another "
            "process can create the file."
        ),
        remediation="Use `tempfile.NamedTemporaryFile` or `tempfile.mkstemp`.",
    ),
    Rule(
        name="js-eval",
        title="Text is executed as a program in JavaScript",
        pattern=re.compile(r"(?<![\w.])(?:eval\s*\(|new\s+Function\s*\()"),
        suffixes=JAVASCRIPT,
        severity="high",
        confidence="medium",
        explanation=(
            "Both run text as a program. If the text comes from an input, the "
            "sender runs whatever they like."
        ),
        remediation="`JSON.parse` for data; an object as a lookup table for branching.",
    ),
    Rule(
        name="js-child-process-shell",
        title="child_process.exec with an assembled command",
        pattern=re.compile(r"(?:exec)(?:Sync)?\s*\(\s*[`'\"][^)]*(?:\$\{|['\"]\s*\+)"),
        suffixes=JAVASCRIPT,
        severity="high",
        confidence="high",
        explanation=(
            "`exec` hands the string to the shell. A substituted value therefore "
            "becomes source, not an argument."
        ),
        remediation=(
            "Use `execFile` or `spawn` with an argument array. The shell then stays "
            "out of it."
        ),
    ),
    Rule(
        name="js-innerhtml",
        title="Assignment to innerHTML",
        pattern=re.compile(r"\.innerHTML\s*=|\bdocument\.write\s*\("),
        suffixes=JAVASCRIPT,
        severity="medium",
        confidence="medium",
        explanation=(
            "Whatever is written here is parsed as HTML -- `<script>` and event "
            "attributes included. That is the classic route to XSS."
        ),
        remediation="Use `textContent`, or create and append the nodes individually.",
    ),
    Rule(
        name="js-tls-verify-off",
        title="TLS verification switched off",
        pattern=re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
        suffixes=JAVASCRIPT,
        severity="high",
        confidence="high",
        explanation="Every certificate is accepted; the other end is therefore anyone.",
        remediation="Leave verification on and pass a private CA through `ca:`.",
    ),
    Rule(
        name="shell-curl-pipe-shell",
        title="What was downloaded is run straight away",
        pattern=re.compile(r"(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|d)?sh\b"),
        suffixes=SHELL,
        severity="high",
        confidence="high",
        explanation=(
            "Whatever is at that address runs unchecked with the caller's "
            "permissions -- today, tomorrow, and after every change made there."
        ),
        remediation=(
            "Download it, check the checksum against a known value, then run it. "
            "Or install a package from a source that is signed."
        ),
    ),
    Rule(
        name="shell-eval",
        title="eval in a shell script",
        pattern=re.compile(r"^\s*eval\s+[^\n]"),
        suffixes=SHELL,
        severity="medium",
        confidence="medium",
        explanation="`eval` reassembles the string as a command; substituted values become source.",
        remediation="Use arrays for arguments and call without `eval`.",
    ),
)

_KOMMENTAR = re.compile(r"^\s*(?:#|//|\*|/\*)")


def scan_text(text: str, path: str) -> list[Finding]:
    suffix = os.path.splitext(path)[1].lower()
    befunde: list[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if len(line) > 4000 or _KOMMENTAR.match(line):
            continue
        for rule in RULES:
            if suffix not in rule.suffixes:
                continue
            if rule.pattern.search(line):
                befunde.append(
                    Finding(
                        bot=BOT,
                        rule=rule.name,
                        title=rule.title,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        path=path,
                        line=number,
                        explanation=rule.explanation,
                        remediation=rule.remediation,
                    )
                )
    return befunde


def iter_files(root: str, excludes=()):
    skip = SKIP_DIRS | {e.strip("/") for e in excludes if e.strip()}
    suffixe = set(PYTHON) | set(JAVASCRIPT) | set(SHELL)
    wurzel = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(wurzel):
        dirnames[:] = [d for d in sorted(dirnames) if d not in skip]
        for name in sorted(filenames):
            if os.path.splitext(name)[1].lower() not in suffixe:
                continue
            voll = os.path.join(dirpath, name)
            rel = os.path.relpath(voll, wurzel).replace(os.sep, "/")
            if any(rel == s or rel.startswith(f"{s}/") for s in skip):
                continue
            try:
                if os.path.getsize(voll) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield rel, voll


def run(root: str, excludes=()) -> list[Finding]:
    befunde: list[Finding] = []
    for rel, voll in iter_files(root, excludes):
        try:
            with open(voll, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError:
            continue
        befunde.extend(scan_text(text, rel))
    return befunde


_SPRACHE = {PYTHON: "Python", JAVASCRIPT: "JavaScript / TypeScript", SHELL: "Shell"}


def regeln() -> list[dict]:
    """Die Regeln dieses Bots, abgeleitet aus `RULES`."""
    return [
        {
            "name": rule.name,
            "titel": rule.title,
            "schwere": rule.severity,
            "zuversicht": rule.confidence,
            "sprache": _SPRACHE.get(rule.suffixes, ", ".join(rule.suffixes)),
            "was": rule.explanation,
        }
        for rule in RULES
    ]
