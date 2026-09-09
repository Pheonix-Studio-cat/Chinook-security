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
        title="Text wird im Python-Quelltext als Programm ausgefuehrt",
        pattern=re.compile(r"(?<![\w.])(?:eval|exec)\s*\("),
        suffixes=PYTHON,
        severity="high",
        confidence="medium",
        explanation=(
            "`eval` und `exec` fuehren Text als Programm aus. Kommt der Text aus einer "
            "Anfrage, einer Datei oder einer Umgebungsvariablen, fuehrt der Aufrufer aus, "
            "was er will."
        ),
        remediation=(
            "Fuer Daten `json.loads` oder `ast.literal_eval` verwenden. Fuer Verzweigungen "
            "eine Zuordnungstabelle statt erzeugten Quelltext."
        ),
    ),
    Rule(
        name="python-subprocess-shell",
        title="subprocess laesst die Shell den Befehl zusammensetzen",
        pattern=re.compile(r"shell\s*=\s*True"),
        suffixes=PYTHON,
        severity="high",
        confidence="medium",
        explanation=(
            "Steht der Schalter `shell` auf wahr, geht der Befehl durch die Shell. Ein "
            "Semikolon oder ein "
            "Backtick in einem eingesetzten Wert ist dann ein eigener Befehl."
        ),
        remediation=(
            "Den Befehl als Liste uebergeben (`['git', 'log', pfad]`) und den "
            "Shell-Schalter weglassen. Dann ist der Wert ein Argument, kein Quelltext."
        ),
    ),
    Rule(
        name="python-pickle-load",
        title="pickle laedt fremde Daten",
        pattern=re.compile(r"(?<![\w.])pickle\.loads?\s*\("),
        suffixes=PYTHON,
        severity="high",
        confidence="medium",
        explanation=(
            "`pickle` fuehrt beim Laden Quelltext aus, der in den Daten steht. Eine "
            "pickle-Datei aus fremder Hand ist ein Programm aus fremder Hand."
        ),
        remediation="JSON verwenden, oder die Daten signieren und die Signatur vor dem Laden pruefen.",
    ),
    Rule(
        name="python-yaml-unsafe",
        title="yaml.load ohne sicheren Loader",
        pattern=re.compile(r"yaml\.load\s*\((?![^)]*Safe)"),
        suffixes=PYTHON,
        severity="high",
        confidence="high",
        explanation=(
            "`yaml.load` ohne `Loader=SafeLoader` kann beliebige Python-Objekte erzeugen "
            "und dabei Quelltext ausfuehren."
        ),
        remediation="`yaml.safe_load(...)` verwenden, oder `Loader=yaml.SafeLoader` angeben.",
    ),
    Rule(
        name="python-tls-verify-off",
        title="TLS-Pruefung abgeschaltet",
        pattern=re.compile(r"verify\s*=\s*False"),
        suffixes=PYTHON,
        severity="high",
        confidence="high",
        explanation=(
            "Steht `verify` auf falsch, wird jedes Zertifikat angenommen. Damit ist die Verbindung "
            "verschluesselt, aber der Gegenueber ist beliebig."
        ),
        remediation=(
            "Die Pruefung eingeschaltet lassen. Bei einer eigenen CA deren Zertifikat "
            "ueber `verify='/pfad/zur/ca.pem'` angeben."
        ),
    ),
    Rule(
        name="python-tempfile-mktemp",
        title="tempfile.mktemp erzeugt eine Wettlaufbedingung",
        pattern=re.compile(r"tempfile\.mktemp\s*\("),
        suffixes=PYTHON,
        severity="medium",
        confidence="high",
        explanation=(
            "`mktemp` gibt nur einen Namen zurueck. Zwischen Name und Oeffnen kann ein "
            "anderer Prozess die Datei anlegen."
        ),
        remediation="`tempfile.NamedTemporaryFile` oder `tempfile.mkstemp` verwenden.",
    ),
    Rule(
        name="js-eval",
        title="Text wird im JavaScript als Programm ausgefuehrt",
        pattern=re.compile(r"(?<![\w.])(?:eval\s*\(|new\s+Function\s*\()"),
        suffixes=JAVASCRIPT,
        severity="high",
        confidence="medium",
        explanation=(
            "Beide fuehren Text als Programm aus. Stammt der Text aus einer Eingabe, "
            "fuehrt der Absender aus, was er will."
        ),
        remediation="`JSON.parse` fuer Daten; fuer Verzweigungen ein Objekt als Zuordnungstabelle.",
    ),
    Rule(
        name="js-child-process-shell",
        title="child_process.exec mit zusammengesetztem Befehl",
        pattern=re.compile(r"(?:exec)(?:Sync)?\s*\(\s*[`'\"][^)]*(?:\$\{|['\"]\s*\+)"),
        suffixes=JAVASCRIPT,
        severity="high",
        confidence="high",
        explanation=(
            "`exec` gibt die Zeichenkette an die Shell. Ein eingesetzter Wert wird damit "
            "zu Quelltext, nicht zu einem Argument."
        ),
        remediation=(
            "`execFile` oder `spawn` mit einem Argument-Array verwenden. Die Shell bleibt "
            "dann aussen vor."
        ),
    ),
    Rule(
        name="js-innerhtml",
        title="Zuweisung an innerHTML",
        pattern=re.compile(r"\.innerHTML\s*=|\bdocument\.write\s*\("),
        suffixes=JAVASCRIPT,
        severity="medium",
        confidence="medium",
        explanation=(
            "Was hier hineingeschrieben wird, wird als HTML ausgewertet -- samt "
            "`<script>` und Ereignis-Attributen. Das ist der klassische Weg zu XSS."
        ),
        remediation="`textContent` verwenden, oder die Knoten einzeln erzeugen und anhaengen.",
    ),
    Rule(
        name="js-tls-verify-off",
        title="TLS-Pruefung abgeschaltet",
        pattern=re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
        suffixes=JAVASCRIPT,
        severity="high",
        confidence="high",
        explanation="Jedes Zertifikat wird angenommen; der Gegenueber ist damit beliebig.",
        remediation="Die Pruefung eingeschaltet lassen und eine eigene CA ueber `ca:` mitgeben.",
    ),
    Rule(
        name="shell-curl-pipe-shell",
        title="Heruntergeladenes wird direkt ausgefuehrt",
        pattern=re.compile(r"(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|d)?sh\b"),
        suffixes=SHELL,
        severity="high",
        confidence="high",
        explanation=(
            "Was an dieser Adresse steht, laeuft ungeprueft mit den Rechten des "
            "Aufrufers -- heute, morgen, und nach jeder Aenderung dort."
        ),
        remediation=(
            "Herunterladen, Pruefsumme gegen einen bekannten Wert pruefen, dann "
            "ausfuehren. Oder ein Paket aus einer Quelle installieren, die signiert ist."
        ),
    ),
    Rule(
        name="shell-eval",
        title="eval in einem Shell-Skript",
        pattern=re.compile(r"^\s*eval\s+[^\n]"),
        suffixes=SHELL,
        severity="medium",
        confidence="medium",
        explanation="`eval` setzt die Zeichenkette erneut als Befehl zusammen; eingesetzte Werte werden zu Quelltext.",
        remediation="Arrays fuer Argumente verwenden und ohne `eval` aufrufen.",
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
