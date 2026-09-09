"""Die Gegenprobe: prueft die Pruefungen.

Der teuerste Fehlertyp ist der, der wie Erfolg aussieht -- eine gruene Pruefung,
die nichts beweist. Dagegen hilft nur eins: den Bot absichtlich kaputt machen
und verlangen, dass die Pruefungen **rot** werden. Bleiben sie gruen, ist die
Pruefung wertlos, und dieses Skript sagt das laut.

Aufruf:  python3 -m checks.counterproof
Rueckgabe: 0, wenn jede Mutation gefangen wurde. Sonst 1.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

WURZEL = Path(__file__).resolve().parent.parent
IGNORIEREN = shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".venv")


@dataclass(frozen=True)
class Mutation:
    """Ein absichtlicher Schaden und die Erwartung, dass er auffliegt."""

    name: str
    datei: str
    alt: str
    neu: str
    trifft: str


MUTATIONEN: tuple[Mutation, ...] = (
    Mutation(
        name="redaktion-abgeschaltet",
        datei="chinook/findings.py",
        alt='    return f"{kind}, {len(text)} Zeichen (Wert wird nicht ausgegeben)"',
        neu='    return f"{kind}: {text}"',
        trifft="der Bot gibt den gefundenen Wert aus",
    ),
    Mutation(
        name="schweregrad-pruefung-entfernt",
        datei="chinook/findings.py",
        alt='        if self.severity not in SEVERITIES:',
        neu='        if False:',
        trifft="ein Befund darf einen erfundenen Schweregrad tragen",
    ),
    Mutation(
        name="schwelle-schlaegt-nie-an",
        datei="chinook/findings.py",
        alt="    return any(severity_rank(f.severity) <= limit for f in findings)",
        neu="    return False",
        trifft="ein kritischer Befund laesst den Lauf trotzdem gruen",
    ),
    Mutation(
        name="alles-ist-ein-platzhalter",
        datei="chinook/secret_bot.py",
        alt='    """Ein Platzhalter ist kein Fund."""',
        neu='    """Ein Platzhalter ist kein Fund."""\n    return True',
        trifft="jeder Fund mittlerer Zuversicht wird weggeworfen",
    ),
    Mutation(
        name="erste-regel-uebersprungen",
        datei="chinook/secret_bot.py",
        alt="        for rule in RULES:",
        neu="        for rule in RULES[1:]:",
        trifft="eine Regel laeuft nicht mehr mit",
    ),
    Mutation(
        name="history-pruefung-abgeschaltet",
        datei="chinook/secret_bot.py",
        alt="def scan_history(root: str, max_commits: int = 500) -> list[Finding]:",
        neu="def scan_history(root: str, max_commits: int = 500) -> list[Finding]:\n    return []",
        trifft="ein Geheimnis in der History bleibt unentdeckt",
    ),
    Mutation(
        name="alles-gilt-als-festgelegt",
        datei="chinook/workflow_bot.py",
        alt="    return bool(_SHA.match(ref))",
        neu="    return True",
        trifft="eine Action auf beweglichem Tag gilt als festgelegt",
    ),
    Mutation(
        name="kein-kontext-ist-unvertraut",
        datei="chinook/workflow_bot.py",
        alt="def untrusted_in(expression: str) -> str | None:",
        neu="def untrusted_in(expression: str) -> str | None:\n    return None",
        trifft="Script Injection wird nicht mehr erkannt",
    ),
    Mutation(
        name="fehlende-rechte-egal",
        datei="chinook/workflow_bot.py",
        alt='    if "permissions" not in top_level_keys:',
        neu="    if False:",
        trifft="ein Workflow ohne permissions gilt als sauber",
    ),
    Mutation(
        name="pull-request-target-ignoriert",
        datei="chinook/workflow_bot.py",
        alt=r'    has_pr_target = any(re.search(r"\bpull_request_target\b", line) for line in lines)',
        neu="    has_pr_target = False",
        trifft="der schwerste Befund des Workflow-Bots faellt weg",
    ),
    Mutation(
        name="exit-code-immer-null",
        datei="chinook/cli.py",
        alt="    if fmt.exceeds(results, args.fail_on):",
        neu="    if False:",
        trifft="der Bot meldet einen Fund, laesst den Lauf aber gruen",
    ),
)


def suite_laeuft(pfad: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "checks", "-t", ".", "-q"],
        cwd=pfad,
        capture_output=True,
        text=True,
    )


def kopie() -> tempfile.TemporaryDirectory:
    handle = tempfile.TemporaryDirectory()
    ziel = Path(handle.name) / "repo"
    shutil.copytree(WURZEL, ziel, ignore=IGNORIEREN)
    return handle


def _ziel(handle: tempfile.TemporaryDirectory) -> Path:
    return Path(handle.name) / "repo"


def grundlauf() -> tuple[bool, str]:
    """Ohne Schaden muss die Suite gruen sein -- sonst faengt sie nachher alles
    aus dem falschen Grund."""
    handle = kopie()
    try:
        ergebnis = suite_laeuft(_ziel(handle))
        return ergebnis.returncode == 0, ergebnis.stderr[-2000:]
    finally:
        handle.cleanup()


def pruefe(mutation: Mutation) -> tuple[bool, str]:
    """Wahr, wenn die Mutation gefangen wurde."""
    handle = kopie()
    try:
        ziel = _ziel(handle)
        datei = ziel / mutation.datei
        original = datei.read_text(encoding="utf-8")
        if mutation.alt not in original:
            return False, "der zu mutierende Text steht nicht in der Datei"
        veraendert = original.replace(mutation.alt, mutation.neu, 1)
        # Ohne diese Zusicherung kann eine Mutation nichts aendern und die
        # Gegenprobe faellt trotzdem ein Urteil.
        if veraendert == original:
            return False, "die Mutation hat die Datei nicht veraendert"
        datei.write_text(veraendert, encoding="utf-8")
        ergebnis = suite_laeuft(ziel)
        if ergebnis.returncode == 0:
            return False, "die Pruefungen blieben gruen"
        return True, ""
    finally:
        handle.cleanup()


def main() -> int:
    print("Gegenprobe: jede Mutation muss die Pruefungen rot machen.\n")
    gruen, meldung = grundlauf()
    if not gruen:
        print("Grundlauf ist bereits rot -- die Gegenprobe sagt so nichts aus.")
        print(meldung)
        return 1
    print("Grundlauf gruen.\n")

    entkommen = []
    for mutation in MUTATIONEN:
        gefangen, warum = pruefe(mutation)
        zeichen = "gefangen " if gefangen else "ENTKOMMEN"
        print(f"  [{zeichen}] {mutation.name}: {mutation.trifft}")
        if not gefangen:
            print(f"              -> {warum}")
            entkommen.append(mutation)

    print()
    if entkommen:
        print(
            f"{len(entkommen)} von {len(MUTATIONEN)} Mutationen sind entkommen. "
            "Die zugehoerigen Pruefungen beweisen nichts."
        )
        return 1
    print(f"Alle {len(MUTATIONEN)} Mutationen gefangen.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
