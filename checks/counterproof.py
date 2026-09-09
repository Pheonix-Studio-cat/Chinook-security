"""Die Gegenprobe: prueft die Pruefungen.

Der teuerste Fehlertyp ist der, der wie Erfolg aussieht -- eine gruene Pruefung,
die nichts beweist. Dagegen hilft nur eins: den Bot absichtlich kaputt machen
und verlangen, dass die Pruefungen **rot** werden. Bleiben sie gruen, ist die
Pruefung wertlos, und dieses Skript sagt das laut.

Aufruf:  python3 -m checks.counterproof [--json datei]
Rueckgabe: 0, wenn jede Mutation gefangen wurde. Sonst 1.

Mit `--json` schreibt sie das Ergebnis maschinenlesbar mit -- das ist die
zweite Aufgabe des Aufsehers: nicht nur Befunde einordnen, sondern **die Bots
kontrollieren**. Die Website zeigt daraus, welche Pruefung gegengeprueft ist.
"""

from __future__ import annotations

import argparse
import json
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
    Mutation(
        name="osv-fehler-verschluckt",
        datei="chinook/dependency_bot.py",
        alt='            raise OsvUnavailable(f"OSV nicht erreichbar: {type(fehler).__name__}: {fehler}") from fehler',
        neu="            continue",
        trifft="ein misslungener Abruf sieht aus wie ein sauberes Ergebnis",
    ),
    Mutation(
        name="osv-antwort-ungeprueft",
        datei="chinook/dependency_bot.py",
        alt="        if not isinstance(ergebnisse, list) or len(ergebnisse) != len(teil):",
        neu="        if False:",
        trifft="eine verschobene Antwort schreibt die Schwachstelle dem falschen Paket zu",
    ),
    Mutation(
        name="unfestgelegte-version-gilt-als-festgelegt",
        datei="chinook/dependency_bot.py",
        alt='        if operator in ("==", "===") and version:',
        neu="        if version:",
        trifft="eine Versionsspanne wird als genaue Version abgefragt",
    ),
    Mutation(
        name="unbewiesen-gilt-als-bestanden",
        datei="chinook/cli.py",
        alt="        return UNBEWIESEN",
        neu="        return OK",
        trifft="ein Lauf ohne Antwort meldet Erfolg",
    ),
    Mutation(
        name="code-regel-uebersprungen",
        datei="chinook/code_bot.py",
        alt="        for rule in RULES:",
        neu="        for rule in RULES[1:]:",
        trifft="eine Code-Regel laeuft nicht mehr mit",
    ),
    Mutation(
        name="dateityp-egal",
        datei="chinook/code_bot.py",
        alt="            if suffix not in rule.suffixes:",
        neu="            if False:",
        trifft="Python-Regeln greifen in JavaScript und umgekehrt",
    ),
    Mutation(
        name="lizenztext-nicht-erkannt",
        datei="chinook/license_bot.py",
        alt='    """Grobe Familie eines Lizenztexts, oder None. Keine Rechtsaussage."""',
        neu='    """Grobe Familie eines Lizenztexts, oder None. Keine Rechtsaussage."""\n    return None',
        trifft="der Widerspruch zwischen Erklaerung und Lizenzdatei faellt weg",
    ),
    Mutation(
        name="widerspruch-ignoriert",
        datei="chinook/license_bot.py",
        alt="    if datei_familie and erklaerte_familie and datei_familie != erklaerte_familie:",
        neu="    if False:",
        trifft="erklaerte Lizenz und beiliegender Text duerfen auseinandergehen",
    ),
    Mutation(
        name="toter-lizenzverweis-egal",
        datei="chinook/license_bot.py",
        alt="                if not os.path.isfile(os.path.join(wurzel, ziel)):",
        neu="                if False:",
        trifft="ein Lizenzverweis ins Leere gilt als in Ordnung",
    ),
    Mutation(
        name="aufseher-verliert-befunde",
        datei="chinook/overseer.py",
        alt="    for befund in befunde:",
        neu="    for befund in bewertungen:",
        trifft="die Antwort des Modells bestimmt, welche Befunde uebrig bleiben",
    ),
    Mutation(
        name="erfundener-fingerabdruck-akzeptiert",
        datei="chinook/overseer.py",
        alt="        if fingerabdruck not in erlaubt or einschaetzung not in EINSCHAETZUNGEN:",
        neu="        if False:",
        trifft="das Modell darf Befunde erfinden und Einschaetzungen ausdenken",
    ),
    Mutation(
        name="ablehnung-gilt-als-ergebnis",
        datei="chinook/overseer.py",
        alt='    if antwort.get("stop_reason") == "refusal":',
        neu="    if False:",
        trifft="eine Ablehnung des Modells sieht aus wie eine Einschaetzung",
    ),
    Mutation(
        name="begruendung-ungefiltert",
        datei="chinook/overseer.py",
        alt='    text = _STEUERZEICHEN.sub(" ", text).strip()',
        neu="    text = text.strip()",
        trifft="Steuerzeichen aus der Modellantwort landen im Bericht",
    ),
    Mutation(
        name="require-wirkungslos",
        datei="chinook/cli.py",
        alt="    if not gelaufen and args.require:",
        neu="    if False:",
        trifft="--require verlangt eine Einschaetzung und nimmt keine Antwort hin",
    ),
    Mutation(
        name="regel-fehlt-auf-der-seite",
        datei="webseite/build.py",
        alt="    for regel in regeln:",
        neu="    for regel in regeln[1:]:",
        trifft="die Website beschreibt eine Regel nicht, die der Bot anwendet",
    ),
    Mutation(
        name="seite-ohne-maskierung",
        datei="webseite/build.py",
        alt="    return html.escape(str(text), quote=False)",
        neu="    return str(text)",
        trifft="fremder Text landet ungefiltert im HTML",
    ),
    Mutation(
        name="gegenprobe-schoengerechnet",
        datei="webseite/build.py",
        alt='    gefangen = daten.get("gefangen", 0)',
        neu='    gefangen = daten.get("gesamt", 0)',
        trifft="die Seite meldet alle Mutationen als gefangen, auch die entkommenen",
    ),
    Mutation(
        name="paketblock-nicht-erkannt",
        datei="chinook/dependency_bot.py",
        alt='        if roh.strip() == "[[package]]":',
        neu="        if False:",
        trifft="poetry.lock und Cargo.lock werden gar nicht mehr gelesen",
    ),
    Mutation(
        name="npm-name-mit-version",
        datei="chinook/dependency_bot.py",
        alt="    return spec[:trenner]",
        neu="    return spec",
        trifft="yarn und pnpm fragen nach einem Paketnamen, den es nicht gibt",
    ),
    Mutation(
        name="pnpm-liest-die-ganze-datei",
        datei="chinook/dependency_bot.py",
        alt="        if not im_paketteil:",
        neu="        if False:",
        trifft="pnpm-Einstellungen werden fuer Pakete gehalten",
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


def _schreibe(pfad: str, nutzlast: dict) -> None:
    ziel = Path(pfad)
    if ziel.parent != Path(""):
        ziel.parent.mkdir(parents=True, exist_ok=True)
    ziel.write_text(json.dumps(nutzlast, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    zerleger = argparse.ArgumentParser(
        prog="checks.counterproof",
        description="Macht die Bots absichtlich kaputt und verlangt rote Pruefungen.",
    )
    zerleger.add_argument("--json", dest="json_out", default="", help="Ergebnis als JSON")
    args = zerleger.parse_args(argv)

    print("Gegenprobe: jede Mutation muss die Pruefungen rot machen.\n")
    ergebnis = {
        "schema_version": "1",
        "bot": "counterproof",
        "grundlauf": "",
        "gesamt": len(MUTATIONEN),
        "gefangen": 0,
        "mutationen": [],
    }

    gruen, meldung = grundlauf()
    ergebnis["grundlauf"] = "gruen" if gruen else "rot"
    if not gruen:
        print("Grundlauf ist bereits rot -- die Gegenprobe sagt so nichts aus.")
        print(meldung)
        if args.json_out:
            _schreibe(args.json_out, ergebnis)
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
        ergebnis["mutationen"].append(
            {
                "name": mutation.name,
                "datei": mutation.datei,
                "trifft": mutation.trifft,
                "gefangen": gefangen,
                "grund": "" if gefangen else warum,
            }
        )
    ergebnis["gefangen"] = ergebnis["gesamt"] - len(entkommen)
    if args.json_out:
        _schreibe(args.json_out, ergebnis)

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
