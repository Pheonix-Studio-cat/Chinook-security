"""Dependency-Bot -- bekannte Schwachstellen in den Abhaengigkeiten.

Er liest die Sperrdateien (nicht die Wunschlisten) und fragt **OSV.dev**, die
offene Schwachstellendatenbank. Kein Schluessel noetig, keine Anmeldung.

**Ein fehlgeschlagener Abruf ist kein leeres Ergebnis.** Wer nicht fragen
konnte, weiss nichts -- und ein Bot, der daraus ein gruenes Haekchen macht, ist
genau die Sorte Pruefung, gegen die dieses Projekt gebaut ist. Deshalb wirft
`query_osv` bei jedem Fehler `OsvUnavailable`, und die Kommandozeile beendet
sich dann mit Rueckgabewert **2**: nicht "sauber", sondern "beweist nichts".
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

from .findings import Finding

BOT = "dependency-bot"

OSV_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://osv.dev/vulnerability/"
BATCH = 500
TIMEOUT = 30

MANIFESTS = ("requirements.txt", "package-lock.json", "go.mod")
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


class OsvUnavailable(RuntimeError):
    """Die Abfrage ist nicht durchgekommen. Der Lauf beweist nichts."""


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    path: str
    line: int


def _line_of(text: str, needle: str, default: int = 1) -> int:
    for number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return number
    return default


_REQUIREMENT = re.compile(
    r"""^\s*
    (?P<name>[A-Za-z0-9][A-Za-z0-9._\-]*)      # Paketname
    (?:\[[^\]]+\])?                            # Extras, egal welche
    \s*(?P<operator>==|===|>=|<=|~=|>|<|!=)?\s*
    (?P<version>[A-Za-z0-9][A-Za-z0-9._\-+!]*)?
    """,
    re.VERBOSE,
)


def parse_requirements(text: str, path: str) -> tuple[list[Dependency], list[Finding]]:
    """`requirements.txt`. Nur `==` gilt als festgelegt."""
    deps: list[Dependency] = []
    lose: list[Finding] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith("-") or line.startswith("."):
            continue
        if "://" in line or line.startswith("git+"):
            continue
        match = _REQUIREMENT.match(line)
        if not match:
            continue
        name = match.group("name")
        operator = match.group("operator")
        version = match.group("version")
        if operator in ("==", "===") and version:
            deps.append(Dependency(name, version, "PyPI", path, number))
        else:
            lose.append(
                Finding(
                    bot=BOT,
                    rule="dependency-unpinned",
                    title="Abhaengigkeit ist nicht auf eine Version festgelegt",
                    severity="low",
                    confidence="high",
                    path=path,
                    line=number,
                    explanation=(
                        f"`{name}` ist ohne `==` angegeben. Damit installiert jeder Lauf "
                        "moeglicherweise etwas anderes, und diese Pruefung sagt nichts "
                        "ueber das aus, was tatsaechlich installiert wird."
                    ),
                    remediation=(
                        "Auf eine genaue Version festlegen (`==`) oder eine Sperrdatei "
                        "verwenden, die der Lauf tatsaechlich installiert."
                    ),
                )
            )
    return deps, lose


def parse_package_lock(text: str, path: str) -> tuple[list[Dependency], list[Finding]]:
    """`package-lock.json`, Sperrdatei-Version 1 wie 2/3."""
    try:
        daten = json.loads(text)
    except json.JSONDecodeError:
        return [], []
    deps: list[Dependency] = []

    def aufnehmen(name: str, version: str, schluessel: str) -> None:
        if name and version:
            deps.append(Dependency(name, version, "npm", path, _line_of(text, f'"{schluessel}"')))

    pakete = daten.get("packages")
    if isinstance(pakete, dict):
        for schluessel, eintrag in pakete.items():
            if not schluessel or not isinstance(eintrag, dict) or eintrag.get("link"):
                continue
            name = eintrag.get("name") or schluessel.rsplit("node_modules/", 1)[-1]
            aufnehmen(name, eintrag.get("version", ""), schluessel)
        return deps, []

    def absteigen(knoten: dict) -> None:
        for name, eintrag in knoten.items():
            if not isinstance(eintrag, dict):
                continue
            aufnehmen(name, eintrag.get("version", ""), name)
            unter = eintrag.get("dependencies")
            if isinstance(unter, dict):
                absteigen(unter)

    if isinstance(daten.get("dependencies"), dict):
        absteigen(daten["dependencies"])
    return deps, []


_GO_REQUIRE = re.compile(r"^\s*(?:require\s+)?(?P<name>[^\s/]+(?:/[^\s]+)*)\s+(?P<version>v\d[^\s]*)")


def parse_go_mod(text: str, path: str) -> tuple[list[Dependency], list[Finding]]:
    deps: list[Dependency] = []
    im_block = False
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("//", 1)[0].rstrip()
        if not line.strip():
            continue
        if re.match(r"^\s*require\s*\($", line):
            im_block = True
            continue
        if im_block and line.strip() == ")":
            im_block = False
            continue
        if not im_block and not line.strip().startswith("require "):
            continue
        match = _GO_REQUIRE.match(line)
        if match:
            deps.append(
                Dependency(match.group("name"), match.group("version"), "Go", path, number)
            )
    return deps, []


PARSER = {
    "requirements.txt": parse_requirements,
    "package-lock.json": parse_package_lock,
    "go.mod": parse_go_mod,
}


def collect(root: str, excludes=()) -> tuple[list[Dependency], list[Finding]]:
    """Findet die Sperrdateien und liest sie."""
    import os

    skip = SKIP_DIRS | {e.strip("/") for e in excludes if e.strip()}
    deps: list[Dependency] = []
    lose: list[Finding] = []
    wurzel = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(wurzel):
        dirnames[:] = [d for d in sorted(dirnames) if d not in skip]
        rel_dir = os.path.relpath(dirpath, wurzel).replace(os.sep, "/")
        if rel_dir != "." and (rel_dir in skip or rel_dir.split("/")[0] in skip):
            continue
        for name in sorted(filenames):
            if name not in PARSER:
                continue
            rel = os.path.relpath(os.path.join(dirpath, name), wurzel).replace(os.sep, "/")
            if any(rel == s or rel.startswith(f"{s}/") for s in skip):
                continue
            try:
                with open(os.path.join(dirpath, name), "r", encoding="utf-8", errors="replace") as h:
                    text = h.read()
            except OSError:
                continue
            gefunden, hinweise = PARSER[name](text, rel)
            deps.extend(gefunden)
            lose.extend(hinweise)
    return deps, lose


def query_osv(deps, url: str = OSV_URL, timeout: int = TIMEOUT) -> dict[int, list[str]]:
    """Fragt OSV nach Schwachstellen. Wirft `OsvUnavailable`, wenn das misslingt.

    Rueckgabe: Index in `deps` -> Liste von Advisory-Kennungen.
    """
    treffer: dict[int, list[str]] = {}
    liste = list(deps)
    for anfang in range(0, len(liste), BATCH):
        teil = liste[anfang : anfang + BATCH]
        koerper = json.dumps(
            {
                "queries": [
                    {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
                    for d in teil
                ]
            }
        ).encode("utf-8")
        anfrage = urllib.request.Request(
            url, data=koerper, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(anfrage, timeout=timeout) as antwort:
                daten = json.load(antwort)
        except (urllib.error.URLError, OSError, ValueError) as fehler:
            raise OsvUnavailable(f"OSV nicht erreichbar: {type(fehler).__name__}: {fehler}") from fehler
        ergebnisse = daten.get("results")
        if not isinstance(ergebnisse, list) or len(ergebnisse) != len(teil):
            raise OsvUnavailable(
                "OSV hat eine Antwort geschickt, die nicht zur Anfrage passt "
                f"({len(ergebnisse) if isinstance(ergebnisse, list) else 'kein results'} "
                f"statt {len(teil)} Ergebnisse)."
            )
        for versatz, ergebnis in enumerate(ergebnisse):
            vulns = (ergebnis or {}).get("vulns") or []
            kennungen = [v.get("id", "") for v in vulns if isinstance(v, dict) and v.get("id")]
            if kennungen:
                treffer[anfang + versatz] = kennungen
    return treffer


def to_findings(deps, treffer: dict[int, list[str]]) -> list[Finding]:
    befunde: list[Finding] = []
    for index, kennungen in sorted(treffer.items()):
        dep = deps[index]
        erste = kennungen[0]
        befunde.append(
            Finding(
                bot=BOT,
                rule="known-vulnerability",
                title="Abhaengigkeit mit bekannter Schwachstelle",
                # Chinook stuft nicht selbst ein: jede bekannte Schwachstelle
                # ist "hoch". Das Einordnen ist Sache des Aufsehers, nicht eine
                # Zahl, die wir uns ausdenken.
                severity="high",
                confidence="high",
                path=dep.path,
                line=dep.line,
                explanation=(
                    f"`{dep.name}` {dep.version} ({dep.ecosystem}) ist laut OSV von "
                    f"{len(kennungen)} bekannten Schwachstelle(n) betroffen: "
                    + ", ".join(kennungen[:5])
                    + ("" if len(kennungen) <= 5 else " u. a.")
                ),
                remediation=(
                    "Auf eine Version aktualisieren, die die Advisories nicht mehr "
                    f"betrifft. Einzelheiten: {OSV_VULN_URL}{erste}"
                ),
                evidence=f"{len(kennungen)} Advisory(s)",
            )
        )
    return befunde


def run(root: str, excludes=(), url: str = OSV_URL, timeout: int = TIMEOUT) -> list[Finding]:
    deps, lose = collect(root, excludes)
    if not deps:
        return lose
    return to_findings(deps, query_osv(deps, url=url, timeout=timeout)) + lose
