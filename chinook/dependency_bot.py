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
                    title="Dependency is not pinned to a version",
                    severity="low",
                    confidence="high",
                    path=path,
                    line=number,
                    explanation=(
                        f"`{name}` is given without `==`. Every run may therefore install "
                        "something different, and this check says nothing about what is "
                        "actually installed."
                    ),
                    remediation=(
                        "Pin an exact version (`==`), or use a lockfile that the run "
                        "actually installs from."
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


_TOML_NAME = re.compile(r'^\s*name\s*=\s*"([^"]+)"')
_TOML_VERSION = re.compile(r'^\s*version\s*=\s*"([^"]+)"')


def _toml_pakete(text: str, path: str, ecosystem: str):
    """`[[package]]`-Bloecke, wie sie `poetry.lock` und `Cargo.lock` benutzen.

    Zeilenweise, ohne TOML-Leser -- dieselbe Entscheidung wie beim
    Workflow-Bot, und dieselbe Grenze: Bloecke, die von der ueblichen Form
    abweichen, werden nicht erkannt.
    """
    deps: list[Dependency] = []
    name = version = ""
    zeile = 0
    im_block = False

    def abschliessen():
        if im_block and name and version:
            deps.append(Dependency(name, version, ecosystem, path, zeile))

    for nummer, roh in enumerate(text.splitlines(), start=1):
        if roh.strip() == "[[package]]":
            abschliessen()
            im_block, name, version, zeile = True, "", "", nummer
            continue
        if roh.startswith("[") and roh.strip() != "[[package]]":
            abschliessen()
            im_block, name, version = False, "", ""
            continue
        if not im_block:
            continue
        if not name:
            treffer = _TOML_NAME.match(roh)
            if treffer:
                name = treffer.group(1)
                continue
        if not version:
            treffer = _TOML_VERSION.match(roh)
            if treffer:
                version = treffer.group(1)
    abschliessen()
    return deps, []


def parse_poetry_lock(text: str, path: str):
    return _toml_pakete(text, path, "PyPI")


def parse_cargo_lock(text: str, path: str):
    return _toml_pakete(text, path, "crates.io")


def _npm_name(spec: str) -> str:
    """Der Paketname aus einer yarn-/pnpm-Angabe.

    `lodash@^4.17.20`, `"@scope/x@npm:^1.0.0"`, `/lodash@4.17.21` -- der Name
    ist alles vor dem **letzten** `@`, das nicht am Anfang steht. Ein fuehrendes
    `@` gehoert zum Namensraum, nicht zur Version.
    """
    spec = spec.strip().strip('"\'').lstrip("/")
    trenner = spec.rfind("@")
    if trenner <= 0:
        return spec
    return spec[:trenner]


# Der Schluessel darf Doppelpunkte enthalten: Berry schreibt
# `"@scope/x@npm:^1.0.0":`. Nur der letzte zaehlt.
_YARN_SCHLUESSEL = re.compile(r"""^(?P<spec>["']?[^\s#].*?)["']?:\s*$""")
_YARN_VERSION = re.compile(r"""^\s+version[:\s]+["']?(?P<version>[^"'\s]+)["']?\s*$""")


def parse_yarn_lock(text: str, path: str):
    """`yarn.lock`, Format 1 wie Berry."""
    deps: list[Dependency] = []
    name = ""
    zeile = 0
    for nummer, roh in enumerate(text.splitlines(), start=1):
        if not roh.strip() or roh.lstrip().startswith("#"):
            continue
        if not roh[0].isspace():
            treffer = _YARN_SCHLUESSEL.match(roh)
            name = _npm_name(treffer.group("spec").split(",")[0]) if treffer else ""
            zeile = nummer
            continue
        if name:
            treffer = _YARN_VERSION.match(roh)
            if treffer:
                deps.append(Dependency(name, treffer.group("version"), "npm", path, zeile))
                name = ""
    return deps, []


_PNPM_EINTRAG = re.compile(r"""^\s{2,}["']?(?P<spec>/?[^:\s"']+)["']?:\s*$""")


def parse_pnpm_lock(text: str, path: str):
    """`pnpm-lock.yaml`. Erkannt werden `/name@version`, `name@version` und
    die aeltere Form `/name/version`."""
    deps: list[Dependency] = []
    im_paketteil = False
    for nummer, roh in enumerate(text.splitlines(), start=1):
        if roh.startswith("packages:"):
            im_paketteil = True
            continue
        if im_paketteil and roh and not roh[0].isspace():
            im_paketteil = False
            continue
        if not im_paketteil:
            continue
        treffer = _PNPM_EINTRAG.match(roh)
        if not treffer:
            continue
        spec = treffer.group("spec").lstrip("/")
        if "@" in spec.lstrip("@"):
            name, version = _npm_name(spec), spec[spec.rfind("@") + 1 :]
        else:
            teile = spec.rsplit("/", 1)
            if len(teile) != 2 or not teile[1][:1].isdigit():
                continue
            name, version = teile
        if name and version:
            deps.append(Dependency(name, version, "npm", path, nummer))
    return deps, []


def parse_composer_lock(text: str, path: str):
    """`composer.lock` -- JSON, `packages` und `packages-dev`."""
    try:
        daten = json.loads(text)
    except json.JSONDecodeError:
        return [], []
    deps: list[Dependency] = []
    for schluessel in ("packages", "packages-dev"):
        for eintrag in daten.get(schluessel) or []:
            if not isinstance(eintrag, dict):
                continue
            name = eintrag.get("name", "")
            version = str(eintrag.get("version", "")).lstrip("v")
            if name and version:
                deps.append(
                    Dependency(name, version, "Packagist", path, _line_of(text, f'"{name}"'))
                )
    return deps, []


PARSER = {
    "requirements.txt": parse_requirements,
    "package-lock.json": parse_package_lock,
    "go.mod": parse_go_mod,
    "poetry.lock": parse_poetry_lock,
    "Cargo.lock": parse_cargo_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "composer.lock": parse_composer_lock,
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
                title="Dependency with a known vulnerability",
                # Chinook Security stuft nicht selbst ein: jede bekannte Schwachstelle
                # ist "hoch". Das Einordnen ist Sache des Aufsehers, nicht eine
                # Zahl, die wir uns ausdenken.
                severity="high",
                confidence="high",
                path=dep.path,
                line=dep.line,
                explanation=(
                    f"`{dep.name}` {dep.version} ({dep.ecosystem}) is affected by "
                    f"{len(kennungen)} known vulnerability/vulnerabilities according to "
                    "OSV: " + ", ".join(kennungen[:5])
                    + ("" if len(kennungen) <= 5 else " and others")
                ),
                remediation=(
                    "Update to a version the advisories no longer affect. Details: "
                    f"{OSV_VULN_URL}{erste}"
                ),
                evidence=f"{len(kennungen)} advisory/advisories",
            )
        )
    return befunde


def run(root: str, excludes=(), url: str = OSV_URL, timeout: int = TIMEOUT) -> list[Finding]:
    deps, lose = collect(root, excludes)
    if not deps:
        return lose
    return to_findings(deps, query_osv(deps, url=url, timeout=timeout)) + lose


REGELN = (
    {
        "name": "known-vulnerability",
        "titel": "Dependency with a known vulnerability",
        "schwere": "high",
        "was": (
            "According to OSV.dev at least one advisory affects this version. "
            "Chinook Security does not rate severity itself -- every known vulnerability is "
            "\u201ehigh\u201c, and rating is the overseer's job."
        ),
    },
    {
        "name": "dependency-unpinned",
        "titel": "Dependency is not pinned to a version",
        "schwere": "low",
        "was": (
            "Without `==` every run may install something different, and the check "
            "says nothing about what is installed. Only for `requirements.txt` -- a "
            "lockfile pins itself."
        ),
    },
)


def regeln() -> list[dict]:
    return [dict(regel) for regel in REGELN]
