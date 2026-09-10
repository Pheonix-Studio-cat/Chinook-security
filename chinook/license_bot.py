"""Lizenz-Bot -- was erklaert ist, was fehlt, und was geprueft werden muss.

**Dieser Bot stellt keine Rechtstatsache fest.** Er sagt nie, unter welcher
Lizenz etwas steht. Er sagt, was **erklaert** ist, wo **nichts** erklaert ist,
und wo die Erklaerung und die beiliegende Datei **auseinandergehen**. Alles
Weitere ist eine Frage an einen Menschen.

Die Erfahrung dahinter stammt aus einem anderen Projekt: das `license`-Feld ist
nicht der Lizenztext, ein `license_link` kann auf eine Datei zeigen, die es
nicht gibt, und wer die Modellseite statt des Repos liest, uebersieht die
Nutzungsbedingung, die danebenliegt.
"""

from __future__ import annotations

import json
import os
import re

from .findings import Finding

BOT = "license-bot"

LICENCE_DATEINAMEN = (
    "LICENSE", "LICENCE", "COPYING", "LICENSE.md", "LICENCE.md",
    "LICENSE.txt", "LICENCE.txt", "COPYING.md", "COPYING.txt",
)

# Bewusst kurz: eine Kennung, die hier fehlt, wird als "muss geprueft werden"
# gemeldet, nicht als falsch.
BEKANNTE_KENNUNGEN = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0",
    "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
    "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "AGPL-3.0-only", "AGPL-3.0-or-later", "Unlicense", "CC0-1.0",
    "0BSD", "Zlib", "Artistic-2.0", "EPL-2.0",
}

# Heuristik, ausdruecklich als solche. Sie dient **nur** dazu, einen Widerspruch
# zur Erklaerung zu melden -- nie dazu, eine Lizenz zu behaupten.
TEXTMERKMALE = (
    ("AGPL-3.0", "gnu affero general public license"),
    ("LGPL", "gnu lesser general public license"),
    ("GPL-3.0", "gnu general public license"),
    ("Apache-2.0", "apache license"),
    ("MPL-2.0", "mozilla public license"),
    ("MIT", "permission is hereby granted, free of charge"),
    ("ISC", "permission to use, copy, modify, and/or distribute this software"),
    ("BSD", "redistribution and use in source and binary forms"),
)

_PRUEFEN = "License status requires verification."


def familie(text: str) -> str | None:
    """Grobe Familie eines Lizenztexts, oder None. Keine Rechtsaussage."""
    klein = text.lower()
    if "gnu general public license" in klein and "version 2" in klein:
        return "GPL-2.0"
    for name, merkmal in TEXTMERKMALE:
        if merkmal in klein:
            return name
    return None


def kennung_familie(kennung: str) -> str | None:
    """Ordnet eine erklaerte Kennung derselben groben Familie zu."""
    k = kennung.strip()
    for prefix in ("AGPL-3.0", "LGPL", "GPL-3.0", "GPL-2.0", "Apache-2.0", "MPL-2.0", "MIT", "ISC"):
        if k.startswith(prefix):
            return "GPL-3.0" if prefix == "GPL-3.0" else prefix
    if k.startswith("BSD") or k == "0BSD":
        return "BSD"
    return None


def _lizenzdatei(root: str) -> tuple[str, str] | None:
    for name in LICENCE_DATEINAMEN:
        pfad = os.path.join(root, name)
        if os.path.isfile(pfad):
            try:
                with open(pfad, "r", encoding="utf-8", errors="replace") as handle:
                    return name, handle.read()
            except OSError:
                return name, ""
    return None


_TOML_LICENSE = re.compile(
    r"""^\s*license\s*=\s*(?:
        "(?P<text>[^"]*)" |
        \{\s*text\s*=\s*"(?P<inline>[^"]*)"\s*\} |
        \{\s*file\s*=\s*"(?P<datei>[^"]*)"\s*\}
    )""",
    re.VERBOSE,
)


def _erklaerung_aus_pyproject(text: str):
    """(Kennung, Datei, Zeile) -- je nachdem, welche Form benutzt wird."""
    for number, line in enumerate(text.splitlines(), start=1):
        match = _TOML_LICENSE.match(line)
        if match:
            return (
                match.group("text") or match.group("inline"),
                match.group("datei"),
                number,
            )
    return None, None, 0


def _befund(rule, title, severity, path, line, explanation, remediation, confidence="high") -> Finding:
    return Finding(
        bot=BOT,
        rule=rule,
        title=title,
        severity=severity,
        confidence=confidence,
        path=path,
        line=line,
        explanation=explanation,
        remediation=remediation,
    )


def _pruefe_kennung(kennung: str, path: str, line: int, datei_familie: str | None) -> list[Finding]:
    befunde: list[Finding] = []
    if kennung not in BEKANNTE_KENNUNGEN:
        befunde.append(
            _befund(
                "license-unrecognised",
                "Declared licence is not a known SPDX identifier",
                "info",
                path,
                line,
                f"`{kennung}` is not on the list of identifiers known here. That does "
                f"not mean it is wrong -- it means this bot cannot confirm it. {_PRUEFEN}",
                "Enter an SPDX identifier, or check by hand and accept the finding.",
                confidence="medium",
            )
        )
        return befunde
    erklaerte_familie = kennung_familie(kennung)
    if datei_familie and erklaerte_familie and datei_familie != erklaerte_familie:
        befunde.append(
            _befund(
                "license-mismatch",
                "Declared licence and the accompanying text disagree",
                "medium",
                path,
                line,
                f"Declared is `{kennung}`; the text of the licence file looks like "
                f"`{datei_familie}`. Which one applies is not for this bot to decide. "
                f"{_PRUEFEN}",
                "Bring the declaration and the file into agreement -- and check which of "
                "the two was intended.",
                confidence="medium",
            )
        )
    return befunde


def run(root: str, excludes=()) -> list[Finding]:
    befunde: list[Finding] = []
    wurzel = os.path.abspath(root)
    skip = {e.strip("/") for e in excludes if e.strip()}

    datei = _lizenzdatei(wurzel)
    datei_familie = familie(datei[1]) if datei else None

    if datei is None:
        befunde.append(
            _befund(
                "license-file-missing",
                "No licence file in the root directory",
                "medium",
                "LICENSE",
                1,
                "Without a licence file it is unclear what anyone may do with the "
                "source. Without permission, in doubt: nothing.",
                "Add a licence file. If the choice is unclear, decide first rather than "
                "putting something there provisionally.",
            )
        )

    # package.json
    paket = os.path.join(wurzel, "package.json")
    if os.path.isfile(paket) and "package.json" not in skip:
        try:
            with open(paket, "r", encoding="utf-8", errors="replace") as handle:
                roh = handle.read()
            daten = json.loads(roh)
        except (OSError, json.JSONDecodeError):
            daten, roh = {}, ""
        zeile = 1
        for number, line in enumerate(roh.splitlines(), start=1):
            if '"license"' in line or '"licenses"' in line:
                zeile = number
                break
        kennung = daten.get("license")
        if not kennung and not daten.get("licenses"):
            befunde.append(
                _befund(
                    "license-undeclared",
                    "package.json declares no licence",
                    "medium",
                    "package.json",
                    zeile,
                    "Without a `license` field npm assumes no licence, and whoever "
                    "depends on the package cannot check whether they may.",
                    "Add a `license` field with an SPDX identifier.",
                )
            )
        elif isinstance(kennung, str):
            verweis = re.match(r"^SEE LICENSE IN (?P<datei>.+)$", kennung.strip())
            if verweis:
                ziel = verweis.group("datei").strip()
                if not os.path.isfile(os.path.join(wurzel, ziel)):
                    befunde.append(
                        _befund(
                            "license-link-broken",
                            "The declared licence points at a file that does not exist",
                            "medium",
                            "package.json",
                            zeile,
                            f"`{kennung}` points at `{ziel}` -- there is nothing there. "
                            f"So there are no terms to read. {_PRUEFEN}",
                            "Add the file, or switch to an SPDX identifier.",
                        )
                    )
            else:
                befunde.extend(_pruefe_kennung(kennung.strip(), "package.json", zeile, datei_familie))

    # pyproject.toml
    pyproject = os.path.join(wurzel, "pyproject.toml")
    if os.path.isfile(pyproject) and "pyproject.toml" not in skip:
        try:
            with open(pyproject, "r", encoding="utf-8", errors="replace") as handle:
                roh = handle.read()
        except OSError:
            roh = ""
        kennung, verweis, zeile = _erklaerung_aus_pyproject(roh)
        if verweis:
            if not os.path.isfile(os.path.join(wurzel, verweis)):
                befunde.append(
                    _befund(
                        "license-link-broken",
                        "The declared licence points at a file that does not exist",
                        "medium",
                        "pyproject.toml",
                        zeile,
                        f"`license = {{file = \"{verweis}\"}}` points at a file that does "
                        f"not exist. {_PRUEFEN}",
                        "Add the file, or switch to an SPDX identifier.",
                    )
                )
        elif kennung:
            befunde.extend(_pruefe_kennung(kennung.strip(), "pyproject.toml", zeile, datei_familie))
        elif "[project]" in roh:
            befunde.append(
                _befund(
                    "license-undeclared",
                    "pyproject.toml declares no licence",
                    "medium",
                    "pyproject.toml",
                    1,
                    "The `[project]` section has no `license`. Whoever depends on the "
                    "package cannot check whether they may.",
                    "Add a `license` field with an SPDX identifier.",
                )
            )
    return befunde


REGELN = (
    {
        "name": "license-file-missing",
        "titel": "No licence file in the root directory",
        "schwere": "medium",
        "was": "Without permission, in doubt: nothing.",
    },
    {
        "name": "license-undeclared",
        "titel": "The package declares no licence",
        "schwere": "medium",
        "was": "Whoever depends on it cannot check whether they may.",
    },
    {
        "name": "license-link-broken",
        "titel": "The declared licence points nowhere",
        "schwere": "medium",
        "was": "The file named does not exist -- there are no terms to read.",
    },
    {
        "name": "license-mismatch",
        "titel": "Declaration and accompanying text disagree",
        "schwere": "medium",
        "was": (
            "Which one applies is not for this bot to decide. "
            "License status requires verification."
        ),
    },
    {
        "name": "license-unrecognised",
        "titel": "Not a known SPDX identifier",
        "schwere": "info",
        "was": (
            "That does not mean it is wrong -- it means the bot cannot confirm it."
        ),
    },
)


def regeln() -> list[dict]:
    return [dict(regel) for regel in REGELN]
