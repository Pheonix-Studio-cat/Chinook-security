"""Prueft, ob OSV die Oekosystem-Namen kennt, die Chinook Security schickt.

Der Dependency-Bot schickt je Sperrdatei einen festen Namen mit: `PyPI`, `npm`,
`Go`, `crates.io`, `Packagist`. Ist einer davon falsch geschrieben, findet OSV
nichts -- und ein leeres Ergebnis sieht aus wie „keine Schwachstellen".

**Das ist genau die Sorte gruene Pruefung, gegen die dieses Projekt gebaut ist.**

Die Probe kann nicht einfach „keine Treffer" als Fehler werten -- die meisten
Pakete haben tatsaechlich keine. Sie arbeitet deshalb im Unterschied: zuerst
fragt sie mit einem **erfundenen** Oekosystem. Weist OSV das zurueck, dann ist
„nicht zurueckgewiesen" ein Beleg dafuer, dass der Name bekannt ist. Weist OSV
es *nicht* zurueck, sagt die Probe, dass sie nichts beweisen kann.

Sie haengt an einem fremden Dienst und darf fehlschlagen. Aufruf:

    python3 -m checks.oekosystemprobe
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

from chinook.dependency_bot import OSV_URL

ERFUNDEN = "Chinook-Oekosystem-Das-Es-Nicht-Gibt"
# Je ein Paket, das es in diesem Oekosystem gibt. Ob es Schwachstellen hat,
# spielt keine Rolle -- gefragt wird, ob OSV den **Namen** annimmt.
PROBEN = (
    ("PyPI", "requests", "2.31.0"),
    ("npm", "lodash", "4.17.21"),
    ("Go", "github.com/gin-gonic/gin", "v1.9.1"),
    ("crates.io", "serde", "1.0.188"),
    ("Packagist", "monolog/monolog", "2.9.1"),
)


def frage(ecosystem: str, name: str, version: str, url: str = OSV_URL, timeout: int = 30):
    """(angenommen, Meldung)."""
    koerper = json.dumps(
        {"queries": [{"package": {"name": name, "ecosystem": ecosystem}, "version": version}]}
    ).encode("utf-8")
    anfrage = urllib.request.Request(
        url, data=koerper, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(anfrage, timeout=timeout) as antwort:
            daten = json.load(antwort)
    except urllib.error.HTTPError as fehler:
        return False, f"HTTP {fehler.code}"
    except (urllib.error.URLError, OSError, ValueError) as fehler:
        return None, f"{type(fehler).__name__}: {fehler}"
    if not isinstance(daten.get("results"), list):
        return False, "Antwort ohne results"
    return True, f"{len(daten['results'][0].get('vulns') or [])} Advisory(s)"


def main(argv=None) -> int:
    url = (argv or sys.argv[1:] or [OSV_URL])[0]
    print("Oekosystem-Probe gegen OSV.\n")

    angenommen, meldung = frage(ERFUNDEN, "requests", "2.31.0", url=url)
    if angenommen is None:
        print(f"OSV ist nicht erreichbar ({meldung}). Die Probe sagt nichts aus.")
        return 1
    if angenommen:
        print(
            "OSV nimmt auch ein erfundenes Oekosystem an "
            f"({ERFUNDEN}: {meldung}).\n"
            "Damit kann diese Probe die Namen **nicht** bestaetigen -- sie sagt\n"
            "nur, dass der Dienst antwortet. Nicht als Beleg verwenden."
        )
        return 1
    print(f"Ein erfundenes Oekosystem wird zurueckgewiesen ({meldung}).")
    print("Damit gilt: nicht zurueckgewiesen = Name bekannt.\n")

    schlecht = []
    for ecosystem, name, version in PROBEN:
        ok, meldung = frage(ecosystem, name, version, url=url)
        zeichen = "bekannt  " if ok else "ABGELEHNT"
        print(f"  [{zeichen}] {ecosystem:12} {name}@{version} -- {meldung}")
        if not ok:
            schlecht.append(ecosystem)

    print()
    if schlecht:
        print(
            f"{len(schlecht)} Oekosystem-Name(n) werden abgelehnt: {', '.join(schlecht)}.\n"
            "Der Dependency-Bot fragt dort ins Leere."
        )
        return 1
    print(f"Alle {len(PROBEN)} Oekosystem-Namen sind OSV bekannt.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
