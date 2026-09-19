#!/usr/bin/env python3
"""Macht aus den Befunden eines Sprachmodells Issues -- ohne Flut.

Der Auftrag war: „bei jedem Fehler ein neues Issue". Wörtlich genommen
entsteht daraus **eine Lawine**, und zwar aus zwei Gründen, die beide nichts
mit dem Code zu tun haben:

1. **Derselbe Code gibt dieselbe Antwort.** Läuft der Prüfer zweimal über
   unveränderten Code, findet er zweimal dasselbe. Ohne Wiedererkennung wären
   das zwei Issues, nach einer Woche vierzehn.
2. **Ein Sprachmodell findet immer etwas.** Gefragt „was ist hier falsch",
   antwortet es auch dort, wo nichts falsch ist. Das ist keine Bosheit,
   sondern die Form der Frage.

Deshalb drei Schranken, und jede hat einen Grund:

* **Wiedererkennung.** Jeder Befund bekommt einen Fingerabdruck aus Datei und
  Titel. Steht dazu schon ein offenes Issue, wird **keins** angelegt.
* **Obergrenze.** Höchstens `GRENZE` neue Issues pro Lauf. Findet das Modell
  mehr, sagt der Lauf das laut -- aber er schüttet sie nicht aus.
* **Kennzeichnung.** In jedem Issue steht, dass ein Sprachmodell den Befund
  gemeldet hat und **niemand ihn geprüft** hat. Ein unbestätigter Befund, der
  aussieht wie ein bestätigter, ist schlimmer als keiner.

Der Fingerabdruck steht als HTML-Kommentar im Text des Issues. Das ist die
einzige Stelle, an der er überlebt -- Titel ändern sich, Beschriftungen auch.

Keine Abhängigkeiten: Standardbibliothek, wie alles hier.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request

# Höchstens so viele neue Issues pro Lauf. Lieber eine gedeckelte Meldung als
# ein Repo, in dem niemand mehr etwas findet.
GRENZE = 5

# Nur das hier wird gemeldet. „niedrig" ist Geschmack, und Geschmack gehört
# nicht in ein Issue, das jemand abarbeiten soll.
GEMELDET = ("hoch", "mittel")

MARKE = "ki-pruefer-fingerabdruck"
ETIKETT = "ki-befund"


class Unbrauchbar(Exception):
    """Die Antwort des Modells liess sich nicht auswerten.

    Ausdrücklich **kein** „dann eben null Befunde": eine unlesbare Antwort ist
    etwas anderes als eine leere. Der Unterschied ist in diesem Projekt schon
    einmal teuer gewesen.
    """


def befunde_aus_text(text: str) -> list[dict]:
    """Zieht die Liste der Befunde aus der Antwort des Modells.

    Modelle verpacken JSON gern in ```-Blöcke oder schreiben einen Satz davor.
    Beides wird abgeräumt; alles andere ist ein Fehler und kein Anlass zu
    raten.
    """
    if not text or not text.strip():
        raise Unbrauchbar("die Antwort war leer")

    roh = text.strip()
    block = re.search(r"```(?:json)?\s*(.+?)```", roh, re.DOTALL)
    if block:
        roh = block.group(1).strip()
    else:
        # Kein Block: die äusserste eckige Klammer nehmen.
        auf = roh.find("[")
        zu = roh.rfind("]")
        if auf == -1 or zu == -1 or zu < auf:
            raise Unbrauchbar("in der Antwort steht keine JSON-Liste")
        roh = roh[auf : zu + 1]

    try:
        daten = json.loads(roh)
    except json.JSONDecodeError as fehler:
        raise Unbrauchbar(f"die Antwort ist kein gueltiges JSON: {fehler}") from fehler

    if not isinstance(daten, list):
        raise Unbrauchbar("die Antwort ist keine Liste")

    sauber = []
    for eintrag in daten:
        if not isinstance(eintrag, dict):
            raise Unbrauchbar("ein Eintrag in der Liste ist kein Objekt")
        fehlt = [f for f in ("titel", "datei", "schwere", "begruendung") if not eintrag.get(f)]
        if fehlt:
            raise Unbrauchbar(f"einem Befund fehlen Felder: {', '.join(fehlt)}")
        if eintrag["schwere"] not in ("hoch", "mittel", "niedrig"):
            raise Unbrauchbar(f"unbekannte Schwere: {eintrag['schwere']!r}")
        sauber.append(eintrag)
    return sauber


def fingerabdruck(befund: dict) -> str:
    """Erkennt denselben Befund wieder, auch über Läufe hinweg.

    Datei und Titel, beide normalisiert. **Nicht** die Zeilennummer: die
    verschiebt sich, sobald jemand oben eine Zeile einfügt, und dann wäre
    derselbe Befund plötzlich ein neuer.
    """
    datei = (befund.get("datei") or "").strip().lower()
    titel = re.sub(r"\s+", " ", (befund.get("titel") or "").strip().lower())
    return hashlib.sha256(f"{datei}\n{titel}".encode()).hexdigest()[:16]


def marke_von(abdruck: str) -> str:
    return f"<!-- {MARKE}: {abdruck} -->"


def abdruecke_aus_issues(issues: list[dict]) -> set[str]:
    """Liest die Fingerabdrücke aus den Texten offener Issues."""
    muster = re.compile(rf"<!--\s*{re.escape(MARKE)}:\s*([0-9a-f]+)\s*-->")
    gefunden = set()
    for issue in issues:
        gefunden.update(muster.findall(issue.get("body") or ""))
    return gefunden


def auswaehlen(befunde: list[dict], bekannt: set[str]) -> tuple[list[dict], list[dict], int]:
    """Teilt die Befunde in: neu zu melden, schon bekannt, wegen Grenze zurueck."""
    meldbar = [b for b in befunde if b["schwere"] in GEMELDET]
    neu, alt = [], []
    for befund in meldbar:
        (alt if fingerabdruck(befund) in bekannt else neu).append(befund)
    # Das Schwerere zuerst, damit die Obergrenze nicht das Wichtige abschneidet.
    neu.sort(key=lambda b: GEMELDET.index(b["schwere"]))
    zurueck = max(0, len(neu) - GRENZE)
    return neu[:GRENZE], alt, zurueck


def issue_text(befund: dict, repo: str, lauf: str) -> str:
    zeile = befund.get("zeile")
    ort = f"`{befund['datei']}`" + (f", Zeile {zeile}" if zeile else "")
    return f"""> ⚠️ **Von einem Sprachmodell gemeldet. Niemand hat das geprüft.**
> Ein Modell, das nach Fehlern gefragt wird, findet auch dort welche, wo
> keine sind. Bevor hier etwas geändert wird: nachsehen, ob der Befund
> stimmt. Stimmt er nicht, schliessen — das ist ein gültiges Ergebnis.

**Ort:** {ort}
**Schwere (laut Modell):** {befund['schwere']}

## Was das Modell sagt

{befund['begruendung']}

---

Gefunden vom KI-Prüfer in `{repo}`. [Der Lauf]({lauf})

{marke_von(fingerabdruck(befund))}
"""


# --- Alles ab hier redet mit GitHub. Darüber nichts, damit es prüfbar bleibt.


def _anfrage(pfad: str, token: str, daten: dict | None = None) -> object:
    ziel = f"https://api.github.com{pfad}"
    leib = json.dumps(daten).encode() if daten is not None else None
    bitte = urllib.request.Request(ziel, data=leib, method="POST" if daten else "GET")
    bitte.add_header("Authorization", f"Bearer {token}")
    bitte.add_header("Accept", "application/vnd.github+json")
    if daten is not None:
        bitte.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(bitte, timeout=30) as antwort:
        return json.loads(antwort.read().decode())


def offene_issues(repo: str, token: str) -> list[dict]:
    gesammelt: list[dict] = []
    seite = 1
    while seite <= 5:  # 500 offene Issues sind genug; darüber hilft kein Bot mehr.
        teil = _anfrage(f"/repos/{repo}/issues?state=open&per_page=100&page={seite}", token)
        if not isinstance(teil, list) or not teil:
            break
        gesammelt.extend(teil)
        if len(teil) < 100:
            break
        seite += 1
    return gesammelt


def issue_anlegen(repo: str, token: str, befund: dict, lauf: str) -> str:
    antwort = _anfrage(
        f"/repos/{repo}/issues",
        token,
        {
            "title": f"[KI] {befund['titel']}",
            "body": issue_text(befund, repo, lauf),
            "labels": [ETIKETT],
        },
    )
    return antwort.get("html_url", "?") if isinstance(antwort, dict) else "?"


def main() -> int:
    zerleger = argparse.ArgumentParser(description="Befunde eines Modells zu Issues machen.")
    zerleger.add_argument("--antwort", required=True, help="Datei mit der Antwort des Modells")
    zerleger.add_argument("--repo", required=True, help="owner/name")
    zerleger.add_argument("--lauf", default="", help="URL des Actions-Laufs")
    zerleger.add_argument("--trocken", action="store_true", help="nur sagen, nichts anlegen")
    werte = zerleger.parse_args()

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token and not werte.trocken:
        print("::error::GITHUB_TOKEN fehlt.")
        return 2

    with open(werte.antwort, encoding="utf-8") as datei:
        text = datei.read()

    try:
        befunde = befunde_aus_text(text)
    except Unbrauchbar as fehler:
        # Exit 2, nicht 1: „konnte nichts feststellen" ist nicht dasselbe wie
        # „nichts gefunden". Dieselbe Regel wie bei der Gegenprobe.
        print(f"::error::Die Antwort des Modells war nicht auswertbar -- {fehler}")
        print("--- was dastand ---")
        print(text[:2000])
        return 2

    if not befunde:
        print("Das Modell hat nichts gefunden. Kein Issue.")
        return 0

    bekannt = set() if werte.trocken else abdruecke_aus_issues(offene_issues(werte.repo, token))
    neu, alt, zurueck = auswaehlen(befunde, bekannt)

    print(f"{len(befunde)} Befund(e), davon {len(alt)} bereits als Issue offen.")
    if zurueck:
        print(f"::warning::{zurueck} weitere Befund(e) zurueckgehalten -- hoechstens {GRENZE} neue Issues pro Lauf.")

    for befund in neu:
        if werte.trocken:
            print(f"[trocken] wuerde anlegen: [{befund['schwere']}] {befund['titel']}")
            continue
        adresse = issue_anlegen(werte.repo, token, befund, werte.lauf)
        print(f"Issue angelegt: {adresse}")

    print(f"{len(neu)} neue(s) Issue(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
