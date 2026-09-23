#!/usr/bin/env python3
"""Der zweite Prüfer: `openai/gpt-oss-20b`, mit Belegpflicht.

Es gibt schon einen KI-Prüfer (Copilot, gpt-4.1). Dieser hier ist nicht
dessen Ersatz, sondern eine **zweite, unabhängige Meinung** — anderes
Modell, andere Fehler. Ein Befund, den beide melden, wiegt schwerer als
einer, den nur eines meldet.

## Was „aufs genaueste" hier konkret heisst

Nicht: ein längerer Auftrag oder ein grösseres Modell. Sondern drei Dinge,
die man **nachrechnen** kann:

**1. Eine Datei pro Anfrage.** Der erste Prüfer schickt bis zu 40 000
Zeichen aus vielen Dateien auf einmal; das Modell antwortet dann vage über
alles. Hier bekommt es eine Datei und sonst nichts. Das ist auch die einzige
Form, die in die Grenze des Gratis-Kontingents passt (8000 Tokens pro
Minute).

**2. Belegpflicht.** Jeder Befund muss die **Quelltextzeile mitliefern**,
über die er redet. Diese Zeile wird gegen die echte Datei geprüft:

* steht sie an der angegebenen Stelle → Befund gilt
* steht sie woanders in der Datei → Zeilennummer wird **korrigiert**
* steht sie gar nicht in der Datei → Befund wird **verworfen**

Das ist ein mechanischer Filter gegen Erfundenes, und er braucht kein
zweites Modell, das urteilt. Ein Modell, das eine Zeile erfindet, die es
nicht gibt, hat über nichts Wirkliches geredet.

**3. Keine Zusammenfassung ohne Zahl.** Wie viele Befunde kamen, wie viele
überlebten den Beleg, und warum die anderen nicht — das steht im Protokoll.
Ein Filter, dessen Wirkung niemand sieht, ist kein Filter.

## Warum Groq und nicht der HF-Router

Dasselbe Modell, beides über Hugging Face auffindbar. Der Router von
Hugging Face rechnet aber gegen ein Monatsguthaben von **0,10 $** auf dem
freien Konto — das reicht für ein paar Läufe. Groq, einer der sechs
Anbieter dieses Modells, gibt **1000 Anfragen und 200 000 Tokens am Tag**
ohne Kreditkarte. Bei siebzehn Repos mit je einem Lauf am Tag ist das der
Unterschied zwischen „läuft" und „läuft bis Dienstag".

*Unbestätigt, bis ein Lauf es zeigt:* ob das Kontingent im Alltag reicht.
Die Rechnung steht in `docs/`, die Messung fehlt noch.

Keine Abhängigkeiten: Standardbibliothek, wie alles hier.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

ENDPUNKT = "https://api.groq.com/openai/v1/chat/completions"
MODELL = "openai/gpt-oss-20b"

# Das Gratis-Kontingent erlaubt 8000 Tokens pro Minute. Eine Datei mit
# 12 000 Zeichen sind grob 3000 Tokens; dazu der Auftrag und die Antwort,
# und es passt mit Luft. Groesser werden hiesse: die erste Anfrage geht
# durch und die zweite bekommt HTTP 429.
ZEICHEN_JE_DATEI = 12000

# Wie viele Dateien ein Lauf hoechstens ansieht. 200 000 Tokens am Tag,
# geteilt durch siebzehn Repos, laesst pro Lauf Raum fuer wenige Dateien.
DATEIEN_JE_LAUF = 8

QUELLE = "gpt-oss-20b"

AUFTRAG = """Du pruefst genau eine Quelltextdatei auf echte Fehler.

Antworte mit NICHTS ausser einer JSON-Liste. Jeder Eintrag:
{"titel": kurz und konkret,
 "zeile": die Zeilennummer, ueber die du redest,
 "beleg": der WORTWOERTLICHE Inhalt genau dieser Zeile, aus der Datei kopiert,
 "schwere": "hoch" | "mittel" | "niedrig",
 "begruendung": zwei bis vier Saetze auf Deutsch: was schiefgeht und wann}

Das Feld "beleg" wird gegen die echte Datei geprueft. Stimmt es mit keiner
Zeile ueberein, wird dein Befund verworfen. Kopiere die Zeile, rate sie nicht.

Melde nur, was wirklich falsch laufen kann: Abstuerze, falsche Ergebnisse,
Sicherheitsluecken, nicht behandelte Fehlerfaelle, Nebenlaeufigkeit.
Melde KEINEN Geschmack: keine Namensgebung, keine Formatierung, keine
fehlenden Kommentare.

Findest du nichts, antworte mit []. Eine leere Liste ist eine vollstaendige
Antwort und besser als ein erfundener Befund."""


class Unbrauchbar(Exception):
    """Die Antwort des Modells liess sich nicht auswerten.

    Ausdruecklich kein „dann eben null Befunde": eine unlesbare Antwort ist
    etwas anderes als eine leere.
    """


def befunde_aus_text(text: str) -> list[dict]:
    """Zieht die Liste aus der Antwort. Tolerant gegen ```-Bloecke."""
    if not text or not text.strip():
        raise Unbrauchbar("die Antwort war leer")
    roh = text.strip()
    block = re.search(r"```(?:json)?\s*(.+?)```", roh, re.DOTALL)
    if block:
        roh = block.group(1).strip()
    else:
        auf, zu = roh.find("["), roh.rfind("]")
        if auf == -1 or zu == -1 or zu < auf:
            raise Unbrauchbar("in der Antwort steht keine JSON-Liste")
        roh = roh[auf : zu + 1]
    try:
        daten = json.loads(roh)
    except json.JSONDecodeError as fehler:
        raise Unbrauchbar(f"kein gueltiges JSON: {fehler}") from fehler
    if not isinstance(daten, list):
        raise Unbrauchbar("die Antwort ist keine Liste")
    return daten


def _norm(zeile: str) -> str:
    """Leerraum ist kein Unterschied. Alles andere schon."""
    return re.sub(r"\s+", " ", zeile).strip()


def belegen(befund: dict, quelltext: str) -> tuple[bool, str, dict]:
    """Prueft den Beleg gegen die echte Datei.

    Gibt zurueck: (gilt, Begruendung, moeglicherweise korrigierter Befund).

    Der ganze Zweck dieses Prüfers steht in dieser Funktion. Ein Modell,
    das behauptet, in Zeile 40 stehe etwas, das dort nicht steht, hat
    entweder die Datei nicht gelesen oder sich etwas ausgedacht. Beides
    macht seinen Befund wertlos -- und beides ist hier feststellbar, ohne
    dass jemand den Code verstehen muss.
    """
    for feld in ("titel", "beleg", "schwere", "begruendung"):
        if not isinstance(befund.get(feld), str) or not befund[feld].strip():
            return False, f"das Feld {feld!r} fehlt oder ist kein Text", befund
    if befund["schwere"] not in ("hoch", "mittel", "niedrig"):
        return False, f"unbekannte Schwere {befund['schwere']!r}", befund

    zeilen = quelltext.splitlines()
    gesucht = _norm(befund["beleg"])
    if not gesucht:
        return False, "der Beleg ist leer", befund

    nummer = befund.get("zeile")
    sitzt = (
        isinstance(nummer, int)
        and 1 <= nummer <= len(zeilen)
        and _norm(zeilen[nummer - 1]) == gesucht
    )
    if sitzt:
        return True, "Beleg sitzt", befund

    # Die Zeilennummer kann daneben liegen, der Beleg trotzdem echt sein.
    # Das ist kein Grund zu verwerfen, sondern einer zu korrigieren.
    treffer = [i + 1 for i, z in enumerate(zeilen) if _norm(z) == gesucht]
    if len(treffer) == 1:
        korrigiert = dict(befund, zeile=treffer[0])
        return True, f"Zeilennummer korrigiert auf {treffer[0]}", korrigiert
    if len(treffer) > 1:
        # Mehrdeutig: der Beleg steht mehrfach da. Die Aussage bleibt wahr,
        # nur die Stelle ist offen -- also ohne Zeilennummer melden.
        ohne = dict(befund)
        ohne.pop("zeile", None)
        return True, f"Beleg steht {len(treffer)}-mal, ohne Zeilennummer", ohne
    return False, "der Beleg steht nirgends in der Datei", befund


def pruefe_belege(befunde: list[dict], quelltext: str) -> tuple[list[dict], list[str]]:
    """Wendet die Belegpflicht auf alle Befunde an und sagt, was passierte."""
    behalten, protokoll = [], []
    for befund in befunde:
        gilt, warum, fertig = belegen(befund, quelltext)
        titel = str(befund.get("titel", "(ohne Titel)"))[:60]
        if gilt:
            behalten.append(fertig)
            protokoll.append(f"  behalten: {titel} -- {warum}")
        else:
            protokoll.append(f"  VERWORFEN: {titel} -- {warum}")
    return behalten, protokoll


def frage(quelltext: str, pfad: str, schluessel: str, zeitgrenze: int = 120) -> str:
    """Eine Datei, eine Anfrage. Gibt den Antworttext zurueck."""
    nummeriert = "\n".join(
        f"{i:4d}| {z}" for i, z in enumerate(quelltext.splitlines(), 1)
    )
    inhalt = (
        f"Datei: {pfad}\n\n"
        "Der Quelltext, mit Zeilennummern am Rand. Die Nummern gehoeren "
        "NICHT zur Datei -- der Beleg ist der Text rechts vom senkrechten "
        "Strich.\n\n"
        f"{nummeriert}"
    )
    leib = json.dumps(
        {
            "model": MODELL,
            "messages": [
                {"role": "system", "content": AUFTRAG},
                {"role": "user", "content": inhalt},
            ],
            "temperature": 0,
            "max_tokens": 1500,
        }
    ).encode()
    bitte = urllib.request.Request(ENDPUNKT, data=leib, method="POST")
    bitte.add_header("Authorization", f"Bearer {schluessel}")
    bitte.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(bitte, timeout=zeitgrenze) as antwort:
        daten = json.loads(antwort.read().decode())
    try:
        return daten["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as fehler:
        raise Unbrauchbar(f"unerwartete Antwortform: {fehler}") from fehler


def dateien_waehlen(kandidaten: list[str], grenze: int = DATEIEN_JE_LAUF) -> list[str]:
    """Welche Dateien schafft dieser Lauf?

    Das Kontingent ist die Schranke, nicht der gute Wille. Sortiert wird
    stabil nach Pfad, damit zwei Laeufe ueber denselben Stand dieselbe
    Auswahl treffen -- sonst waere jeder Lauf ueber eine andere Haelfte des
    Repos und die Issues zappelten.
    """
    return sorted(kandidaten)[:grenze]


def main() -> int:
    zerleger = argparse.ArgumentParser(description="Zweiter Pruefer: gpt-oss-20b.")
    zerleger.add_argument(
        "--dateien", required=True, help="Datei mit Pfaden, einer pro Zeile"
    )
    zerleger.add_argument("--ausgabe", required=True, help="wohin die Befunde als JSON")
    zerleger.add_argument(
        "--trocken", action="store_true", help="nicht fragen, nur sagen"
    )
    werte = zerleger.parse_args()

    schluessel = os.environ.get("GROQ_API_KEY", "")
    if not schluessel and not werte.trocken:
        print("::error::GROQ_API_KEY fehlt.")
        return 2

    with open(werte.dateien, encoding="utf-8") as datei:
        kandidaten = [z.strip() for z in datei if z.strip()]
    gewaehlt = dateien_waehlen(kandidaten)
    if len(kandidaten) > len(gewaehlt):
        print(
            f"::warning::{len(kandidaten)} Datei(en) da, "
            f"{len(gewaehlt)} angesehen -- das Tageskontingent ist die Schranke."
        )

    alle: list[dict] = []
    angesehen: list[str] = []
    for pfad in gewaehlt:
        try:
            with open(pfad, encoding="utf-8") as datei:
                quelltext = datei.read()
        except OSError as fehler:
            print(f"  {pfad}: nicht lesbar ({fehler})")
            continue
        if len(quelltext) > ZEICHEN_JE_DATEI:
            quelltext = quelltext[:ZEICHEN_JE_DATEI]
            print(f"  {pfad}: auf {ZEICHEN_JE_DATEI} Zeichen gekuerzt")
        angesehen.append(pfad)

        if werte.trocken:
            print(f"  [trocken] wuerde fragen: {pfad}")
            continue

        print(f"  {pfad} ...")
        try:
            roh = frage(quelltext, pfad, schluessel)
            befunde = befunde_aus_text(roh)
        except urllib.error.HTTPError as fehler:
            leib = fehler.read().decode(errors="replace")[:500]
            print(f"::error::HTTP {fehler.code} von Groq bei {pfad}: {leib}")
            # 429 heisst Kontingent erschoepft -- das ist eine Auskunft, kein
            # Fehler dieser Datei. Der Lauf hoert auf, statt weiter anzuklopfen.
            if fehler.code == 429:
                print("::warning::Kontingent erschoepft. Der Lauf endet hier.")
                break
            return 2
        except Unbrauchbar as fehler:
            print(f"::error::Antwort zu {pfad} nicht auswertbar -- {fehler}")
            return 2

        gehalten, protokoll = pruefe_belege(befunde, quelltext)
        for zeile in protokoll:
            print(zeile)
        print(f"  {pfad}: {len(befunde)} gemeldet, {len(gehalten)} belegt.")
        for befund in gehalten:
            alle.append(dict(befund, datei=pfad, quelle=QUELLE))

    with open(werte.ausgabe, "w", encoding="utf-8") as datei:
        json.dump(alle, datei, ensure_ascii=False, indent=1)
    with open("angesehen.txt", "w", encoding="utf-8") as datei:
        datei.write("\n".join(angesehen) + ("\n" if angesehen else ""))
    print(f"{len(alle)} belegte(r) Befund(e) aus {len(angesehen)} Datei(en).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
