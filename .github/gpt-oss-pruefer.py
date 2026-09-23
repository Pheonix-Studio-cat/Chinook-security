#!/usr/bin/env python3
"""Der zweite Prüfer: `openai/gpt-oss-20b` über Hugging Face, mit Belegpflicht.

Es gibt schon einen KI-Prüfer (Copilot, gpt-4.1). Dieser hier ist nicht
dessen Ersatz, sondern eine **zweite, unabhängige Meinung** — anderes
Modell, andere Fehler. Ein Befund, den beide melden, wiegt schwerer als
einer, den nur eines meldet.

## Was „aufs genaueste" hier konkret heisst

Nicht: ein längerer Auftrag oder ein grösseres Modell. Sondern drei Dinge,
die man **nachrechnen** kann:

**1. Eine Datei pro Anfrage.** Der erste Prüfer schickt bis zu 40 000
Zeichen aus vielen Dateien auf einmal; das Modell antwortet dann vage über
alles. Hier bekommt es eine Datei und sonst nichts.

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

## Das Budget formt den Takt

Der Projektinhaber will es über **Hugging Face und sonst nichts**. Das freie
Konto hat dort **0,10 $ Guthaben im Monat** für Inference Providers. Das ist
keine Nebenbedingung, sondern die Hauptbedingung, und sie ist gerechnet:

    eine Dateiprüfung  ~3000 Tokens hinein, ~500 hinaus  ≈ $0.000375
    0,10 $ reichen fuer                      etwa 266 Prüfungen im Monat

    17 Repos, taeglich, 8 Dateien   4080 Prüfungen = $1.53   15-fach drüber
    17 Repos, taeglich, 3 Dateien   1530 Prüfungen = $0.57   drüber
    17 Repos, woechentlich, 3       204 Prüfungen = $0.076   passt
    17 Repos, woechentlich, 5       340 Prüfungen = $0.128   knapp drüber

Deshalb: **wöchentlich, höchstens drei Dateien pro Lauf.** Nicht aus
Bescheidenheit, sondern weil alles andere die Rechnung sprengt.

*Die Preise stammen von der Anbieterseite für dasselbe Modell; was der
Router von Hugging Face berechnet, kann davon abweichen.* Deshalb die
Marge, und deshalb behandelt dieser Prüfer ein erschöpftes Guthaben als
Auskunft statt als Fehler: er sagt es und hört auf.

Der Router von Hugging Face verteilt die Anfrage intern an einen seiner
Anbieter — gerechnet und abgerechnet wird sie bei Hugging Face, gerechnet
im Wortsinn wird sie anderswo. Das gehört dazugesagt.

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

ENDPUNKT = "https://router.huggingface.co/v1/chat/completions"
MODELL = "openai/gpt-oss-20b"

# Eine Datei mit 12 000 Zeichen sind grob 3000 Tokens. Groesser heisst
# teurer, und teurer heisst bei 0,10 $ im Monat: frueher vorbei.
ZEICHEN_JE_DATEI = 12000

# Wie viele Dateien ein Lauf hoechstens ansieht. **Drei**, und das ist
# keine Vorsicht, sondern die Rechnung oben: siebzehn Repos mal drei
# Dateien mal vier Wochen sind 204 Pruefungen und damit rund 0,076 $ --
# die einzige Kombination aus Takt und Menge, die in das Monatsguthaben
# passt. Wer hier hochdreht, zahlt ab der Mitte des Monats.
DATEIEN_JE_LAUF = 3

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

    schluessel = os.environ.get("HF_TOKEN", "")
    if not schluessel and not werte.trocken:
        print("::error::HF_TOKEN fehlt.")
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
            # 402 heisst: das Monatsguthaben ist aufgebraucht. 429 heisst:
            # zu schnell. Beides ist eine **Auskunft ueber das Konto**, kein
            # Fehler dieser Datei und kein Grund, den Lauf rot zu faerben --
            # sonst blinkt das Repo ab Monatsmitte grundlos rot, und daran
            # gewoehnt man sich.
            if fehler.code in (402, 429):
                print(f"::warning::HTTP {fehler.code} von Hugging Face: {leib[:200]}")
                print(
                    "::warning::Guthaben oder Takt erschoepft. Der Lauf endet "
                    "hier und faerbt sich nicht rot."
                )
                break
            print(f"::error::HTTP {fehler.code} von Hugging Face bei {pfad}: {leib}")
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
