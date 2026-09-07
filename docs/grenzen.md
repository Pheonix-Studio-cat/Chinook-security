# Grenzen

Was Chinook **nicht** kann. Diese Datei ist wichtiger als eine Merkmalsliste:
wer die Grenze nicht kennt, hält ein leeres Ergebnis für eine Unbedenklichkeits-
bescheinigung.

## Allgemein

**Kein Befund heißt nicht „sicher".** Es heißt: diese Regeln haben nichts
gefunden. Die Regeln stehen vollständig in `chinook/secret_bot.py` und
`chinook/workflow_bot.py` — was dort nicht steht, wird nicht gesucht.

## Secret-Bot

- **Musterbasiert.** Was kein bekanntes Format hat, wird nur von der Regel
  `assigned-credential` erfasst, und die läuft mit mittlerer Zuversicht.
- **Keine Entropie-Prüfung.** Bewusst: sie erzeugt Falschmeldungen auf Hashes,
  Base64-Blöcken und Testdaten, und wäre schwer gegenzuprüfen.
- **Binärdateien werden übersprungen** (erkannt am Null-Byte in den ersten 4 KB),
  ebenso Dateien über 2 MB.
- **Die History-Prüfung liest die letzten 500 Commits** und nur hinzugefügte
  Zeilen. Ein Geheimnis, das älter ist oder nur in einem nicht erreichbaren
  Objekt liegt, wird nicht gefunden. Sie braucht `fetch-depth: 0`; ohne das
  sieht sie nur den Kopf und meldet nichts — **still**, was der unangenehmere
  Fall ist.
- **Ein Fund kann ein Platzhalter sein.** Die Liste erkennbarer Platzhalter ist
  bewusst knapp; eine großzügige Liste ist der Weg, auf dem ein Bot grün wird,
  ohne zu prüfen.

## Workflow-Bot

- **Kein YAML-Parser.** Er liest Zeilen und Einrückung. Das reicht für die fünf
  Regeln und ist der Preis dafür, keine Abhängigkeit zu haben. Nicht erkannt
  werden dadurch:
  - Anker und Aliase (`&x` / `*x`),
  - mehrzeilige Flow-Maps (`{ ... }` über mehrere Zeilen),
  - `permissions:` in einer eingerückten Struktur, die nicht am Zeilenanfang steht.
- **`unpinned-action`** meldet jeden Ref, der kein voller 40-stelliger SHA ist.
  Ein Tag ist kein Beweis für Unsicherheit — er ist eine Zusage, die jemand
  anderes zurücknehmen kann.
- **`script-injection`** prüft nur `run:`-Blöcke. Fremder Kontext in `with:`
  einer Fremd-Action kann ebenfalls gefährlich sein und wird noch nicht erfasst.
- **Kein Blick auf die Repo-Einstellungen.** Ob die Standardrechte eng oder weit
  sind, steht nicht in der Datei; deshalb ist `permissions-missing` „mittel"
  und nicht „hoch".

## Composite Actions

- Der aufrufende Workflow muss **selbst auschecken**. Eine composite action
  bringt keinen Checkout mit.
- Für die History-Prüfung muss der Checkout `fetch-depth: 0` setzen.
- `python3` wird als vorhanden vorausgesetzt (auf `ubuntu-latest` ist es das).
