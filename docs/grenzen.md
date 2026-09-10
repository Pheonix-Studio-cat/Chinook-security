# Grenzen

Was Chinook Security **nicht** kann. Diese Datei ist wichtiger als eine Merkmalsliste:
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
- **`script-injection`** prüft `run:`- und `script:`-Blöcke — beides wird
  ausgeführt. Ein Wert in `with:` einer anderen Action wird dagegen als
  **Eingabe** übergeben und ist nicht von sich aus gefährlich; ob die Action ihn
  in eine Shell einsetzt, sieht der Bot nicht. Dieser Fall wird deshalb bewusst
  **nicht** gemeldet — eine Regel, die jede Eingabe anmahnt, wäre Rauschen.
- **Kein Blick auf die Repo-Einstellungen.** Ob die Standardrechte eng oder weit
  sind, steht nicht in der Datei; deshalb ist `permissions-missing` „mittel"
  und nicht „hoch".

## Dependency-Bot

- **Nur Sperrdateien**, und nur acht Formate: `requirements.txt`,
  `poetry.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `go.mod`,
  `Cargo.lock`, `composer.lock`. Kein Maven, kein Gradle, kein NuGet, kein
  `Gemfile.lock`. Wo nichts gelesen wird, wird auch nichts gefragt — und dann
  ist ein leeres Ergebnis wirklich leer.
- **Zeilenweise gelesen, nicht mit einem Leser des jeweiligen Formats.** Für
  `poetry.lock`, `Cargo.lock`, `yarn.lock` und `pnpm-lock.yaml` heisst das:
  übliche Formen ja, Sonderfälle nein. Dieselbe Entscheidung wie beim
  Workflow-Bot und derselbe Preis.
- **`pnpm-lock.yaml` Format 9 führt jedes Paket zweimal auf** — unter
  `packages:` und noch einmal unter `snapshots:`. Gelesen wird nur der erste
  Abschnitt; sonst würde jedes Paket doppelt abgefragt.
- **Die Ökosystem-Namen sind Zeichenketten**, die OSV kennen muss. Ein falsch
  geschriebener Name fände nichts, und nichts sähe aus wie „sauber". Ob OSV sie
  kennt, prüft `checks/oekosystemprobe.py` gegen den echten Dienst — die
  Prüfungen im Repo können es nicht.
- **`requirements.txt` nur mit `==`.** Eine Spanne beschreibt nicht, was
  installiert wird; sie wird als `dependency-unpinned` gemeldet statt geraten.
- **Er haengt an einem fremden Dienst.** OSV.dev muss erreichbar sein. Ist es
  das nicht, endet der Lauf mit **2** und gilt nicht als bestanden.
- **Er holt keine Einzelheiten zu den Advisories.** Die Sammelabfrage gibt nur
  Kennungen zurueck; eine behobene Version steht deshalb **nicht** im Befund.
  Sie zu nennen, ohne sie geholt zu haben, waere eine erfundene Angabe.
- **Keine Einstufung nach Schwere.** Jede bekannte Schwachstelle ist "hoch".
  Das Einordnen ist Aufgabe des Aufsehers (Etappe 3).
- **Die echte Adresse wird von den Pruefungen nicht angesprochen.** Sie fahren
  gegen einen Stub auf dem eigenen Rechner. In der Selbstpruefung gibt es dafuer
  den Job `netzprobe` — der **darf fehlschlagen**, weil er ueber einen fremden
  Dienst Auskunft gibt und nicht ueber Chinook Security.

## Code-Bot

- **Musterbasiert, ohne Datenflussanalyse.** Er sieht, *dass* eine gefaehrliche
  Stelle da ist, nicht *ob* an ihr etwas Fremdes ankommt. `eval` auf einer
  Konstanten ist harmlos und wird trotzdem gemeldet -- deshalb tragen diese
  Regeln mittlere Zuversicht.
- **Zeilenweise.** Ein Aufruf, der ueber zwei Zeilen geht, wird nicht erkannt.
- **Kommentarzeilen werden uebersprungen**, erkannt an `#`, `//`, `*`, `/*`.
  Ein auskommentierter Block in der Mitte einer Zeile zaehlt weiter.
- **Nur `.py`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.sh`, `.bash`.**
  Kein Go, kein Rust, kein Java, kein PHP.

## Lizenz-Bot

- **Er stellt keine Rechtstatsache fest.** Er sagt nie, unter welcher Lizenz
  etwas steht -- nur was erklaert ist, was fehlt und was auseinandergeht.
- **Die Texterkennung ist eine Heuristik** an wenigen Merkmalsaetzen. Sie dient
  ausschliesslich dazu, einen **Widerspruch** zur Erklaerung zu melden.
- **Nur das Wurzelverzeichnis**, nur `package.json` und `pyproject.toml`. Keine
  Unterprojekte, kein `setup.cfg`, keine Klassifizierer.
- **`pyproject.toml` wird zeilenweise gelesen**, nicht als TOML. Erkannt werden
  `license = "…"`, `license = {text = "…"}` und `license = {file = "…"}` --
  jeweils am Zeilenanfang.
- **Die Kennungsliste ist kurz.** Was fehlt, wird als *License status requires
  verification* gemeldet, nicht als falsch.
- **Die Lizenzen der Abhaengigkeiten** sind nicht erfasst. Das ist eine eigene
  Aufgabe und braucht die Metadaten der Pakete, nicht nur ihre Namen.

## Composite Actions

- Der aufrufende Workflow muss **selbst auschecken**. Eine composite action
  bringt keinen Checkout mit.
- Für die History-Prüfung muss der Checkout `fetch-depth: 0` setzen.
- `python3` wird als vorhanden vorausgesetzt (auf `ubuntu-latest` ist es das).

## Aufseher

- **Er ist freiwillig, und das ist kein Nebensatz.** Ohne `CHINOOK_AI_TOKEN`
  passiert nichts, und der Lauf bleibt gruen. Ein Bericht ohne Einordnung ist
  ein vollstaendiger Bericht -- nur ohne Sortierhilfe.
- **Er kann irren.** Eine Einschaetzung ist eine Meinung eines Modells, kein
  Befund. Sie steht deshalb in einem eigenen Feld `triage` neben dem Befund und
  ersetzt ihn nie.
- **Ein Aufruf, keine Schleife.** Er sieht die Befunde, nicht das Repo -- kein
  Quelltext, kein Diff, keine Nachfrage. Was nicht im Befund steht, weiss er
  nicht, und was er dazu erfindet, faellt bei der Pruefung der Antwort weg.
- **Nur die Anthropic-Messages-API.** Andere Anbieter sprechen eine andere
  Request-Form. `--api-url` aendert die Adresse, nicht das Format.
- **Er sieht kein `evidence`.** Das enthaelt zwar keinen Fund, gehoert aber
  nicht zur Einordnung -- und was nicht hinausgeht, kann auch nicht lecken.
- **Die Begruendung ist Text aus einem Modell.** Sie wird von Steuerzeichen
  befreit und auf 400 Zeichen gekuerzt, sonst nicht geprueft. Wer sie anzeigt,
  behandelt sie als Text, nicht als Markup.

## Website

- **Sie zeigt den Stand einer Fassung, nicht den eines fremden Repos.** Die
  Zahlen darauf gelten fuer Chinook Security selbst.
- **Der Stand der Gegenprobe stammt vom letzten Bau** -- bei jedem Merge auf
  `main` und einmal woechentlich. Was dazwischen passiert, steht nicht darauf.
- **Kein Suchfeld, keine Navigation, kein Skript.** Eine Seite, eine Datei.
- **Veroeffentlicht wird ueber den Branch `gh-pages`**, nicht ueber
  `actions/deploy-pages`. Der Grund steht in `entscheidungen.md`: Pages war im
  Repo nicht eingeschaltet, und das Anlegen des Branches hat es von selbst
  aktiviert. Damit haengt der Workflow an keiner Einstellung, die jemand
  vergessen kann.
- **Der Branch ist erzeugter Inhalt.** Jeder Lauf schreibt einen einzelnen
  Commit ohne Vorgeschichte und setzt den Branch mit `--force`. Wer dort etwas
  von Hand aendert, verliert es beim naechsten Merge auf `main`.

## Die Gegenprobe dauert

25 Mutationen, jede mit einem vollstaendigen Lauf der Pruefungen in einer Kopie
des Repos. Das sind auf einem CI-Laeufer einige Minuten. Der Preis ist bekannt
und wird bezahlt: eine Pruefung, die nie gegen einen kaputten Zustand gelaufen
ist, ist keine Pruefung.

## Es gibt keine aufrufbaren Workflows

Nur composite actions. Der aufrufende Workflow muss also **selbst auschecken**
und die Bots als Schritte einbauen -- vier Zeilen statt einer. Der Grund steht
in `entscheidungen.md`: ein aufrufbarer Workflow käme nicht an die Fassung
heran, die der Aufrufer gewählt hat.
