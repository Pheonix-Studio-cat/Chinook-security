# Entscheidungen

Was entschieden ist **und warum**. Ohne das „warum" wird es beim nächsten Mal
neu verhandelt.

---

## Keine Abhängigkeiten, nur Standardbibliothek

Ein Sicherheitswerkzeug mit dreihundert transitiven Paketen ist selbst eine
Angriffsfläche — und es läuft in fremden Repos, mit deren Rechten. Dazu kommt:
ein Lockfile will gepflegt werden, und der Projektinhaber arbeitet vom iPad
ohne Kommandozeile.

Der Preis ist benannt, nicht verschwiegen: der Workflow-Bot liest Zeilen statt
YAML-Struktur. Die Grenze steht in `grenzen.md`.

---

## Ein Befund trägt nie den gefundenen Wert

Kein Präfix, kein Hash, nur Regel und Länge.

- Ein Präfix wäre bei einem Passwort ein echtes Leck.
- Ein Hash wäre bei einem schwachen Passwort ein Orakel.
- Das Action-Log eines öffentlichen Repos liest jeder.

Ein Secret-Bot, der den Fund ausdruckt, ist selbst das Leck. Die Zusage hängt
an `findings.redact()` und ist mit der Mutation `redaktion-abgeschaltet`
gegengeprüft.

---

## Composite Actions statt reusable workflows — vorerst

Eine composite action findet ihren eigenen Quelltext über
`${{ github.action_path }}`. Ein reusable workflow müsste sein eigenes Repo ein
zweites Mal auschecken, und zwar auf einem **fest verdrahteten Ref** — der dann
nicht mehr dem entspricht, was der Aufrufer mit `@v1` gewählt hat.

Reusable workflows kommen in Etappe 2, mit einer Antwort auf dieses Problem.

---

## Der Aufseher zahlt nicht auf ein fremdes Konto

Der Modellschlüssel kommt aus dem Repo-Secret dessen, der den Bot einsetzt —
nicht aus einem Schlüssel dieses Projekts. Eine öffentliche Action, die auf ein
fremdes Guthaben rechnet, ist eine offene Brieftasche.

Daraus folgt: **der Aufseher ist optional.** Fehlt der Schlüssel, laufen die
Bots trotzdem. Ein Scanner, der ausfällt, weil ein Modell nicht antwortet, ist
schlechter als keiner.

---

## Der Aufseher bekommt keine Werkzeuge und keine Schreibrechte

Er liest zwangsläufig fremden Text: PR-Titel, Kommentare, Paketnamen, Quelltext
aus einem Fork. Alles davon kann eine Anweisung enthalten. Ein Modell mit
Schreibrechten, das solchen Text liest, ist Prompt Injection mit Schreibzugriff.

Also: Befunde hinein, Einordnung heraus. Und er darf einen Befund **einordnen,
aber nie löschen** — Wegräumen ist eine Menschenentscheidung.

---

## Secret-Fixtures werden zur Laufzeit erzeugt

Ein formatgültiges Token als Datei im Repo wird von GitHubs Push-Protection
blockiert, von Scannern gemeldet, und wer die Datei kopiert, verteilt etwas,
das wie ein Schlüssel aussieht. Deshalb setzt `checks/fixtures.py` die Werte
aus Teilen zusammen und legt sie nur im Temp-Verzeichnis des Laufs ab.

Dasselbe gilt im Quelltext selbst: sogar die Kopfzeile eines privaten
RSA-Schlüssels steht dort zerlegt, sonst fände der Secret-Bot sein eigenes
Fixture-Modul. Diese Datei enthält sie deshalb auch nicht ausgeschrieben —
der Bot hat es beim ersten Entwurf sofort gemeldet.

---

## Kaputte Workflows liegen außerhalb von `.github/workflows/`

Sonst führt GitHub sie aus. Eine Prüfung hält das fest.

---

## Der eigene `actions/checkout` ist noch nicht auf einen SHA festgelegt

Der Workflow-Bot meldet das an der eigenen `selfcheck.yml` — als Hinweis, weil
`actions/*` GitHub selbst gehört. Es bleibt trotzdem offen: der SHA wird
eingetragen, sobald er verifiziert vorliegt. Einen SHA zu erfinden, damit die
eigene Prüfung schöner aussieht, ist keine Option.
