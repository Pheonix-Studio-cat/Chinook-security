# Sicherheit

## Eine Lücke melden

Bitte **kein öffentliches Issue** für eine ausnutzbare Lücke. Der Weg ist
GitHubs *Security → Report a vulnerability* in diesem Repo (Private
Vulnerability Reporting).

Hilfreich in der Meldung: was betroffen ist, was ein Angreifer damit erreicht,
und ein möglichst kleiner Fall, der es zeigt.

## Was Chinook selbst verspricht

| Zusage | Wie sie gehalten wird |
| --- | --- |
| Ein Befund enthält nie den gefundenen Wert | `findings.redact()`, geprüft in `checks/test_secret_bot.py`, gegengeprüft mit der Mutation `redaktion-abgeschaltet` |
| Keine Laufzeit-Abhängigkeit | nur Standardbibliothek; keine `requirements.txt`, kein Lockfile |
| Die Bots führen keinen fremden Code aus | sie lesen Dateien und gleichen Muster ab, sie starten nichts aus dem geprüften Repo |
| Die eigenen Workflows halten die eigenen Regeln ein | `test_die_eigenen_workflows_sind_sauber` |
| Kein Geheimnis im Repo | der Secret-Bot läuft bei jeder Selbstprüfung über sein eigenes Repo, mit History |
| Ein Lauf, der nichts feststellen konnte, gilt nicht als bestanden | Rückgabewert `2`, gegengeprüft mit `unbewiesen-gilt-als-bestanden` |
| Der Lizenz-Bot behauptet keine Lizenz | `KeineRechtsaussageTest` in `checks/test_license_bot.py` |
| **Kein Befund geht verloren** | der Aufseher baut seine Liste aus den Befunden, nie aus der Modellantwort; `KeinBefundGehtVerlorenTest` und fünf Mutationen |
| Der Aufseher hat keine Werkzeuge und keine Schreibrechte | `test_der_aufseher_bekommt_keine_werkzeuge`; er stellt genau eine Anfrage und liest die Antwort |
| Chinook hält keinen Modellschlüssel | der Schlüssel kommt aus `CHINOOK_AI_TOKEN` im Repo des Nutzers |
| Die aufgerufene Fassung ist festgelegt | leeres `job_workflow_sha` bricht den Workflow ab, statt irgendeine Fassung zu holen |

## Was Chinook **nicht** verspricht

- **Vollständigkeit.** Die Bots finden, was ihre Regeln beschreiben. Kein
  Befund heißt nicht „sicher", es heißt „diese Regeln haben nichts gefunden".
- **Keine Falschmeldungen.** Die Regel `assigned-credential` läuft mit
  mittlerer Zuversicht und wird gelegentlich danebenliegen.
- **Kein vollständiges YAML-Verständnis.** Der Workflow-Bot liest Zeilen, nicht
  Dokumentstruktur. Die Grenze steht in `docs/grenzen.md`.
- **Keine Erkennungsraten.** Es gibt hier keine Prozentzahlen, weil es keine
  Messung gibt, die sie belegt.
- **Keine eigene Einstufung von Schwachstellen.** Jede bekannte Schwachstelle
  ist „hoch". Chinook rechnet kein CVSS aus.
- **Keine Rechtsauskunft.** Der Lizenz-Bot meldet, was fehlt und was
  auseinandergeht. Was daraus folgt, entscheidet ein Mensch.
- **Der Aufseher irrt.** Eine Einschätzung ist die Meinung eines Modells, kein
  Befund. Sie steht in einem eigenen Feld und ersetzt nichts. „Vermutlich
  Rauschen" ist keine Freigabe.

## Wenn der Secret-Bot etwas findet

Den Schlüssel als **kompromittiert** behandeln: beim Anbieter widerrufen und neu
ausstellen. Erst danach aus dem Quelltext entfernen.

Einen Commit zu löschen genügt nicht — die History bleibt, Forks bleiben, und
Klone bleiben sowieso. Deshalb prüft der Bot die History mit.
