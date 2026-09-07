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

## Was Chinook **nicht** verspricht

- **Vollständigkeit.** Die Bots finden, was ihre Regeln beschreiben. Kein
  Befund heißt nicht „sicher", es heißt „diese Regeln haben nichts gefunden".
- **Keine Falschmeldungen.** Die Regel `assigned-credential` läuft mit
  mittlerer Zuversicht und wird gelegentlich danebenliegen.
- **Kein vollständiges YAML-Verständnis.** Der Workflow-Bot liest Zeilen, nicht
  Dokumentstruktur. Die Grenze steht in `docs/grenzen.md`.
- **Keine Erkennungsraten.** Es gibt hier keine Prozentzahlen, weil es keine
  Messung gibt, die sie belegt.

## Wenn der Secret-Bot etwas findet

Den Schlüssel als **kompromittiert** behandeln: beim Anbieter widerrufen und neu
ausstellen. Erst danach aus dem Quelltext entfernen.

Einen Commit zu löschen genügt nicht — die History bleibt, Forks bleiben, und
Klone bleiben sowieso. Deshalb prüft der Bot die History mit.
