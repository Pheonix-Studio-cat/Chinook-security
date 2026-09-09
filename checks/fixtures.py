"""Erzeugt die absichtlich kaputten Faelle zur Laufzeit.

**Warum nicht als Datei im Repo?** Ein Fixture mit einem formatgueltigen Token
ist selbst ein Problem: GitHubs Push-Protection blockiert den Push, Scanner
melden das Repo, und wer die Datei kopiert, verteilt einen Sting, der wie ein
Schluessel aussieht. Also werden die Zeichenketten hier aus Teilen
zusammengesetzt und liegen nur im Temp-Verzeichnis des Laufs.

Die Werte sind erfunden und gehoeren zu keinem Konto.
"""

from __future__ import annotations

import os
import subprocess
import tempfile

# Aus Teilen zusammengesetzt, damit im Quelltext nichts steht, das ein Scanner
# fuer einen echten Schluessel haelt.
FAKE = {
    "aws-access-key-id": "AKIA" + "QWERTYUIOPASDFGH",
    "github-token": "ghp_" + "0a1B" * 9,
    "huggingface-token": "hf_" + "wXyZ" * 9,
    "anthropic-key": "sk-ant-" + "api03-" + "kLmN" * 8,
    "openai-key": "sk-" + "pQrS" * 9,
    "slack-token": "xoxb-" + "1234567890-" + "abcdefghij",
    "google-api-key": "AIza" + "SyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",
    # Auch dieser Kopf wird zerlegt -- sonst faende der Secret-Bot sein
    # eigenes Fixture-Modul.
    "private-key-block": "-----BEGIN RSA " + "PRIVATE KEY" + "-----",
    "assigned-credential": "Zg7-" + "Tp41xQv9Ls",
}


def secret_line(rule: str) -> str:
    """Eine Zeile, in der genau diese Regel greifen muss."""
    value = FAKE[rule]
    if rule == "private-key-block":
        return value
    if rule == "assigned-credential":
        return f'api_key = "{value}"'
    return f'wert = "{value}"'


CLEAN_FILE = (
    "# Diese Datei ist absichtlich sauber.\n"
    'api_key = os.environ["API_KEY"]\n'
    'password = "changeme"          # Platzhalter, kein Fund\n'
    'token = "${DEPLOY_TOKEN}"      # Interpolation, kein Fund\n'
    'beispiel = "your-key-here-1234567890"\n'
)


def write_broken_tree(root: str, rule: str) -> str:
    """Legt unter `root` eine Datei an, in der `rule` greifen muss."""
    path = os.path.join(root, "src")
    os.makedirs(path, exist_ok=True)
    target = os.path.join(path, "konfiguration.py")
    with open(target, "w", encoding="utf-8") as handle:
        handle.write("# Kaputt mit Absicht.\n")
        handle.write(secret_line(rule) + "\n")
    return target


def write_clean_tree(root: str) -> str:
    path = os.path.join(root, "src")
    os.makedirs(path, exist_ok=True)
    target = os.path.join(path, "konfiguration.py")
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(CLEAN_FILE)
    return target


def git(root: str, *args: str) -> None:
    subprocess.run(["git", "-C", root, *args], check=True, capture_output=True, text=True)


def make_repo_with_deleted_secret(rule: str = "aws-access-key-id") -> tempfile.TemporaryDirectory:
    """Ein Git-Repo, dessen Arbeitsbaum sauber ist und dessen History nicht.

    Genau der Fall, den ein reiner Diff-Scan durchgehen laesst.
    """
    handle = tempfile.TemporaryDirectory()
    root = handle.name
    git(root, "init", "--quiet", "--initial-branch=main")
    git(root, "config", "user.email", "fixture@example.invalid")
    git(root, "config", "user.name", "Fixture")
    write_broken_tree(root, rule)
    git(root, "add", "-A")
    git(root, "commit", "--quiet", "-m", "Erster Commit mit dem Fund")
    write_clean_tree(root)
    git(root, "add", "-A")
    git(root, "commit", "--quiet", "-m", "Aufgeraeumt -- aber nur im Arbeitsbaum")
    return handle


# --- Code-Bot -------------------------------------------------------------

import json as _json
import pathlib as _pathlib

WURZEL = _pathlib.Path(__file__).resolve().parent.parent


def code_proben() -> dict:
    """Die Proben aus `fixtures/code/samples.json`.

    Sie liegen als JSON und nicht als `.py`/`.js`/`.sh`, weil der Code-Bot sonst
    beim Lauf ueber das eigene Repo seine eigenen Fixtures melden wuerde.
    """
    with open(WURZEL / "fixtures" / "code" / "samples.json", encoding="utf-8") as handle:
        return _json.load(handle)["regeln"]


def schreibe_code_datei(root: str, name: str, probe: dict, sauber: bool = False) -> str:
    """Schreibt eine Probe als Datei mit der passenden Endung."""
    ziel = os.path.join(root, f"{name.replace('/', '_')}{probe['suffix']}")
    with open(ziel, "w", encoding="utf-8") as handle:
        handle.write(probe["sauber" if sauber else "kaputt"] + "\n")
    return ziel


# --- Dependency-Bot -------------------------------------------------------


class OsvStub:
    """Ein OSV-Ersatz auf dem eigenen Rechner.

    Die echte Adresse ist aus dieser Umgebung nicht erreichbar, und eine
    Pruefung, die vom Netz abhaengt, ist keine Pruefung. Also wird gegen einen
    Stub gefahren -- und der Stub raeumt sich selbst ab.
    """

    def __init__(self, antwort=None, status: int = 200, koerper: bytes | None = None):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import threading

        self.anfragen = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 -- von BaseHTTPRequestHandler vorgegeben
                laenge = int(self.headers.get("Content-Length", "0"))
                stub.anfragen.append(_json.loads(self.rfile.read(laenge) or b"{}"))
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                if koerper is not None:
                    nutzlast = koerper
                else:
                    anzahl = len(stub.anfragen[-1].get("queries", []))
                    vorgabe = {"results": [{} for _ in range(anzahl)]}
                    nutzlast = _json.dumps(antwort if antwort is not None else vorgabe).encode()
                self.send_header("Content-Length", str(len(nutzlast)))
                self.end_headers()
                self.wfile.write(nutzlast)

            def log_message(self, *_args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}/v1/querybatch"

    def __enter__(self) -> "OsvStub":
        self.thread.start()
        return self

    def __exit__(self, *_ausnahme) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def schreibe_requirements(root: str, zeilen) -> str:
    ziel = os.path.join(root, "requirements.txt")
    with open(ziel, "w", encoding="utf-8") as handle:
        handle.write("\n".join(zeilen) + "\n")
    return ziel


# --- Aufseher --------------------------------------------------------------


class ModellStub:
    """Ein Messages-API-Ersatz auf dem eigenen Rechner.

    Der Aufseher wird nie gegen die echte Adresse gefahren: das kostet Geld,
    haengt am Netz und liefert bei jedem Lauf etwas anderes. Was hier geprueft
    wird, ist nicht das Modell, sondern **was Chinook mit dessen Antwort
    macht** -- und das muss auch bei einer boesartigen Antwort stimmen.
    """

    def __init__(self, bewertungen=None, status: int = 200, koerper: bytes | None = None,
                 stop_reason: str = "end_turn", text: str | None = None):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import threading

        self.anfragen = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                laenge = int(self.headers.get("Content-Length", "0"))
                stub.anfragen.append(
                    {
                        "koerper": _json.loads(self.rfile.read(laenge) or b"{}"),
                        # Kopfzeilen sind laut HTTP gross-/kleinschreibungsblind;
                        # urllib schickt sie kapitalisiert. Klein ablegen, sonst
                        # prueft man die Schreibweise statt des Inhalts.
                        "kopfzeilen": {k.lower(): v for k, v in self.headers.items()},
                    }
                )
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                if koerper is not None:
                    nutzlast = koerper
                else:
                    inhalt = text if text is not None else _json.dumps(
                        {"bewertungen": bewertungen or []}, ensure_ascii=False
                    )
                    nutzlast = _json.dumps(
                        {
                            "id": "msg_stub",
                            "model": "claude-opus-5",
                            "stop_reason": stop_reason,
                            "content": [{"type": "text", "text": inhalt}],
                        }
                    ).encode()
                self.send_header("Content-Length", str(len(nutzlast)))
                self.end_headers()
                self.wfile.write(nutzlast)

            def log_message(self, *_args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}/v1/messages"

    def __enter__(self) -> "ModellStub":
        self.thread.start()
        return self

    def __exit__(self, *_ausnahme) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def schreibe_bericht(pfad: str, befunde) -> str:
    """Ein Befundbericht im Chinook-Format, wie ihn ein Bot schreibt."""
    with open(pfad, "w", encoding="utf-8") as handle:
        _json.dump(
            {
                "schema_version": "1",
                "bot": "secret-bot",
                "generated_at": "2026-01-01T00:00:00Z",
                "target": {},
                "summary": {"total": len(befunde), "by_severity": {}},
                "findings": befunde,
            },
            handle,
        )
    return pfad


def befund(fingerprint: str, **felder) -> dict:
    grund = {
        "id": "secret-bot/github-token",
        "bot": "secret-bot",
        "rule": "github-token",
        "title": "GitHub-Token im Quelltext",
        "severity": "critical",
        "confidence": "high",
        "location": {"path": "src/konfiguration.py", "line": 4},
        "explanation": "Erklaerung",
        "remediation": "Gegenmittel",
        "evidence": "github-token, 40 Zeichen (Wert wird nicht ausgegeben)",
        "fingerprint": fingerprint,
    }
    grund.update(felder)
    return grund
