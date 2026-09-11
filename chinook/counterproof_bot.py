"""Gegenproben-Bot -- bricht fremden Code absichtlich und sieht nach, ob es auffaellt.

Jeder andere Bot hier sagt dir, **was in deinem Code steht**. Dieser sagt dir,
**was deine Pruefungen nicht merken wuerden**. Das ist die gefaehrlichere
Luecke, weil sie wie Erfolg aussieht: eine gruene Pruefsuite, die eine kaputte
Berechtigungspruefung durchwinkt, sieht genauso aus wie eine, die sie faengt.

Das Verfahren ist das, mit dem Chinook Security seit Anfang an seine eigenen
Bots prueft (`checks/counterproof.py`) -- hier nach aussen gedreht, auf ein
beliebiges Repo mit einem beliebigen Testkommando.

Der Ablauf:

1. **Das Testkommando muss zuerst gruen sein.** Ist es rot, kann niemand
   unterscheiden, ob eine Mutation gefangen wurde oder ob es schon vorher
   kaputt war. Dann meldet der Bot `Unprovable` und der Lauf endet mit 2 --
   nicht mit 0. Ein Lauf, der nichts feststellen konnte, ist kein sauberer Lauf.
2. Aus den Quelldateien werden Mutationen erzeugt: eine Vergleichsrichtung
   gedreht, ein `and` zu einem `or`, ein `return` auf `True` gesetzt.
3. Jede Mutation wird einzeln eingespielt, das Testkommando laeuft, die Datei
   wird zurueckgesetzt.
4. Faellt die Pruefsuite um, ist die Mutation **gefangen**. Bleibt sie gruen,
   ist die Mutation **entkommen** -- und das ist der Befund.

**Ein Befund traegt nie die Quellzeile.** Das ist dieselbe Regel wie beim
Secret-Bot, und sie ist hier nicht weniger wichtig: in
`if token == "…":` steckt ein Geheimnis, und ein Bericht, der die
mutierte Zeile mitliefert, traegt es in fremde Action-Logs. Gemeldet werden
Ort und Operator, sonst nichts.

**Die Auswahl ist bestimmt, nicht zufaellig.** Zwei Laeufe ueber denselben
Stand pruefen dieselben Mutationen. Ein Bot, der jedes Mal etwas anderes misst,
ist in einer CI nicht zu gebrauchen.
"""

from __future__ import annotations

import ast
import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field

from .findings import Finding

BOT = "counterproof-bot"


class Unprovable(Exception):
    """Der Lauf konnte nichts feststellen.

    Kein Ergebnis, kein leeres Ergebnis -- der Aufrufer macht daraus die 2.
    """


# --------------------------------------------------------------------------
# Was ueberhaupt mutiert wird
# --------------------------------------------------------------------------

QUELL_ENDUNGEN = (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")

# Verzeichnisse, in denen zu mutieren sinnlos oder schaedlich waere.
UEBERSPRINGEN = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".next", ".nuxt", "vendor", "coverage", ".tox", ".mypy_cache", ".pytest_cache",
    "site-packages", ".cache", "out", "target",
}

# Pruefdateien selbst werden nie mutiert. Eine kaputte Pruefung faengt sich
# selbst -- das misst nichts.
TESTMUSTER = re.compile(
    r"(^|/)(tests?|__tests__|spec|e2e)(/|$)"
    r"|(^|/)(test_[^/]*|[^/]*_test|[^/]*\.test|[^/]*\.spec)\.[^/]+$",
    re.IGNORECASE,
)

# Woran der Bot Code erkennt, bei dem eine entkommene Mutation mehr wiegt.
# Bewusst eine Heuristik und als solche gekennzeichnet: sie entscheidet nur
# ueber den Schweregrad, nie darueber, ob geprueft wird.
SICHERHEITSWOERTER = (
    "auth", "login", "logout", "passwo", "secret", "token", "credential",
    "permission", "privile", "verify", "verifi", "valid", "sanitiz", "escape",
    "csrf", "xss", "inject", "crypt", "hash", "hmac", "sign", "cert", "admin",
    "allow", "deny", "access", "session", "cookie", "jwt", "nonce", "salt",
    "owner", "role", "guard", "policy", "sandbox", "quota", "limit",
)


def _sicherheitsnah(*texte: str) -> bool:
    zusammen = " ".join(t.lower() for t in texte if t)
    return any(wort in zusammen for wort in SICHERHEITSWOERTER)


@dataclass(frozen=True)
class Mutation:
    """Ein einzelner absichtlicher Bruch.

    `neu` ist der vollstaendige neue Dateiinhalt. Er wird zum Einspielen
    gebraucht und **nie** in einen Befund geschrieben.
    """

    pfad: str          # relativ zur Wurzel
    zeile: int
    operator: str      # z. B. "comparison-flipped"
    wandel: str        # z. B. "== -> !=", nie die Quellzeile
    neu: str = field(repr=False, compare=False, default="")
    sicherheitsnah: bool = False

    @property
    def name(self) -> str:
        return f"{self.pfad}:{self.zeile} {self.operator}"


# --------------------------------------------------------------------------
# Mutationen fuer Python -- ueber den Syntaxbaum, aber chirurgisch eingesetzt
# --------------------------------------------------------------------------
#
# Der Baum sagt, **wo** etwas steht; ersetzt wird im Text. `ast.unparse` wuerde
# die ganze Datei neu schreiben und dabei Kommentare und Formatierung
# verlieren -- das ist ein zweiter, ungewollter Unterschied, und ein zweiter
# Unterschied macht eine Messung wertlos.

_PY_VERGLEICH = {
    ast.Eq: ("==", "!="), ast.NotEq: ("!=", "=="),
    ast.Lt: ("<", ">="), ast.GtE: (">=", "<"),
    ast.Gt: (">", "<="), ast.LtE: ("<=", ">"),
    ast.Is: ("is", "is not"), ast.IsNot: ("is not", "is"),
}


def _zeilenanfaenge(text: str) -> list[int]:
    """Zeichen-Index, an dem jede Zeile beginnt (0-basiert indiziert)."""
    anfaenge = [0]
    for i, zeichen in enumerate(text):
        if zeichen == "\n":
            anfaenge.append(i + 1)
    return anfaenge


def _spanne(anfaenge: list[int], zeile: int, spalte: int) -> int:
    """AST-Position (1-basierte Zeile, 0-basierte Spalte) -> Zeichen-Index."""
    return anfaenge[zeile - 1] + spalte


def _funktionsnamen(baum: ast.AST) -> dict[int, str]:
    """Zeile -> Name der umschliessenden Funktion oder Klasse.

    Nur fuer die Einstufung des Schweregrads. Bei Verschachtelung gewinnt die
    innerste, weil sie das Genauere ueber die Stelle sagt.
    """
    zuordnung: dict[int, str] = {}
    for knoten in ast.walk(baum):
        if isinstance(knoten, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            ende = getattr(knoten, "end_lineno", knoten.lineno) or knoten.lineno
            for zeile in range(knoten.lineno, ende + 1):
                zuordnung[zeile] = knoten.name
    return zuordnung


def python_mutationen(pfad: str, text: str) -> list[Mutation]:
    """Alle Mutationen, die sich aus einer Python-Datei ergeben.

    Syntaxfehler in der Vorlage sind kein Befund dieses Bots -- dann gibt es
    hier nichts zu holen, und der Code-Bot ist der Zustaendige.
    """
    try:
        baum = ast.parse(text)
    except SyntaxError:
        return []

    anfaenge = _zeilenanfaenge(text)
    namen = _funktionsnamen(baum)
    gefunden: list[Mutation] = []

    def hinzu(start: int, ende: int, zeile: int, operator: str, alt: str,
              neu_text: str, wandel: str | None = None) -> None:
        """`wandel` beschreibt die Aenderung fuer den Bericht.

        Er wird **nur** dann aus `alt` gebaut, wenn `alt` ein fester Operator
        aus einer Tabelle hier ist. Wo eine beliebige Stelle des fremden
        Quelltexts ersetzt wird, muss der Aufrufer eine Beschreibung
        mitgeben -- sonst stuende in `if t == "losungswort"` das Losungswort
        im Bericht und damit im Action-Log.
        """
        if text[start:ende] != alt:
            # Die Position stimmt nicht mit dem Text ueberein -- dann lieber
            # keine Mutation als eine falsche.
            return
        neu = text[:start] + neu_text + text[ende:]
        if neu == text:
            return  # dieselbe Regel wie in der eigenen Gegenprobe
        gefunden.append(Mutation(
            pfad=pfad, zeile=zeile, operator=operator,
            wandel=wandel or f"{alt} -> {neu_text}", neu=neu,
            sicherheitsnah=_sicherheitsnah(pfad, namen.get(zeile, "")),
        ))

    for knoten in ast.walk(baum):
        # 1. Eine Vergleichsrichtung drehen.
        if isinstance(knoten, ast.Compare) and len(knoten.ops) == 1:
            op = type(knoten.ops[0])
            if op in _PY_VERGLEICH:
                alt, neu_text = _PY_VERGLEICH[op]
                links = knoten.left
                rechts = knoten.comparators[0]
                if links.end_lineno and rechts.col_offset is not None:
                    von = _spanne(anfaenge, links.end_lineno, links.end_col_offset)
                    bis = _spanne(anfaenge, rechts.lineno, rechts.col_offset)
                    stueck = text[von:bis]
                    versatz = stueck.find(alt)
                    if versatz >= 0 and _sauber(stueck, versatz, alt):
                        hinzu(von + versatz, von + versatz + len(alt),
                              knoten.lineno, "comparison-flipped", alt, neu_text)

        # 2. `and` zu `or` -- die Bedingung, die alles durchlaesst.
        elif isinstance(knoten, ast.BoolOp) and len(knoten.values) >= 2:
            alt = "and" if isinstance(knoten.op, ast.And) else "or"
            neu_text = "or" if alt == "and" else "and"
            erster, zweiter = knoten.values[0], knoten.values[1]
            if erster.end_lineno and zweiter.col_offset is not None:
                von = _spanne(anfaenge, erster.end_lineno, erster.end_col_offset)
                bis = _spanne(anfaenge, zweiter.lineno, zweiter.col_offset)
                stueck = text[von:bis]
                treffer = re.search(rf"\b{alt}\b", stueck)
                if treffer:
                    hinzu(von + treffer.start(), von + treffer.end(),
                          knoten.lineno, "boolean-operator-swapped", alt, neu_text)

        # 3. `not` streichen -- die verneinte Pruefung, die nicht mehr verneint.
        elif isinstance(knoten, ast.UnaryOp) and isinstance(knoten.op, ast.Not):
            ziel = knoten.operand
            if ziel.col_offset is not None:
                von = _spanne(anfaenge, knoten.lineno, knoten.col_offset)
                bis = _spanne(anfaenge, ziel.lineno, ziel.col_offset)
                if text[von:bis].strip() == "not":
                    hinzu(von, bis, knoten.lineno, "negation-removed", text[von:bis], "",
                          wandel="not <condition> -> <condition>")

        # 4. Ein `return` auf `True` festnageln -- "erlaubt alles".
        elif isinstance(knoten, ast.Return) and knoten.value is not None:
            wert = knoten.value
            if isinstance(wert, ast.Constant) and wert.value is True:
                continue  # ergaebe keinen Unterschied
            if wert.end_lineno:
                von = _spanne(anfaenge, wert.lineno, wert.col_offset)
                bis = _spanne(anfaenge, wert.end_lineno, wert.end_col_offset)
                hinzu(von, bis, knoten.lineno, "return-forced-true", text[von:bis], "True",
                      wandel="return <expression> -> return True")

    return gefunden


def _sauber(stueck: str, versatz: int, alt: str) -> bool:
    """Steht der Treffer wirklich fuer sich, nicht in `!=` oder `==`?"""
    davor = stueck[versatz - 1] if versatz > 0 else " "
    danach = stueck[versatz + len(alt)] if versatz + len(alt) < len(stueck) else " "
    return davor not in "=!<>" and danach not in "=!<>"


# --------------------------------------------------------------------------
# Mutationen fuer JavaScript und TypeScript -- zeilenweise, ohne Parser
# --------------------------------------------------------------------------
#
# Dieselbe Entscheidung wie beim Workflow-Bot: kein Fremdparser, also keine
# Abhaengigkeit. Der Preis ist Genauigkeit, und der wird hier bewusst in die
# **sichere** Richtung bezahlt.
#
# Eine Mutation, die Unsinn erzeugt, laesst die Pruefsuite umfallen und gilt
# als gefangen. Das kostet Budget, aber es meldet nichts Falsches. Gefaehrlich
# waere der andere Fall: eine Mutation in einem Kommentar oder in einer
# Zeichenkette aendert nichts am Verhalten, bleibt gruen -- und wuerde als
# entkommen gemeldet. Deshalb werden Kommentare und Zeichenketten ausgelassen,
# und zwar lieber einmal zu oft.

_JS_WANDEL = [
    ("comparison-flipped", "===", "!=="),
    ("comparison-flipped", "!==", "==="),
    ("boolean-operator-swapped", "&&", "||"),
    ("boolean-operator-swapped", "||", "&&"),
]

_JS_WORT = [
    ("constant-flipped", "true", "false"),
    ("constant-flipped", "false", "true"),
]

_JS_NAME = re.compile(
    r"(?:function\s+([A-Za-z_$][\w$]*)"
    r"|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*="
    r"|([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{)"
)


def _js_maskiert(zeile: str) -> str:
    """Die Zeile mit ausgeloeschten Zeichenketten und Kommentaren.

    Ersetzt wird Zeichen fuer Zeichen durch ein Leerzeichen, damit die Spalten
    stimmen. Ein Treffer, der in der Maske verschwunden ist, wird nicht
    mutiert.
    """
    raus = list(zeile)
    i = 0
    anfuehrung = ""
    while i < len(zeile):
        z = zeile[i]
        if anfuehrung:
            raus[i] = " "
            if z == "\\":
                if i + 1 < len(zeile):
                    raus[i + 1] = " "
                i += 2
                continue
            if z == anfuehrung:
                anfuehrung = ""
        elif z in "\"'`":
            anfuehrung = z
            raus[i] = " "
        elif z == "/" and i + 1 < len(zeile) and zeile[i + 1] == "/":
            for j in range(i, len(zeile)):
                raus[j] = " "
            break
        i += 1
    return "".join(raus)


def js_mutationen(pfad: str, text: str) -> list[Mutation]:
    """Alle Mutationen, die sich aus einer JS- oder TS-Datei ergeben."""
    zeilen = text.split("\n")
    gefunden: list[Mutation] = []
    in_blockkommentar = False
    letzter_name = ""

    for nummer, zeile in enumerate(zeilen, start=1):
        blank = zeile.strip()

        # Blockkommentare ueberspringen -- eine Mutation darin aendert nichts
        # und wuerde faelschlich als entkommen gelten.
        if in_blockkommentar:
            if "*/" in zeile:
                in_blockkommentar = False
            continue
        if blank.startswith("/*"):
            if "*/" not in blank[2:]:
                in_blockkommentar = True
            continue
        if blank.startswith("//") or blank.startswith("*"):
            continue

        maske = _js_maskiert(zeile)

        treffer = _JS_NAME.search(maske)
        if treffer:
            letzter_name = next((g for g in treffer.groups() if g), letzter_name)

        nah = _sicherheitsnah(pfad, letzter_name)

        def eintragen(spalte: int, alt: str, neu_text: str, operator: str) -> None:
            neue_zeile = zeile[:spalte] + neu_text + zeile[spalte + len(alt):]
            if neue_zeile == zeile:
                return
            kopie = list(zeilen)
            kopie[nummer - 1] = neue_zeile
            gefunden.append(Mutation(
                pfad=pfad, zeile=nummer, operator=operator,
                wandel=f"{alt} -> {neu_text}", neu="\n".join(kopie),
                sicherheitsnah=nah,
            ))

        for operator, alt, neu_text in _JS_WANDEL:
            start = 0
            while True:
                spalte = maske.find(alt, start)
                if spalte < 0:
                    break
                start = spalte + len(alt)
                # `===` enthaelt `==`; `&&&` gibt es nicht, aber `|||` in einer
                # Regex schon. Nur freistehende Treffer.
                davor = maske[spalte - 1] if spalte else " "
                danach = maske[spalte + len(alt)] if spalte + len(alt) < len(maske) else " "
                if davor in "=!<>&|" or danach in "=!<>&|":
                    continue
                eintragen(spalte, alt, neu_text, operator)

        for operator, alt, neu_text in _JS_WORT:
            for m in re.finditer(rf"\b{alt}\b", maske):
                eintragen(m.start(), alt, neu_text, operator)

    return gefunden


# --------------------------------------------------------------------------
# Quellen finden und Mutationen auswaehlen
# --------------------------------------------------------------------------


def ist_testdatei(relativ: str) -> bool:
    return bool(TESTMUSTER.search(relativ.replace(os.sep, "/")))


def finde_quellen(wurzel: str, ausschluss: tuple[str, ...] = ()) -> list[str]:
    """Alle mutierbaren Quelldateien, relativ zur Wurzel, in fester Reihenfolge."""
    gefunden: list[str] = []
    for ordner, unterordner, dateien in os.walk(wurzel):
        unterordner[:] = sorted(u for u in unterordner if u not in UEBERSPRINGEN)
        for datei in sorted(dateien):
            if not datei.endswith(QUELL_ENDUNGEN):
                continue
            voll = os.path.join(ordner, datei)
            relativ = os.path.relpath(voll, wurzel).replace(os.sep, "/")
            if ist_testdatei(relativ):
                continue
            if any(relativ.startswith(a.rstrip("/")) for a in ausschluss if a):
                continue
            gefunden.append(relativ)
    return gefunden


def mutationen_fuer(wurzel: str, relativ: str) -> list[Mutation]:
    voll = os.path.join(wurzel, relativ)
    try:
        with open(voll, encoding="utf-8") as griff:
            text = griff.read()
    except (OSError, UnicodeDecodeError):
        return []
    if relativ.endswith(".py"):
        return python_mutationen(relativ, text)
    return js_mutationen(relativ, text)


def waehle(alle: list[Mutation], budget: int) -> list[Mutation]:
    """Bestimmt, nicht zufaellig: sicherheitsnahe zuerst, dann nach Ort.

    Zwei Laeufe ueber denselben Stand pruefen dieselben Mutationen. Ein Bot,
    der jedes Mal etwas anderes misst, ist in einer CI nicht zu gebrauchen.

    Innerhalb einer Datei wird gestreut: erst die erste Mutation jeder Datei,
    dann die zweite. Sonst verbraucht eine einzige grosse Datei das ganze
    Budget, und der Rest des Repos bleibt ungeprueft, ohne dass es auffaellt.
    """
    geordnet = sorted(
        alle,
        key=lambda m: (not m.sicherheitsnah, m.pfad, m.zeile, m.operator, m.wandel),
    )
    nach_datei: dict[tuple[bool, str], list[Mutation]] = {}
    for mutation in geordnet:
        nach_datei.setdefault((not mutation.sicherheitsnah, mutation.pfad), []).append(mutation)

    runde = 0
    ausgewaehlt: list[Mutation] = []
    while len(ausgewaehlt) < budget:
        etwas_genommen = False
        for schluessel in sorted(nach_datei):
            liste = nach_datei[schluessel]
            if runde < len(liste):
                ausgewaehlt.append(liste[runde])
                etwas_genommen = True
                if len(ausgewaehlt) >= budget:
                    break
        if not etwas_genommen:
            break
        runde += 1
    return ausgewaehlt


# --------------------------------------------------------------------------
# Das Testkommando laufen lassen
# --------------------------------------------------------------------------


def zerlege(kommando: str) -> list[str]:
    """Das Testkommando in seine Teile, ohne Shell.

    **Ohne Shell ist Absicht.** Der Bot bekommt ein Kommando von aussen und
    fuehrt es aus -- das ist sein Zweck und nicht zu vermeiden. Was sich
    vermeiden laesst, ist die Shell dazwischen: mit ihr waere jedes `;` und
    jedes `&&` in dieser Zeichenkette ein zweites Kommando.

    Der eigene Code-Bot hat genau das hier angemahnt, solange die Shell noch
    mitlief. Die Regel zu entschaerfen waere der falsche Weg gewesen; der
    richtige ist, sie nicht mehr zu verletzen. (Und der Regelname darf hier
    nicht ausgeschrieben stehen -- sonst faengt der Bot den Kommentar ueber
    seinen eigenen Befund. Das ist in diesem Repo schon zweimal passiert.)

    Gekostet hat es nichts: `npm test`, `vitest run`, `bash tests/run.sh`,
    `python3 -m unittest discover` -- keines dieser Kommandos braucht eine
    Shell. Wer wirklich eine will, schreibt sie hin (`sh -c "a && b"`) und
    sieht sie dann auch in seiner Workflow-Datei stehen.
    """
    try:
        teile = shlex.split(kommando)
    except ValueError as fehler:
        raise Unprovable(f"the test command could not be read: {fehler}") from fehler
    if not teile:
        raise Unprovable("no test command given -- there is nothing to counter-prove against")
    return teile


def laufe(kommando: str, wurzel: str, zeitgrenze: int) -> bool:
    """True, wenn das Testkommando sauber durchlief.

    Eine Zeitueberschreitung gilt als **nicht** sauber. Eine Mutation, die den
    Lauf haengen laesst, ist gefangen -- jemand wuerde es merken.
    """
    try:
        fertig = subprocess.run(
            zerlege(kommando), cwd=wurzel, timeout=zeitgrenze,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return False
    except OSError as fehler:
        raise Unprovable(f"the test command could not be started: {fehler}") from fehler
    return fertig.returncode == 0


# --------------------------------------------------------------------------
# Der Lauf
# --------------------------------------------------------------------------


def gegenprobe(
    wurzel: str,
    testkommando: str,
    budget: int = 20,
    zeitgrenze: int = 600,
    ausschluss: tuple[str, ...] = (),
    laeufer=laufe,
) -> tuple[list[Finding], dict]:
    """Bricht den Code absichtlich und meldet, was niemandem auffiel.

    Gibt die Befunde und die Deckung zurueck: wie viele Mutationen gepruet
    wurden, wie viele gefangen. Ein gruener Lauf ohne diese Zahlen waere genau
    die Sorte Erfolg, gegen die dieser Bot gebaut ist.
    """
    zerlege(testkommando)  # frueh scheitern, nicht erst mitten im Lauf

    # 1. Die Vorlage muss gruen sein. Sonst ist jede Messung danach wertlos:
    #    man kann nicht unterscheiden, ob die Mutation gefangen wurde oder ob
    #    es schon vorher kaputt war.
    if not laeufer(testkommando, wurzel, zeitgrenze):
        raise Unprovable(
            "the test suite is not green before mutation -- "
            "a caught mutation cannot be told apart from an already broken build"
        )

    quellen = finde_quellen(wurzel, ausschluss)
    alle: list[Mutation] = []
    for relativ in quellen:
        alle.extend(mutationen_fuer(wurzel, relativ))

    if not alle:
        raise Unprovable(
            "no mutation could be generated -- no source file was found that this bot can break"
        )

    ausgewaehlt = waehle(alle, budget)
    befunde: list[Finding] = []
    gefangen = 0

    for mutation in ausgewaehlt:
        voll = os.path.join(wurzel, mutation.pfad)
        with open(voll, encoding="utf-8") as griff:
            vorlage = griff.read()
        if mutation.neu == vorlage:
            # Dieselbe Zusicherung wie in der eigenen Gegenprobe: eine
            # Mutation, die nichts aendert, misst nichts.
            continue
        try:
            with open(voll, "w", encoding="utf-8") as griff:
                griff.write(mutation.neu)
            ueberlebt = laeufer(testkommando, wurzel, zeitgrenze)
        finally:
            # Auch bei einem Abbruch mitten im Lauf bleibt das Repo, wie es war.
            with open(voll, "w", encoding="utf-8") as griff:
                griff.write(vorlage)

        if ueberlebt:
            befunde.append(_befund(mutation))
        else:
            gefangen += 1

    deckung = {
        "test_command": testkommando,
        "source_files": len(quellen),
        "mutations_possible": len(alle),
        "mutations_run": gefangen + len(befunde),
        "mutations_caught": gefangen,
        "mutations_survived": len(befunde),
    }
    return befunde, deckung


def _befund(mutation: Mutation) -> Finding:
    nah = mutation.sicherheitsnah
    return Finding(
        bot=BOT,
        rule="mutation-survived",
        title=f"A deliberate break went unnoticed: {mutation.operator}",
        # Sicherheitsnaher Code wiegt schwerer. Das ist eine Heuristik ueber
        # Datei- und Funktionsnamen und wird als solche erklaert -- sie
        # entscheidet nur den Schweregrad, nie ob geprueft wird.
        severity="high" if nah else "low",
        # Gemessen, nicht geraten: die Tests liefen gruen, obwohl der Code
        # nachweislich veraendert war.
        confidence="high",
        path=mutation.pfad,
        line=mutation.zeile,
        explanation=(
            "This code was deliberately changed and the test suite stayed green. "
            "Nothing here checks the behaviour that was broken"
            + (
                ". The file or function name suggests security-relevant code, "
                "which is why this is rated high -- that name match is a heuristic, "
                "the surviving mutation is not."
                if nah
                else "."
            )
        ),
        remediation=(
            "Add a test that fails when this behaviour changes. If the change is "
            "genuinely harmless, the code may be dead -- delete it instead."
        ),
        # Nie die Quellzeile: in `if token == "..."` steckt ein Geheimnis,
        # und dieser Bericht landet in fremden Action-Logs.
        evidence=f"{mutation.operator}: {mutation.wandel} (source line not shown)",
    )


def regeln() -> list[dict]:
    """Die Regeltabelle fuer die Website. Eine Quelle, kein zweiter Text."""
    return [
        {
            "name": "mutation-survived",
            "titel": "A deliberate break went unnoticed",
            "schwere": "high",
            "was": (
                "The bot changes the code on purpose -- flips a comparison, turns an "
                "`and` into an `or`, forces a `return` to `true` -- and runs your own "
                "test suite. Whatever stays green is a behaviour nothing checks. "
                "Rated high in security-relevant code, low elsewhere."
            ),
        },
    ]
