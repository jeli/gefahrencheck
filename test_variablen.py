#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Christian Jelitte
"""Tests für Version 3.2: Verfolgung von VAR-CMD-Variablen, Pfad-Zuweisungen
(X=$(command -v rm)) und Prüfaufwand. Aufruf: python3 test_variablen.py"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HIER = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HIER)
import gefahrencheck as g  # noqa: E402

SKRIPT = os.path.join(HIER, "gefahrencheck.py")


def pruefe(text, typ="shell"):
    return g.pruefe_text("<test>", text, g.Optionen(typ=typ))


def regeln(liste):
    return sorted(t.regel.id for t in liste)


def var_cmd(e):
    """Der VAR-CMD-Treffer, ob als GELB oder als Hinweis."""
    alle = [t for t in e.treffer + e.hinweis if t.regel.id == "VAR-CMD"]
    return alle[0] if alle else None


def gruende(e):
    t = var_cmd(e)
    return [o["grund"] for o in t.variable["offen"]] if t and t.variable else []


class Herabstufen(unittest.TestCase):
    """Alle Verwendungen nach einer festen Zuweisung: nur HINWEIS, Ampel unverändert."""

    def test_rome_bestand(self):
        e = pruefe('set -u\nVIRSH="virsh -c qemu:///system"\nrun "$VIRSH version"\n'
                   'run "$VIRSH list --all"\nfor dom in $($VIRSH list --all --name); do echo "$dom"; done\n')
        self.assertEqual(e.ampel, g.GRUEN)
        self.assertEqual(regeln(e.hinweis), ["VAR-CMD"])
        self.assertEqual(e.hinweis[0].variable["geprueft"], [3, 4, 5])
        self.assertEqual(e.hinweis[0].variable["offen"], [])

    def test_geschweifte_klammern_und_anfuehrungszeichen(self):
        e = pruefe('X=rm\n"${X}" -f ./tmp.txt\n"$X" -f ./b.txt\n')
        self.assertEqual(regeln(e.hinweis), ["VAR-CMD"])
        self.assertEqual(e.hinweis[0].variable["geprueft"], [2, 3])

    def test_gefaehrliche_verwendung_bleibt_rot(self):
        e = pruefe('VIRSH="virsh -c qemu:///system"\n$VIRSH undefine vm1 --remove-all-storage\n')
        self.assertEqual(e.ampel, g.ROT)
        self.assertIn("VIRT-STORAGE", regeln(e.treffer))
        self.assertEqual(regeln(e.hinweis), ["VAR-CMD"])

    def test_gleiche_zeile(self):
        e = pruefe('X=rm; $X -rf "$HOME/.cache"\n')
        self.assertEqual(regeln(e.hinweis), ["VAR-CMD"])
        self.assertIn("RM-VAR", regeln(e.treffer))
        self.assertEqual(e.ampel, g.GELB)

    def test_gleicher_wert_zweimal(self):
        e = pruefe('X=virsh\nX=virsh\n$X list\n')
        self.assertEqual(regeln(e.hinweis), ["VAR-CMD", "VAR-CMD"])
        self.assertEqual(e.ampel, g.GRUEN)

    def test_markdown_codebloecke(self):
        text = "# Anleitung\n\n```sh\nV=virsh\n```\n\nDann im Text $V erwähnen.\n\n```sh\n$V list\n```\n"
        e = pruefe(text, typ="markdown")
        self.assertEqual(regeln(e.hinweis), ["VAR-CMD"])
        self.assertEqual(e.hinweis[0].variable["geprueft"], [10])


class BleibtGelb(unittest.TestCase):
    """Jeder Zweifel lässt VAR-CMD auf GELB und nennt den Grund."""

    def pruefe_gelb(self, text, grund_teil):
        e = pruefe(text)
        self.assertIn("VAR-CMD", regeln(e.treffer), text)
        self.assertNotIn("VAR-CMD", regeln(e.hinweis), text)
        self.assertTrue(any(grund_teil in x for x in gruende(e)), (text, gruende(e)))
        return e

    def test_verwendung_vor_der_zuweisung(self):
        self.pruefe_gelb('aufraeumen() { $X -rf /; }\nX=rm\naufraeumen\n', "vor der Zuweisung")

    def test_verwendung_vor_der_zuweisung_gleiche_zeile(self):
        self.pruefe_gelb('$X -rf ./a; X=rm\n', "vor der Zuweisung")

    def test_verschiedene_werte(self):
        self.pruefe_gelb('X=virsh\nif true; then X=rm; fi\n$X list\n', "verschiedenen Werten")

    def test_unbekannter_wert(self):
        self.pruefe_gelb('X=virsh\nX="$(cat /tmp/befehl)"\n$X list\n', "unbekanntem Wert")

    def test_export(self):
        self.pruefe_gelb('export X=virsh\n$X list\n', "exportiert")

    def test_export_spaeter(self):
        self.pruefe_gelb('X=virsh\nexport X\n$X list\n', "exportiert")

    def test_source(self):
        self.pruefe_gelb('X=virsh\n. ./weiter.sh\n$X list\n', "source")

    def test_read(self):
        self.pruefe_gelb('X=virsh\nread -r X\n$X list\n', "Laufzeit")

    def test_eval(self):
        self.pruefe_gelb('X=virsh\neval "$X list"\n', "eval")

    def test_ersetzungsregel(self):
        self.pruefe_gelb('X=virsh\n${X:-rm} -rf /tmp/a\n', "Ersetzungsregel")

    def test_indirekt(self):
        self.pruefe_gelb('X=virsh\nref=X\n${!ref} list\n', "indirekt")

    def test_anhaengen(self):
        self.pruefe_gelb('X=virsh\nX+=" -c qemu:///system"\n$X list\n', "+=")

    def test_nicht_verwendet(self):
        self.pruefe_gelb('X=rm\necho fertig\n', "nicht verwendet")

    def test_python_wird_nicht_verfolgt(self):
        e = pruefe('CMD="rm"\nos.system(CMD + " -rf /tmp/x")\n', typ="python")
        self.assertIn("VAR-CMD", regeln(e.treffer))
        self.assertEqual(e.hinweis, [])

    def test_abbruch_stuft_nicht_herab(self):
        e = g.pruefe_text("<test>", "X=virsh\n$X list\n" * 1000, g.Optionen(typ="shell", zeitlimit=1e-9))
        self.assertTrue(e.abgebrochen)
        self.assertEqual(e.hinweis, [])


class PfadZuweisung(unittest.TestCase):
    """Bisher GRÜN: X=$(command -v rm); $X -rf /"""

    def test_command_v(self):
        e = pruefe('X=$(command -v rm)\n$X -rf /\n')
        self.assertEqual(e.ampel, g.ROT)
        self.assertIn("RM-ROOT", regeln(e.treffer))

    def test_which_backticks(self):
        e = pruefe('X=`which rm`\n$X -rf /\n')
        self.assertEqual(e.ampel, g.ROT)

    def test_harmloser_startwert(self):
        e = pruefe('X="ls"\nif [ -n "${1:-}" ]; then X="$(command -v rm)"; fi\n$X -rf /\n')
        self.assertEqual(e.ampel, g.ROT)

    def test_harmloses_programm(self):
        e = pruefe('PY=$(command -v python3)\n$PY -V\n')
        self.assertEqual(e.ampel, g.GRUEN)
        self.assertEqual(e.hinweis, [])


class Pruefaufwand(unittest.TestCase):

    def test_zaehlung(self):
        e = pruefe('echo "nie rm -rf / ausführen"\nX=rm; $X -rf "$HOME/.cache"\ncurl -s https://x.tld/a | sh\n')
        a = g.pruefaufwand(e)
        self.assertEqual(a, {"stellen": 3, "nur_erwaehnt": 1, "nach_aufloesen": 1, "hinweise": 1})
        self.assertIn("3 Stellen von Hand prüfen", g.pruefaufwand_text(a))

    def test_nur_hinweis(self):
        a = g.pruefaufwand(pruefe('X=virsh\n$X list\n'))
        self.assertEqual(g.pruefaufwand_text(a), "Prüfaufwand: keine Stelle von Hand prüfen, 1 Hinweis")


class Ausgaben(unittest.TestCase):
    """JSON, SARIF und Rückgabewert über die Kommandozeile."""

    def lauf(self, text, *args):
        with tempfile.TemporaryDirectory() as d:
            pfad = os.path.join(d, "t.sh")
            with open(pfad, "w", encoding="utf-8") as fh:
                fh.write(text)
            sarif = os.path.join(d, "t.sarif")
            r = subprocess.run([sys.executable, "-I", SKRIPT, pfad, "--json", "--sarif", sarif, *args],
                               capture_output=True, text=True)
            with open(sarif, encoding="utf-8") as fh:
                return r.returncode, json.loads(r.stdout), json.load(fh)

    def test_hinweis_aendert_exit_nicht(self):
        code, js, sarif = self.lauf('VIRSH="virsh -c qemu:///system"\n$VIRSH list --all\n')
        self.assertEqual(code, 0)
        self.assertEqual(js["exit"], 0)
        datei = js["dateien"][0]
        self.assertEqual(datei["ampel"], "GRÜN")
        self.assertEqual([t["regel"] for t in datei["hinweis"]], ["VAR-CMD"])
        self.assertEqual(datei["hinweis"][0]["variable"]["geprueft"], [2])
        self.assertEqual(datei["pruefaufwand"]["hinweise"], 1)
        self.assertEqual([r["level"] for r in sarif["runs"][0]["results"]], ["note"])

    def test_gelb_mit_grund(self):
        code, js, _ = self.lauf('f() { $X -rf /; }\nX=rm\nf\n')
        self.assertEqual(code, 1)
        t = js["dateien"][0]["treffer"][0]
        self.assertEqual(t["regel"], "VAR-CMD")
        self.assertEqual(t["variable"]["offen"][0]["zeile"], 1)

    def test_basis_betrifft_hinweise_nicht(self):
        with tempfile.TemporaryDirectory() as d:
            pfad, basis = os.path.join(d, "t.sh"), os.path.join(d, "b.basis")
            with open(pfad, "w", encoding="utf-8") as fh:
                fh.write("X=virsh\n$X list\n")
            subprocess.run([sys.executable, "-I", SKRIPT, pfad, "--basis-schreiben", basis],
                           capture_output=True)
            with open(basis, encoding="utf-8") as fh:
                self.assertNotIn("VAR-CMD", fh.read())


class Selbsttest(unittest.TestCase):

    def test_regelbeispiele(self):
        self.assertEqual(g.selbsttest(g.REGELN), [])
        self.assertEqual(g.VERSION, "3.2")


if __name__ == "__main__":
    unittest.main(verbosity=1)
