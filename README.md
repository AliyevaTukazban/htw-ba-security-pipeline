# Versuchsaufbau zur Bachelorarbeit

**Security-Automatisierung in CI/CD-Pipelines: Vergleichende Bewertung frei verfügbarer SAST- und Dependency-Scanning-Werkzeuge**
Tukazban Aliyeva, HTW Berlin, Wirtschaftsinformatik

Dieses Repository enthält den vollständigen Versuchsaufbau aus Kapitel 3 der Arbeit. Untersucht werden
die SAST-Werkzeuge Semgrep CE und CodeQL sowie die SCA-Werkzeuge npm audit und Trivy an OWASP Juice Shop.

## Aufbau

| Pfad | Inhalt |
|---|---|
| `.github/workflows/1-vorbereitung.yml` | Stichtag: Versionen einfrieren, Lockfiles erzeugen, Referenzlisten erstellen |
| `.github/workflows/2-messung.yml` | 12 Messreihen × 5 Läufe auf `ubuntu-24.04`, danach Auswertung |
| `.github/workflows/3-auswertung.yml` | Auswertung erneut berechnen, z. B. nach der manuellen Prüfung |
| `scripts/bereich.py` | Untersuchungsbereich von Frontend und Backend (gemeinsam für alle Skripte) |
| `scripts/sast_referenzliste.py` | Referenzliste SAST aus den Markierungen `vuln-code-snippet` |
| `scripts/sca_referenzliste.py` | Referenzliste SCA aus der GitHub Advisory Database |
| `scripts/auswertung.py` | Einheitliches Schema, Abgleich, Kennzahlen, Laufzeiten, Prüflisten |
| `scripts/diagramme.py` | Diagramme für Kapitel 5 |
| `config/versionen.json` | eingefrorene Versionen und Stichtag (entsteht in Schritt 1) |
| `lockfiles/` | package.json und package-lock.json von Backend und Frontend zum Stichtag |
| `ground_truth/` | Referenzlisten `sast.json` und `sca.json` |
| `ergebnisse/` | Rohdaten aller Läufe, Kennzahlen (CSV/JSON) und Diagramme |
| `review/` | Prüflisten für die manuelle Prüfung |

## Ablauf

1. **Actions → „1 Vorbereitung (Stichtag)“ → Run workflow.** Der Tag dieses Laufs ist der Stichtag.
   Danach liegen `config/versionen.json`, `lockfiles/` und `ground_truth/` im Repository.
2. **Actions → „2 Messung“ → Run workflow** mit `umfang = test`. Ein Lauf je Messreihe (12 Jobs) zum Prüfen.
3. Wenn alles grün ist: **„2 Messung“** erneut mit `umfang = vollständig` (60 Jobs).
   Schritt 1 und Schritt 3 sollten am selben Tag laufen, weil sich npm audit und die Datenbank von Trivy täglich ändern.
4. **Manuelle Prüfung:** `review/pruefliste_sast.csv` und `review/pruefliste_sca.csv` herunterladen, in der Spalte
   `bewertung` jeweils `echt` oder `fehlalarm` eintragen, in `begruendung` kurz den Grund. Datei wieder hochladen
   (gleicher Name, gleicher Ordner). Workflow 3 startet dann automatisch und berechnet die geprüfte Precision.

## Festlegungen (für Kapitel 4)

- **Untersuchungsbereich:** Frontend = `frontend/src` ohne `frontend/src/assets`; Backend = übrige Dateien ohne
  `frontend/`, `test/`, `data/static/codefixes/`, `rsn/`, `scripts/`, versteckte Ordner und `cypress.config.ts`.
  Testdateien (`*.spec.ts`, `*.test.ts`) sind überall ausgeschlossen. Untersucht werden TypeScript und JavaScript,
  im Frontend zusätzlich die HTML-Vorlagen.
- **Semgrep:** Regelsatz `p/default`, `--metrics off`.
- **CodeQL:** CLI-Bundle, Abfragesammlung `javascript-security-extended`. Datenbank und Analyse werden getrennt gemessen.
- **npm audit:** `--json`, Variante ohne Build-Abhängigkeiten mit `--omit=dev`.
- **Trivy:** `trivy fs --scanners vuln`, Variante mit Build-Abhängigkeiten mit `--include-dev-deps`.
  Der Download der Datenbank wird getrennt gemessen; „gesamt“ ist bei Trivy die reine Scan-Zeit.
- **Referenzliste SCA:** geprüfte Einträge aus `github/advisory-database` (Commit in `config/versionen.json`),
  nur `high` und `critical`. Ein Paket gilt als Build-Abhängigkeit, wenn es im Lockfile nur mit `dev: true` vorkommt.
- **Referenzliste SAST:** Zeilen mit `vuln-code-snippet vuln-line`, Treffer bei höchstens 2 Zeilen Abstand.
- **Stichprobe:** mehr als 50 nicht zugeordnete SAST-Befunde je Werkzeug → Zufallsstichprobe von 50 (Seed 42).
- **Wiederholungen:** jeder der 5 Läufe läuft auf einer eigenen virtuellen Maschine (`ubuntu-24.04`).
  `ergebnisse/konsistenz.csv` zeigt, ob die Befunde in allen Läufen gleich sind. Ausgewertet wird Lauf 1.

## Ergebnisdateien

| Datei | Inhalt |
|---|---|
| `ergebnisse/kennzahlen.csv` | TP, FP, FN, Precision (streng/geprüft), Recall, F1 je Messreihe |
| `ergebnisse/laufzeiten.csv` | Median, Minimum, Maximum je Messreihe und Messgröße |
| `ergebnisse/ueberschneidung.csv` | beide / nur eines / keines der Werkzeuge |
| `ergebnisse/konsistenz.csv` | Vergleich der 5 Läufe |
| `ergebnisse/befunde_normalisiert.csv` | alle Befunde im einheitlichen Schema (Tabelle 6) |
| `ergebnisse/diagramme/` | Diagramme für Kapitel 5 |
