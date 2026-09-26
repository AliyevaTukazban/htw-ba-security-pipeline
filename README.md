# Security-Scan-Pipeline zur Werkzeugbewertung

Implementierungsteil zur Bachelorarbeit: automatisierte Ausführung von Semgrep (SAST), npm audit und Trivy (Dependency Scanning) gegen ein Testobjekt mit bekannten Schwachstellen, plus Auswertungsskript, das Erkennungsgüte (Precision/Recall/F1) und Laufzeit je Tool berechnet.

## Aufbau

.github/workflows/security-scan.yml   Pipeline (GitHub Actions)
scripts/analyze_findings.py           Auswertungsskript
scripts/requirements.txt              Python-Abhängigkeiten (aktuell leer)
reference_vulnerabilities.json        Ground Truth - MUSS von dir befüllt werden
reports/                              Ablageort für generierte Reports (leer im Repo)

## So bringst du es zum Laufen

1. Ground Truth pflegen (wichtigster Schritt): Öffne reference_vulnerabilities.json und trage die tatsächlich bekannten Schwachstellen deines Testobjekts ein. Für OWASP Juice Shop findest du eine offizielle Liste der eingebauten Challenges/Lücken auf der Projekt-Seite.

2. Pipeline manuell auslösen: Im GitHub-Repo unter „Actions" -> „Security Scan Pipeline" -> „Run workflow".

3. Ergebnisse abholen: Nach Abschluss des Workflows liegen unter „Artifacts" zwei ZIP-Dateien mit den Rohdaten und der Auswertung (CSV/JSON).

## Für die Auswertung in der Arbeit

Die CSV-Datei liefert dir pro Tool: Gesamtfunde, True/False Positives, False Negatives, Precision, Recall, F1-Score und Laufzeit in Sekunden. Das ist die direkte Datengrundlage für Kapitel „Ergebnisse".
