#!/usr/bin/env python3
"""
analyze_findings.py

Liest die JSON-Reports von Semgrep, npm audit und Trivy ein, überführt sie
in ein gemeinsames Schema (Normalisierung) und vergleicht die Funde gegen
eine Referenzliste bekannter Schwachstellen im Testobjekt.

Berechnete Kennzahlen je Tool:
    - true_positives   : erkannte Funde, die in der Referenzliste stehen
    - false_positives  : erkannte Funde, die NICHT in der Referenzliste stehen
    - false_negatives  : Referenz-Funde, die das Tool NICHT gefunden hat
    - precision        : true_positives / (true_positives + false_positives)
    - recall           : true_positives / (true_positives + false_negatives)
    - f1_score         : harmonisches Mittel aus precision und recall
    - runtime_seconds  : Laufzeit des jeweiligen Scans (aus scan-timings.json)

Die Referenzliste (reference_vulnerabilities.json) muss vorab manuell
gepflegt werden: Sie enthält die tatsächlich im Testobjekt bekannten
Schwachstellen (z. B. dokumentierte CVEs oder absichtlich eingebaute
Lücken bei OWASP Juice Shop). Ohne diese "Ground Truth" lässt sich keine
Erkennungsgüte berechnen - das ist der methodische Kern der Auswertung.

Nutzung:
    python analyze_findings.py \
        --semgrep reports/semgrep.json \
        --npm-audit reports/npm-audit.json \
        --trivy reports/trivy.json \
        --timings reports/scan-timings.json \
        --reference reference_vulnerabilities.json \
        --output reports/auswertung.json \
        --output-csv reports/auswertung.csv
"""

import argparse
import csv
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Finding:
    """Normalisierte Repräsentation eines Funds, unabhängig vom Ursprungstool."""
    tool: str
    identifier: str       # CVE-ID, Rule-ID o.ä. - zentrales Vergleichsmerkmal
    severity: str
    file: str = ""
    description: str = ""

    def key(self) -> str:
        """Vergleichsschlüssel für den Abgleich mit der Referenzliste.

        Bewusst nur über die Kennung (CVE/Rule-ID), nicht über Tool oder
        Datei - so werden identische Schwachstellen, die von mehreren
        Tools oder in mehreren Dateien gemeldet werden, korrekt als
        dieselbe Schwachstelle erkannt.
        """
        return self.identifier.strip().lower()


def load_json(path: str) -> dict:
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        print(f"[Warnung] Datei nicht gefunden oder leer: {path}", file=sys.stderr)
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[Warnung] Konnte {path} nicht parsen: {exc}", file=sys.stderr)
        return {}


# ---------------------------------------------------------------------------
# Parser je Tool: übersetzen das jeweilige Ausgabeformat in Finding-Objekte.
# Diese Funktionen sind der einzige Teil, der bei Austausch eines Tools
# angepasst werden muss.
# ---------------------------------------------------------------------------

def parse_semgrep(data: dict) -> list[Finding]:
    findings = []
    for result in data.get("results", []):
        check_id = result.get("check_id", "unknown-rule")
        severity = (
            result.get("extra", {})
            .get("severity", "UNKNOWN")
        )
        path = result.get("path", "")
        message = result.get("extra", {}).get("message", "")
        findings.append(Finding(
            tool="semgrep",
            identifier=check_id,
            severity=severity,
            file=path,
            description=message,
        ))
    return findings


def parse_npm_audit(data: dict) -> list[Finding]:
    findings = []
    # npm audit --json hat je nach npm-Version ein unterschiedliches Schema.
    # Neuere npm-Versionen (>=7) liefern "vulnerabilities" als Dict.
    vulns = data.get("vulnerabilities", {})
    for pkg_name, info in vulns.items():
        severity = info.get("severity", "unknown")
        via = info.get("via", [])
        for entry in via:
            if isinstance(entry, dict):
                url = entry.get("url", "")
                title = entry.get("title", "")
                # Nur die Advisory-ID (z. B. GHSA-xxxx) extrahieren, nicht die
                # volle URL - sonst stimmt das Format nicht mit
                # reference_vulnerabilities.json ueberein und es gibt nie
                # einen Treffer (Bug in der Vorversion dieses Skripts).
                if "advisories/" in url:
                    identifier = url.rstrip("/").split("advisories/")[-1]
                else:
                    identifier = title or pkg_name
                description = title
            else:
                # "via" kann auch nur den Paketnamen als String enthalten
                identifier = f"{pkg_name}:{entry}"
                description = str(entry)
            findings.append(Finding(
                tool="npm_audit",
                identifier=str(identifier),
                severity=severity,
                file="package.json",
                description=description,
            ))
    return findings


def parse_trivy(data: dict) -> list[Finding]:
    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(Finding(
                tool="trivy",
                identifier=vuln.get("VulnerabilityID", "unknown-cve"),
                severity=vuln.get("Severity", "UNKNOWN"),
                file=target,
                description=vuln.get("Title", ""),
            ))
    return findings


PARSERS = {
    "semgrep": parse_semgrep,
    "npm_audit": parse_npm_audit,
    "trivy": parse_trivy,
}


def load_reference(path: str) -> set[str]:
    """Lädt die Ground-Truth-Liste bekannter Schwachstellen.

    Erwartetes Format (reference_vulnerabilities.json):
        {
          "known_vulnerabilities": [
            {"identifier": "CVE-2021-XXXXX", "description": "..."},
            {"identifier": "GHSA-xxxx-xxxx-xxxx", "description": "..."}
          ]
        }
    """
    data = load_json(path)
    entries = data.get("known_vulnerabilities", [])
    return {str(e["identifier"]).strip().lower() for e in entries if "identifier" in e}


def evaluate_tool(tool_name: str, findings: list[Finding], reference: set[str]) -> dict:
    found_keys = {f.key() for f in findings}

    true_positives = found_keys & reference
    false_positives = found_keys - reference
    false_negatives = reference - found_keys

    tp, fp, fn = len(true_positives), len(false_positives), len(false_negatives)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "tool": tool_name,
        "total_findings": len(findings),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3),
    }


def main():
    parser = argparse.ArgumentParser(description="Werte Security-Scan-Reports aus.")
    parser.add_argument("--semgrep", required=True)
    parser.add_argument("--npm-audit", required=True)
    parser.add_argument("--trivy", required=True)
    parser.add_argument("--timings", required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output", required=True, help="Ausgabe als JSON")
    parser.add_argument("--output-csv", required=True, help="Ausgabe als CSV (für Excel/LaTeX-Tabellen)")
    args = parser.parse_args()

    reference = load_reference(args.reference)
    if not reference:
        print(
            "[Hinweis] Referenzliste ist leer. Precision/Recall können erst "
            "berechnet werden, nachdem reference_vulnerabilities.json mit den "
            "bekannten Schwachstellen des Testobjekts befüllt wurde.",
            file=sys.stderr,
        )

    raw_reports = {
        "semgrep": load_json(args.semgrep),
        "npm_audit": load_json(args.npm_audit),
        "trivy": load_json(args.trivy),
    }
    timings = load_json(args.timings)

    results = []
    for tool_name, raw in raw_reports.items():
        findings = PARSERS[tool_name](raw)
        metrics = evaluate_tool(tool_name, findings, reference)
        timing_key = {
            "semgrep": "semgrep_seconds",
            "npm_audit": "npm_audit_seconds",
            "trivy": "trivy_seconds",
        }[tool_name]
        metrics["runtime_seconds"] = timings.get(timing_key, None)
        results.append(metrics)

    output = {
        "reference_size": len(reference),
        "results": results,
    }

    Path(args.output).write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    with open(args.output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "tool", "total_findings", "true_positives", "false_positives",
            "false_negatives", "precision", "recall", "f1_score", "runtime_seconds",
        ])
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    print(json.dumps(output, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
