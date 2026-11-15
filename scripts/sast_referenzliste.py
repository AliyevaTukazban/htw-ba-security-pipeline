"""Erstellt die Referenzliste für die SAST-Werkzeuge (Abschnitt 3.3.2).

Liest die Markierungen der Coding Challenges (vuln-code-snippet ...) aus den
TypeScript- und JavaScript-Dateien von Juice Shop. Testdateien und die
Musterlösungen werden über bereich.py ausgelassen.

Aufruf: python sast_referenzliste.py <juice-shop-ordner> <ausgabe.json>
"""
import json
import os
import re
import sys
from collections import OrderedDict

sys.path.insert(0, os.path.dirname(__file__))
import bereich  # noqa: E402

MARKE = re.compile(r"vuln-code-snippet\s+(start|end|vuln-line)\b\s*(.*)$")


def namen(rest):
    return [n for n in re.split(r"\s+", rest.strip()) if n and n.endswith("Challenge")]


def lesen(wurzel):
    challenges = OrderedDict()
    for teil in ("frontend", "backend"):
        for rel in sorted(bereich.dateien(wurzel, teil, nur_code=True)):
            if not rel.endswith((".ts", ".js")):
                continue
            with open(os.path.join(wurzel, rel), encoding="utf-8", errors="replace") as f:
                zeilen = f.read().splitlines()
            for nr, zeile in enumerate(zeilen, start=1):
                m = MARKE.search(zeile)
                if not m:
                    continue
                art, rest = m.groups()
                for name in namen(rest):
                    c = challenges.setdefault(name, {"challenge": name, "teil": teil, "datei": rel,
                                                     "abschnitt": [None, None], "verwundbare_zeilen": []})
                    if c["datei"] != rel:
                        # sehr selten: Challenge in mehreren Dateien markiert
                        c.setdefault("weitere_dateien", {}).setdefault(rel, [])
                    if art == "start":
                        c["abschnitt"][0] = nr
                    elif art == "end":
                        c["abschnitt"][1] = nr
                    elif c["datei"] == rel:
                        c["verwundbare_zeilen"].append(nr)
                    else:
                        c["weitere_dateien"][rel].append(nr)
    # nur Challenges mit mindestens einer markierten verwundbaren Zeile
    return [c for c in challenges.values() if c["verwundbare_zeilen"]]


if __name__ == "__main__":
    wurzel, ziel = sys.argv[1], sys.argv[2]
    liste = lesen(wurzel)
    zusammen = {
        "beschreibung": "Referenzliste SAST: markierte verwundbare Zeilen der Coding Challenges",
        "anzahl": len(liste),
        "anzahl_frontend": sum(c["teil"] == "frontend" for c in liste),
        "anzahl_backend": sum(c["teil"] == "backend" for c in liste),
        "challenges": liste,
    }
    os.makedirs(os.path.dirname(ziel) or ".", exist_ok=True)
    with open(ziel, "w", encoding="utf-8") as f:
        json.dump(zusammen, f, indent=2, ensure_ascii=False)
    print(f"{zusammen['anzahl']} Challenges (Frontend {zusammen['anzahl_frontend']}, Backend {zusammen['anzahl_backend']})")
