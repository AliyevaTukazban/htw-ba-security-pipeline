"""Untersuchungsbereich von Frontend und Backend (Kapitel 3.2 / 3.4).

Wird von allen Skripten gemeinsam genutzt, damit Scan, Referenzliste und
Zählung (Tabelle 5) exakt dieselben Dateien betrachten.
"""
import os
import shutil
import sys

CODE_ENDUNGEN = (".ts", ".js")
FRONTEND_ZUSATZ = (".html",)          # Angular-Vorlagen gehören zum Frontend
HILFSDATEIEN = ("package.json",)       # für CodeQL (Projektstruktur), wird nicht gezählt

# Teile von Juice Shop, die nicht untersucht werden
BACKEND_AUSGESCHLOSSEN = (
    "frontend/",              # eigener Teil
    "test/",                  # Testdateien
    "data/static/codefixes/", # Musterlösungen der Coding Challenges
    "rsn/",                   # Hilfswerkzeug für die Musterlösungen
    "scripts/",               # Hilfsskripte für die Entwicklung
    "node_modules/",
)
FRONTEND_EINGESCHLOSSEN = "frontend/src/"
FRONTEND_AUSGESCHLOSSEN = (
    "frontend/src/assets/",   # mitgelieferte fremde Bibliotheken (z. B. three.js)
)
DATEI_AUSGESCHLOSSEN = ("cypress.config.ts",)


def _versteckt(rel):
    return any(teil.startswith(".") for teil in rel.split("/"))


def ist_testdatei(rel):
    name = rel.rsplit("/", 1)[-1]
    return name.endswith((".spec.ts", ".test.ts", ".spec.js", ".test.js"))


def im_bereich(rel, teil, nur_code=False):
    """True, wenn die Datei (Pfad relativ zur Juice-Shop-Wurzel) zum Teil gehört."""
    rel = rel.replace("\\", "/")
    while rel.startswith("./"):
        rel = rel[2:]
    if _versteckt(rel) or ist_testdatei(rel) or rel in DATEI_AUSGESCHLOSSEN:
        return False
    endungen = CODE_ENDUNGEN + (FRONTEND_ZUSATZ if teil == "frontend" else ())
    name = rel.rsplit("/", 1)[-1]
    ist_code = rel.endswith(endungen)
    ist_hilf = (not nur_code) and (name in HILFSDATEIEN or (name.startswith("tsconfig") and name.endswith(".json")))
    if not (ist_code or ist_hilf):
        return False
    if teil == "frontend":
        if ist_hilf and (rel == "frontend/package.json" or rel.startswith("frontend/tsconfig")):
            return True
        return rel.startswith(FRONTEND_EINGESCHLOSSEN) and not rel.startswith(FRONTEND_AUSGESCHLOSSEN)
    if teil == "backend":
        return not rel.startswith(BACKEND_AUSGESCHLOSSEN)
    raise ValueError(teil)


def dateien(wurzel, teil, nur_code=False):
    for ordner, unterordner, namen in os.walk(wurzel):
        unterordner[:] = [u for u in unterordner if u not in ("node_modules", ".git")]
        for n in namen:
            voll = os.path.join(ordner, n)
            rel = os.path.relpath(voll, wurzel).replace(os.sep, "/")
            if im_bereich(rel, teil, nur_code):
                yield rel


def kopieren(quelle, ziel, teil):
    """Legt eine Kopie nur mit den Dateien des Teils an (Pfade bleiben gleich)."""
    if os.path.exists(ziel):
        shutil.rmtree(ziel)
    anzahl = 0
    for rel in dateien(quelle, teil):
        z = os.path.join(ziel, rel)
        os.makedirs(os.path.dirname(z), exist_ok=True)
        shutil.copy2(os.path.join(quelle, rel), z)
        anzahl += 1
    return anzahl


if __name__ == "__main__":
    # Aufruf: python bereich.py <juice-shop-ordner> <frontend|backend> <zielordner>
    q, t, z = sys.argv[1:4]
    n = kopieren(q, z, t)
    code = sum(1 for _ in dateien(q, t, nur_code=True))
    print(f"{t}: {n} Dateien kopiert, davon {code} Code-Dateien")
