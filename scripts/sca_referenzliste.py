"""Erstellt die Referenzliste für die SCA-Werkzeuge (Abschnitt 3.3.1).

Schritte:
  1. Pakete und Versionen aus den Dateien package-lock.json lesen
     (Frontend und Backend getrennt, Kennzeichen "nur Build-Abhängigkeit").
  2. Geprüfte (reviewed) Einträge der GitHub Advisory Database für npm lesen.
     Quelle ist das öffentliche Repository github/advisory-database zum
     Stichtag (Commit wird festgehalten).
  3. Ein Eintrag wird übernommen, wenn die installierte Version im
     betroffenen Versionsbereich liegt.
  4. Nur Schweregrad high oder critical.

Aufruf:
  python sca_referenzliste.py <advisory-database-ordner> <lockfiles-ordner> <ground_truth-ordner>
"""
import json
import os
import re
import sys

TEILE = ("frontend", "backend")


# ---------------------------------------------------------------- Semver
_SEMVER = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$")


def semver(v):
    m = _SEMVER.match(v.strip())
    if not m:
        return None
    a, b, c, pre = m.groups()
    pre_teile = tuple((0, int(x), "") if x.isdigit() else (1, 0, x) for x in pre.split(".")) if pre else None
    return (int(a), int(b or 0), int(c or 0), pre_teile)


def vergleich(x, y):
    """-1, 0, 1 nach den Regeln von SemVer 2.0 (Vorabversionen sind kleiner)."""
    if x[:3] != y[:3]:
        return -1 if x[:3] < y[:3] else 1
    px, py = x[3], y[3]
    if px == py:
        return 0
    if px is None:
        return 1
    if py is None:
        return -1
    return -1 if px < py else 1


def betroffen(version, affected):
    v = semver(version)
    if v is None:
        return False
    if version in (affected.get("versions") or []):
        return True
    for r in affected.get("ranges") or []:
        if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue
        ereignisse = []
        for e in r.get("events", []):
            (art, wert), = e.items()
            sv = (0, 0, 0, None) if (art == "introduced" and wert == "0") else semver(wert)
            if sv is not None:
                ereignisse.append((sv, art))
        # nach Version sortieren, bei Gleichstand introduced zuerst
        from functools import cmp_to_key
        ereignisse.sort(key=cmp_to_key(lambda a, b: vergleich(a[0], b[0]) or (-1 if a[1] == "introduced" else 1)))
        status = False
        for sv, art in ereignisse:
            c = vergleich(sv, v)
            if art == "introduced" and c <= 0:
                status = True
            elif art == "fixed" and c <= 0:
                status = False
            elif art == "last_affected" and c < 0:
                status = False
        if status:
            return True
    return False


# ---------------------------------------------------------------- Lockfiles
def pakete_aus_lockfile(pfad):
    """{(name, version): nur_build} aus package-lock.json (lockfileVersion 2/3)."""
    with open(pfad, encoding="utf-8") as f:
        lock = json.load(f)
    pakete = {}
    for schluessel, info in (lock.get("packages") or {}).items():
        if not schluessel or info.get("link") or "version" not in info:
            continue
        name = info.get("name") or schluessel.rsplit("node_modules/", 1)[-1]
        k = (name, info["version"])
        nur_build = bool(info.get("dev"))
        # nur Build-Abhängigkeit, wenn jede Fundstelle des Pakets dev ist
        pakete[k] = pakete.get(k, True) and nur_build
    return pakete


# ---------------------------------------------------------------- Advisory Database
def advisories_lesen(adb):
    basis = os.path.join(adb, "advisories", "github-reviewed")
    nach_paket, index = {}, {}
    for ordner, _, namen in os.walk(basis):
        for n in namen:
            if not n.endswith(".json"):
                continue
            with open(os.path.join(ordner, n), encoding="utf-8") as f:
                a = json.load(f)
            if a.get("withdrawn"):
                continue
            npm = [x for x in a.get("affected", []) if (x.get("package") or {}).get("ecosystem") == "npm"]
            if not npm:
                continue
            schwere = ((a.get("database_specific") or {}).get("severity") or "").lower()
            if schwere == "moderate":
                schwere = "medium"
            eintrag = {"ghsa": a["id"], "aliase": sorted(x for x in a.get("aliases", []) if x != a["id"]),
                       "schweregrad": schwere}
            index[a["id"]] = eintrag
            for x in npm:
                nach_paket.setdefault(x["package"]["name"], []).append((eintrag, x))
    return nach_paket, index


def main(adb, lockdir, ziel):
    nach_paket, index = advisories_lesen(adb)
    referenz, umfang = [], {}
    for teil in TEILE:
        pakete = pakete_aus_lockfile(os.path.join(lockdir, teil, "package-lock.json"))
        umfang[teil] = {
            "pakete_insgesamt": len(pakete),
            "davon_nur_build": sum(1 for b in pakete.values() if b),
        }
        gesehen = set()
        for (name, version), nur_build in sorted(pakete.items()):
            for eintrag, affected in nach_paket.get(name, []):
                if eintrag["schweregrad"] not in ("high", "critical"):
                    continue
                if not betroffen(version, affected):
                    continue
                k = (teil, name, version, eintrag["ghsa"])
                if k in gesehen:
                    continue
                gesehen.add(k)
                referenz.append({"teil": teil, "paket": name, "version": version, "nur_build": nur_build,
                                 "ghsa": eintrag["ghsa"], "aliase": eintrag["aliase"],
                                 "schweregrad": eintrag["schweregrad"]})
    os.makedirs(ziel, exist_ok=True)
    with open(os.path.join(ziel, "sca.json"), "w", encoding="utf-8") as f:
        json.dump({"beschreibung": "Referenzliste SCA: geprüfte Einträge der GitHub Advisory Database, "
                                   "Schweregrad high/critical",
                   "anzahl": len(referenz), "eintraege": referenz}, f, indent=2, ensure_ascii=False)
    with open(os.path.join(ziel, "advisory_index_npm.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False)
    with open(os.path.join(ziel, "umfang_pakete.json"), "w", encoding="utf-8") as f:
        json.dump(umfang, f, indent=2)
    for teil in TEILE:
        e = [r for r in referenz if r["teil"] == teil]
        print(f"{teil}: {umfang[teil]['pakete_insgesamt']} Pakete, {len(e)} Einträge "
              f"(davon nur Build: {sum(r['nur_build'] for r in e)})")


if __name__ == "__main__":
    main(*sys.argv[1:4])
