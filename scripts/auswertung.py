"""Auswertung der Scans (Abschnitt 3.4).

Liest die Rohdaten aller Durchläufe, überführt jeden Befund in das einheitliche
Schema (Tabelle 6), gleicht ihn mit den Referenzlisten ab und berechnet
TP, FP, FN, Precision, Recall, F1, Überschneidungen und Laufzeiten.

Aufruf:
  python scripts/auswertung.py --roh ergebnisse/roh --ziel ergebnisse
"""
import argparse
import csv
import hashlib
import json
import os
import random
import statistics
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
import bereich  # noqa: E402
from sca_referenzliste import pakete_aus_lockfile, semver, vergleich  # noqa: E402

WURZEL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAST = ("semgrep", "codeql")
SCA = ("npm-audit", "trivy")
TEILE = ("frontend", "backend")
HOCH = ("high", "critical")
ZEILEN_TOLERANZ = 2
STICHPROBE = 50
SEED = 42


def lade(pfad, standard=None):
    if not os.path.exists(pfad):
        return standard
    with open(pfad, encoding="utf-8") as f:
        return json.load(f)


def schwere(s):
    s = (s or "").strip().lower()
    return {"moderate": "medium", "error": "high", "warning": "medium", "note": "low", "info": "low"}.get(s, s)


def befund_id(*teile):
    return hashlib.sha1("|".join(str(t) for t in teile).encode()).hexdigest()[:12]


# ======================================================================= Einlesen
def lese_semgrep(ordner, teil):
    daten = lade(os.path.join(ordner, "semgrep.json"), {}) or {}
    out = []
    for r in daten.get("results", []):
        pfad = r.get("path", "")
        while pfad.startswith("./"):
            pfad = pfad[2:]
        out.append({"datei": pfad, "zeile": r.get("start", {}).get("line"),
                    "kennung": r.get("check_id"),
                    "schweregrad": schwere(r.get("extra", {}).get("severity")),
                    "nachricht": (r.get("extra", {}).get("message") or "")[:300]})
    return out


def lese_codeql(ordner, teil):
    daten = lade(os.path.join(ordner, "codeql.sarif"), {}) or {}
    out = []
    for run in daten.get("runs", []):
        regeln = {}
        for quelle in [run.get("tool", {}).get("driver", {})] + run.get("tool", {}).get("extensions", []):
            for regel in quelle.get("rules", []) or []:
                regeln[regel.get("id")] = regel
        for r in run.get("results", []):
            regel_id = r.get("ruleId") or (r.get("rule") or {}).get("id")
            regel = regeln.get(regel_id, {})
            sev = (regel.get("properties") or {}).get("security-severity")
            if sev is not None:
                try:
                    sev = float(sev)
                    sev = "critical" if sev >= 9 else "high" if sev >= 7 else "medium" if sev >= 4 else "low"
                except ValueError:
                    sev = None
            for loc in (r.get("locations") or [])[:1]:
                pl = loc.get("physicalLocation", {})
                out.append({"datei": pl.get("artifactLocation", {}).get("uri", ""),
                            "zeile": pl.get("region", {}).get("startLine"),
                            "kennung": regel_id,
                            "schweregrad": sev or schwere(r.get("level") or (regel.get("defaultConfiguration") or {}).get("level")),
                            "nachricht": ((r.get("message") or {}).get("text") or "")[:300]})
    return out


def lese_npm_audit(ordner, teil, lock):
    daten = lade(os.path.join(ordner, "npm-audit.json"), {}) or {}
    pakete_lock = (lock.get("packages") or {}) if lock else {}
    out = []
    for name, eintrag in (daten.get("vulnerabilities") or {}).items():
        versionen = sorted({(pakete_lock.get(n) or {}).get("version") for n in eintrag.get("nodes", [])} - {None})
        for via in eintrag.get("via", []):
            if not isinstance(via, dict) or "url" not in via:
                continue  # nur ein Verweis auf ein anderes Paket
            kennung = via["url"].rstrip("/").rsplit("/", 1)[-1]
            for v in versionen or ["?"]:
                out.append({"paket": via.get("name", name), "version": v, "kennung": kennung,
                            "schweregrad": schwere(via.get("severity")),
                            "nachricht": (via.get("title") or "")[:300]})
    return out


def lese_trivy(ordner, teil):
    daten = lade(os.path.join(ordner, "trivy.json"), {}) or {}
    out = []
    for res in daten.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            out.append({"paket": v.get("PkgName"), "version": v.get("InstalledVersion"),
                        "kennung": v.get("VulnerabilityID"), "schweregrad": schwere(v.get("Severity")),
                        "nachricht": (v.get("Title") or "")[:300]})
    return out


# ======================================================================= Hilfen
class Advisories:
    def __init__(self, index):
        self.index = index or {}
        self.alias = {}
        for ghsa, e in self.index.items():
            self.alias[ghsa] = ghsa
            for a in e.get("aliase", []):
                self.alias.setdefault(a, ghsa)

    def ghsa(self, kennung):
        return self.alias.get(kennung)

    def schwere(self, kennung, standard):
        g = self.ghsa(kennung)
        return self.index[g]["schweregrad"] if g else standard


def kennzahlen(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f1 = 2 * p * r / (p + r) if p and r else (0.0 if p is not None and r is not None else None)
    return p, r, f1


def runde(x, n=3):
    return None if x is None else round(x, n)


# ======================================================================= Hauptteil
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--roh", default=os.path.join(WURZEL, "ergebnisse", "roh"))
    ap.add_argument("--ziel", default=os.path.join(WURZEL, "ergebnisse"))
    ap.add_argument("--review", default=os.path.join(WURZEL, "review"))
    args = ap.parse_args()

    gt_sast = lade(os.path.join(WURZEL, "ground_truth", "sast.json"))
    gt_sca = lade(os.path.join(WURZEL, "ground_truth", "sca.json"))
    adv = Advisories(lade(os.path.join(WURZEL, "ground_truth", "advisory_index_npm.json"), {}))
    locks = {t: lade(os.path.join(WURZEL, "lockfiles", t, "package-lock.json"), {}) for t in TEILE}
    build_flag = {t: pakete_aus_lockfile(os.path.join(WURZEL, "lockfiles", t, "package-lock.json"))
                  if locks[t] else {} for t in TEILE}

    # ---- Läufe einsammeln
    laeufe = defaultdict(dict)   # (werkzeug, teil, variante) -> {lauf: ordner}
    for name in sorted(os.listdir(args.roh)):
        ordner = os.path.join(args.roh, name)
        meta = lade(os.path.join(ordner, "meta.json"))
        if not meta:
            continue
        laeufe[(meta["werkzeug"], meta["teil"], meta["variante"])][int(meta["lauf"])] = ordner

    def normalisiert(werkzeug, teil, variante, ordner):
        if werkzeug == "semgrep":
            roh = lese_semgrep(ordner, teil)
        elif werkzeug == "codeql":
            roh = lese_codeql(ordner, teil)
        elif werkzeug == "npm-audit":
            roh = lese_npm_audit(ordner, teil, locks[teil])
        else:
            roh = lese_trivy(ordner, teil)
        out, gesehen = [], set()
        for b in roh:
            b.update({"werkzeug": werkzeug, "teil": teil, "variante": variante})
            if werkzeug in SAST:
                if not b["datei"] or not bereich.im_bereich(b["datei"], teil, nur_code=True):
                    continue  # außerhalb des Untersuchungsbereichs
                schluessel = (b["datei"], b["zeile"], b["kennung"])
            else:
                b["schweregrad"] = adv.schwere(b["kennung"], b["schweregrad"])
                if b["schweregrad"] not in HOCH:
                    continue  # Regel 3: nur high/critical
                b["ghsa"] = adv.ghsa(b["kennung"]) or ""
                schluessel = (b["paket"], b["version"], b["ghsa"] or b["kennung"])
            if schluessel in gesehen:
                continue  # Regel 2: Mehrfachmeldungen nur einmal
            gesehen.add(schluessel)
            b["id"] = befund_id(werkzeug, teil, variante, *schluessel)
            out.append(b)
        return out

    alle_befunde, kennz, laufz, konsist = [], [], [], []
    gefunden = {}          # (werkzeug, teil, variante) -> set der gefundenen Referenz-Einträge
    ungeklaert = defaultdict(list)

    for (werkzeug, teil, variante), lauf_ordner in sorted(laeufe.items()):
        reihe = {"werkzeug": werkzeug, "teil": teil, "variante": variante}
        # Konsistenz über alle Läufe
        mengen = {n: {b["id"] for b in normalisiert(werkzeug, teil, variante, o)} for n, o in lauf_ordner.items()}
        erster = min(lauf_ordner)
        abweichend = [n for n, m in mengen.items() if m != mengen[erster]]
        konsist.append({**reihe, "laeufe": len(mengen), "identisch": "ja" if not abweichend else "nein",
                        "abweichende_laeufe": " ".join(map(str, abweichend)),
                        "befunde_je_lauf": " ".join(str(len(mengen[n])) for n in sorted(mengen))})

        # Laufzeiten
        zeiten = defaultdict(list)
        for n, o in lauf_ordner.items():
            for k, v in (lade(os.path.join(o, "zeit.json"), {}) or {}).items():
                if isinstance(v, (int, float)):
                    zeiten[k].append(v)
        for k, werte in sorted(zeiten.items()):
            laufz.append({**reihe, "messgroesse": k, "n": len(werte), "median_s": round(statistics.median(werte), 2),
                          "min_s": round(min(werte), 2), "max_s": round(max(werte), 2)})

        # Abgleich (Lauf 1)
        befunde = normalisiert(werkzeug, teil, variante, lauf_ordner[erster])
        if werkzeug in SAST:
            refs = [c for c in gt_sast["challenges"] if c["teil"] == teil]
            treffer = set()
            for b in befunde:
                passend = [c["challenge"] for c in refs
                           if c["datei"] == b["datei"] and b["zeile"] is not None
                           and any(abs(b["zeile"] - z) <= ZEILEN_TOLERANZ for z in c["verwundbare_zeilen"])]
                b["zuordnung"] = " ".join(passend)
                b["ergebnis"] = "TP" if passend else "FP"
                treffer.update(passend)
            gefunden[(werkzeug, teil, variante)] = treffer
            tp = sum(b["ergebnis"] == "TP" for b in befunde)
            fp = len(befunde) - tp
            fn_ch = len(refs) - len(treffer)
            precision = tp / len(befunde) if befunde else None
            recall = len(treffer) / len(refs) if refs else None
            f1 = 2 * precision * recall / (precision + recall) if precision and recall else 0.0
            kennz.append({**reihe, "befunde": len(befunde), "tp": tp, "fp": fp,
                          "referenz": len(refs), "gefunden": len(treffer), "fn": fn_ch,
                          "precision_streng": runde(precision), "recall": runde(recall), "f1_streng": runde(f1)})
        else:
            refs = [r for r in gt_sca["eintraege"] if r["teil"] == teil and (variante == "mit" or not r["nur_build"])]
            ref_index = defaultdict(list)
            for r in refs:
                ref_index[(r["paket"], r["version"])].append(r)
            treffer = set()
            for b in befunde:
                passend = [r for r in ref_index.get((b["paket"], b["version"]), [])
                           if b["kennung"] == r["ghsa"] or b["kennung"] in r["aliase"] or b.get("ghsa") == r["ghsa"]]
                b["zuordnung"] = " ".join(r["ghsa"] for r in passend)
                b["ergebnis"] = "TP" if passend else "FP"
                b["nur_build"] = build_flag[teil].get((b["paket"], b["version"]), "")
                treffer.update((r["paket"], r["version"], r["ghsa"]) for r in passend)
            gefunden[(werkzeug, teil, variante)] = treffer
            tp = sum(b["ergebnis"] == "TP" for b in befunde)
            fp = len(befunde) - tp
            fn = len(refs) - len(treffer)
            p = tp / (tp + fp) if tp + fp else None
            r_ = len(treffer) / len(refs) if refs else None
            f1 = 2 * p * r_ / (p + r_) if p and r_ else (0.0 if p is not None and r_ is not None else None)
            nur_build = sum(1 for b in befunde if b["nur_build"] is True)
            kennz.append({**reihe, "befunde": len(befunde), "tp": tp, "fp": fp,
                          "referenz": len(refs), "gefunden": len(treffer), "fn": fn,
                          "precision_streng": runde(p), "recall": runde(r_), "f1_streng": runde(f1),
                          "anteil_nur_build": runde(nur_build / len(befunde)) if befunde else None})
        for b in befunde:
            if b["ergebnis"] == "FP":
                ungeklaert[werkzeug].append(b)
        alle_befunde.extend(befunde)

    # ---- manuelle Prüfung (Prüflisten anlegen bzw. Bewertungen übernehmen)
    os.makedirs(args.review, exist_ok=True)
    bewertung = {}
    for art in ("sast", "sca"):
        pfad = os.path.join(args.review, f"pruefliste_{art}.csv")
        alt = {}
        if os.path.exists(pfad):
            with open(pfad, encoding="utf-8-sig") as f:
                for z in csv.DictReader(f, delimiter=";"):
                    alt[z["id"]] = z
                    if (z.get("bewertung") or "").strip():
                        bewertung[z["id"]] = z["bewertung"].strip().lower()
        zeilen = []
        for werkzeug in (SAST if art == "sast" else SCA):
            kandidaten = sorted(ungeklaert.get(werkzeug, []), key=lambda b: b["id"])
            if art == "sast" and len(kandidaten) > STICHPROBE:
                kandidaten = sorted(random.Random(SEED).sample(kandidaten, STICHPROBE), key=lambda b: b["id"])
            for b in kandidaten:
                if art == "sast":
                    zeilen.append({"id": b["id"], "werkzeug": werkzeug, "teil": b["teil"], "datei": b["datei"],
                                   "zeile": b["zeile"], "regel": b["kennung"], "nachricht": b["nachricht"],
                                   "bewertung": (alt.get(b["id"]) or {}).get("bewertung", ""),
                                   "begruendung": (alt.get(b["id"]) or {}).get("begruendung", "")})
                else:
                    zeilen.append({"id": b["id"], "werkzeug": werkzeug, "teil": b["teil"], "variante": b["variante"],
                                   "paket": b["paket"], "version": b["version"], "kennung": b["kennung"],
                                   "nachricht": b["nachricht"],
                                   "bewertung": (alt.get(b["id"]) or {}).get("bewertung", ""),
                                   "begruendung": (alt.get(b["id"]) or {}).get("begruendung", "")})
        if zeilen:
            with open(pfad, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(zeilen[0].keys()), delimiter=";")
                w.writeheader()
                w.writerows(zeilen)

    # ---- geprüfte Precision (SAST) bzw. bestätigte Zusatzfunde (SCA)
    for werkzeug in SAST + SCA:
        geprueft = [b for b in ungeklaert.get(werkzeug, []) if b["id"] in bewertung]
        echt = [b for b in geprueft if bewertung[b["id"]].startswith("echt")]
        anteil = len(echt) / len(geprueft) if geprueft else None
        for k in kennz:
            if k["werkzeug"] != werkzeug:
                continue
            fp_reihe = [b for b in ungeklaert[werkzeug] if b["teil"] == k["teil"] and b["variante"] == k["variante"]]
            alle_geprueft = all(b["id"] in bewertung for b in fp_reihe)
            if werkzeug in SAST:
                if alle_geprueft:
                    zusatz = sum(bewertung[b["id"]].startswith("echt") for b in fp_reihe)
                elif anteil is not None:
                    zusatz = anteil * len(fp_reihe)   # Hochrechnung aus der Stichprobe
                else:
                    zusatz = None
                k["geprueft"] = len([b for b in fp_reihe if b["id"] in bewertung])
                k["echt_ausserhalb_referenz"] = runde(zusatz, 1)
                k["precision_geprueft"] = runde((k["tp"] + zusatz) / k["befunde"]) if zusatz is not None and k["befunde"] else None
            else:
                k["geprueft"] = len([b for b in fp_reihe if b["id"] in bewertung])
                k["echt_ausserhalb_referenz"] = sum(1 for b in fp_reihe if bewertung.get(b["id"], "").startswith("echt"))

    # ---- Überschneidung der Werkzeugpaare
    ueber = []
    for paar, varianten in ((SAST, ("-",)), (SCA, ("mit", "ohne"))):
        for teil in TEILE:
            for v in varianten:
                a, b = (gefunden.get((w, teil, v)) for w in paar)
                if a is None or b is None:
                    continue
                if paar == SAST:
                    alle = {c["challenge"] for c in gt_sast["challenges"] if c["teil"] == teil}
                else:
                    alle = {(r["paket"], r["version"], r["ghsa"]) for r in gt_sca["eintraege"]
                            if r["teil"] == teil and (v == "mit" or not r["nur_build"])}
                ueber.append({"werkzeugart": "SAST" if paar == SAST else "SCA", "teil": teil, "variante": v,
                              "referenz": len(alle), "beide": len(a & b), f"nur_{paar[0]}": len(a - b),
                              f"nur_{paar[1]}": len(b - a), "keines": len(alle - a - b)})

    # ---- schreiben
    os.makedirs(args.ziel, exist_ok=True)

    def schreibe(name, zeilen):
        if not zeilen:
            return
        felder = []
        for z in zeilen:
            felder += [k for k in z if k not in felder]
        with open(os.path.join(args.ziel, name), "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=felder, delimiter=";")
            w.writeheader()
            w.writerows(zeilen)

    schreibe("kennzahlen.csv", kennz)
    schreibe("laufzeiten.csv", laufz)
    schreibe("ueberschneidung.csv", ueber)
    schreibe("konsistenz.csv", konsist)
    schreibe("befunde_normalisiert.csv", alle_befunde)
    with open(os.path.join(args.ziel, "kennzahlen.json"), "w", encoding="utf-8") as f:
        json.dump({"kennzahlen": kennz, "laufzeiten": laufz, "ueberschneidung": ueber, "konsistenz": konsist},
                  f, indent=2, ensure_ascii=False)
    for k in kennz:
        print(f"{k['werkzeug']:9} {k['teil']:8} {k['variante']:4}  Befunde {k['befunde']:4}  TP {k['tp']:3}  "
              f"FP {k['fp']:4}  Ref {k['referenz']:3}  P {k['precision_streng']}  R {k['recall']}  F1 {k['f1_streng']}")


if __name__ == "__main__":
    main()
