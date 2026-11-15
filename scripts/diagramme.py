"""Diagramme für Kapitel 5 (Abschnitt 3.4, letzter Absatz).

Aufruf: python scripts/diagramme.py ergebnisse/kennzahlen.json ergebnisse/diagramme
"""
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from matplotlib.patches import Circle  # noqa: E402


def venn2(ax, nur_a, nur_b, beide, name_a, name_b):
    """Einfaches Mengendiagramm mit zwei Kreisen (Zahlen statt Flächen)."""
    for x, farbe in ((-0.5, FARBEN[0]), (0.5, FARBEN[2])):
        ax.add_patch(Circle((x, 0), 1.0, alpha=0.35, color=farbe, lw=0))
    for x, wert in ((-0.95, nur_a), (0, beide), (0.95, nur_b)):
        ax.text(x, 0, str(wert), ha="center", va="center", fontsize=13, fontweight="bold")
    ax.text(-0.6, -1.25, name_a, ha="center", fontsize=9)
    ax.text(0.6, -1.25, name_b, ha="center", fontsize=9)
    ax.set_xlim(-1.7, 1.7)
    ax.set_ylim(-1.5, 1.2)
    ax.set_aspect("equal")
    ax.axis("off")

plt.rcParams.update({"font.size": 10, "font.family": "DejaVu Serif", "axes.spines.top": False,
                     "axes.spines.right": False, "savefig.dpi": 200})
FARBEN = ["#1f4e79", "#7fa7d0", "#c55a11"]
NAME = {"semgrep": "Semgrep", "codeql": "CodeQL", "npm-audit": "npm audit", "trivy": "Trivy",
        "frontend": "Frontend", "backend": "Backend", "mit": "mit Build", "ohne": "ohne Build", "-": ""}


def bezeichnung(k):
    teile = [NAME[k["werkzeug"]], NAME[k["teil"]]]
    if k["variante"] != "-":
        teile.append(NAME[k["variante"]])
    return "\n".join(teile)


def balken(reihen, werte, titel, datei, ylabel="Wert", ylim=(0, 1.05), fehler=None):
    fig, ax = plt.subplots(figsize=(max(6, len(reihen) * 1.1), 4))
    n = len(werte)
    breite = 0.8 / n
    for i, (name, ys) in enumerate(werte.items()):
        xs = [j + (i - (n - 1) / 2) * breite for j in range(len(reihen))]
        ys_plot = [y if y is not None else 0 for y in ys]
        ax.bar(xs, ys_plot, breite, label=name, color=FARBEN[i % len(FARBEN)],
               yerr=fehler[i] if fehler else None, capsize=3 if fehler else 0)
        for x, y in zip(xs, ys):
            ax.text(x, (y or 0) + (ylim[1] if ylim else max(ys_plot or [1])) * 0.01,
                    "–" if y is None else (f"{y:.2f}" if ylim == (0, 1.05) else f"{y:.0f}"),
                    ha="center", va="bottom", fontsize=7)
    ax.set_xticks(range(len(reihen)))
    ax.set_xticklabels(reihen, fontsize=8)
    ax.set_ylabel(ylabel)
    if ylim:
        ax.set_ylim(*ylim)
    ax.set_title(titel)
    if n > 1:
        ax.legend(fontsize=8, frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.22), ncol=n)
    fig.tight_layout()
    fig.savefig(datei)
    plt.close(fig)
    print("geschrieben:", datei)


def main(quelle, ziel):
    with open(quelle, encoding="utf-8") as f:
        d = json.load(f)
    os.makedirs(ziel, exist_ok=True)
    kz = d["kennzahlen"]

    sast = [k for k in kz if k["werkzeug"] in ("semgrep", "codeql")]
    if sast:
        balken([bezeichnung(k) for k in sast],
               {"Precision (streng)": [k["precision_streng"] for k in sast],
                "Precision (geprüft)": [k.get("precision_geprueft") for k in sast],
                "Recall": [k["recall"] for k in sast]},
               "SAST: Precision und Recall", os.path.join(ziel, "sast_precision_recall.png"))
    sca = [k for k in kz if k["werkzeug"] in ("npm-audit", "trivy")]
    if sca:
        balken([bezeichnung(k) for k in sca],
               {"Precision": [k["precision_streng"] for k in sca], "Recall": [k["recall"] for k in sca]},
               "SCA: Precision und Recall", os.path.join(ziel, "sca_precision_recall.png"))

    gesamt = [z for z in d["laufzeiten"] if z["messgroesse"] == "gesamt"]
    if gesamt:
        med = [z["median_s"] for z in gesamt]
        fehler = [[m - z["min_s"] for m, z in zip(med, gesamt)], [z["max_s"] - m for m, z in zip(med, gesamt)]]
        balken([bezeichnung(z) for z in gesamt], {"Median": med}, "Laufzeit je Messreihe (Median, Spannweite)",
               os.path.join(ziel, "laufzeit.png"), ylabel="Sekunden", ylim=None, fehler=[fehler])

    if d["ueberschneidung"]:
        reihen = d["ueberschneidung"]
        fig, axes = plt.subplots(1, len(reihen), figsize=(3.2 * len(reihen), 3.2))
        axes = axes if len(reihen) > 1 else [axes]
        for ax, u in zip(axes, reihen):
            namen = [k[4:] for k in u if k.startswith("nur_")]
            a, b = (u[f"nur_{n}"] for n in namen)
            venn2(ax, a, b, u["beide"], NAME.get(namen[0], namen[0]), NAME.get(namen[1], namen[1]))
            titel = f"{u['werkzeugart']} {NAME[u['teil']]}" + (f", {NAME[u['variante']]}" if u["variante"] != "-" else "")
            ax.set_title(f"{titel}\nkeines: {u['keines']} von {u['referenz']}", fontsize=9)
        fig.tight_layout()
        fig.savefig(os.path.join(ziel, "ueberschneidung.png"))
        plt.close(fig)
        print("geschrieben:", os.path.join(ziel, "ueberschneidung.png"))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
