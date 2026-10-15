#!/usr/bin/env python3
"""Traite la boîte « signalements » et produit tickets, réponses et rapport.

  python scripts/run.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from phishtriage.classify import CATEGORIES  # noqa: E402
from phishtriage.pipeline import load, metrics, run  # noqa: E402
from phishtriage.reply import reply_for  # noqa: E402
from phishtriage.tickets import to_markdown  # noqa: E402


def main() -> int:
    emails, reports, truth = load(ROOT / "data")
    categories, groups, tickets, replies = run(emails, reports)
    m = metrics(emails, reports, truth, categories, groups, tickets)

    tdir = ROOT / "tickets"
    tdir.mkdir(exist_ok=True)
    for old in tdir.glob("TCK-*.md"):
        old.unlink()
    rows = ["# File de traitement", "",
            "Triée par priorité, puis par nombre de signaleurs.", "",
            "| Ticket | Priorité | Catégorie | Signaleurs | Statut | Objet |",
            "|---|---|---|---|---|---|"]
    for t in tickets:
        (tdir / f"{t.id}.md").write_text(to_markdown(t), encoding="utf-8")
        subj = (t.subjects[0] if t.subjects else "").replace("|", "/")[:60]
        rows.append(f"| [{t.id}]({t.id}.md) | {t.priority or '—'} | {CATEGORIES[t.category]} "
                    f"| {len(t.reporters)} | {t.status} | {subj} |")
    (tdir / "README.md").write_text("\n".join(rows) + "\n", encoding="utf-8")

    rdir = ROOT / "replies"
    rdir.mkdir(exist_ok=True)
    with open(rdir / "replies.jsonl", "w", encoding="utf-8") as f:
        for r in replies:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    ex = ["# Réponses aux signaleurs — exemples", "",
          "Une réponse part à **chaque** signaleur, quel que soit le verdict.", ""]
    for cat in ("credential_phishing", "suspicious", "benign", "exercise"):
        t = next((t for t in tickets if t.category == cat), None)
        if not t:
            continue
        sender = t.senders[0].split("@")[-1] if t.senders else ""
        ex += [f"## {CATEGORIES[cat]} ({t.id})", "", "**FR**", "", "```",
               reply_for(cat, t.reports[0]["name"], sender, len(t.reporters)), "```", "",
               "**EN**", "", "```",
               reply_for(cat, t.reports[0]["name"], sender, len(t.reporters), "en"), "```", ""]
    (rdir / "README.md").write_text("\n".join(ex), encoding="utf-8")

    (ROOT / "report").mkdir(exist_ok=True)
    (ROOT / "report" / "metrics.json").write_text(json.dumps(m, indent=1), encoding="utf-8")
    print(json.dumps(m, indent=1, ensure_ascii=False))
    print(f"\n{len(tickets)} tickets -> tickets/README.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
