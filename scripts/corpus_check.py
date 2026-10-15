#!/usr/bin/env python3
"""Contrôle de sécurité à grande échelle : sur des milliers de VRAIS e-mails de
phishing, combien l'outil aurait-il classés « légitime » (et donc clos sans
humain) ? L'objectif est 0. Le reste se répartit entre catégories et file
« suspect ».

  python scripts/corpus_check.py --corpus phishing_pot/email --n 3000
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from phishtriage.classify import CATEGORIES, classify  # noqa: E402
from phishtriage.indicators import assess  # noqa: E402
from phishtriage.parse import parse_eml  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--n", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=2026)
    args = ap.parse_args()
    files = sorted(Path(args.corpus).glob("*.eml"), key=lambda p: p.name)
    files = random.Random(args.seed).sample(files, min(args.n, len(files)))
    cats, sig, errors = Counter(), Counter(), 0
    for f in files:
        try:
            e = parse_eml(f.read_bytes())
        except Exception:
            errors += 1
            continue
        a = assess(e)
        cats[classify(e, a)] += 1
        for s in a.signals:
            sig[s.id] += 1
    n = sum(cats.values())
    res = {"emails": n, "parse_errors": errors, "categories": dict(cats.most_common()),
           "auto_closed_as_legit": cats["benign"] + cats["exercise"],
           "signals": dict(sig.most_common())}
    out = ROOT / "report" / "corpus_check.json"
    out.write_text(json.dumps(res, indent=1), encoding="utf-8")
    print(f"{n} vrais e-mails de phishing analysés")
    for c, k in cats.most_common():
        print(f"  {CATEGORIES[c]:62} {k:5d}  ({100 * k / n:.1f} %)")
    print(f"Clos à tort comme légitimes : {res['auto_closed_as_legit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
