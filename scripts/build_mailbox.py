#!/usr/bin/env python3
"""Construit la boîte « signalements » d'une semaine pour une organisation fictive.

- E-mails malveillants : de VRAIS e-mails de phishing (corpus Phishing Pot,
  rf-peixoto, CC BY-NC 4.0). On les lit, on n'ouvre jamais leurs liens.
- E-mails légitimes et exercices : écrits à la main (voir src/phishtriage/benign.py).
- Signalements : chaque e-mail reçu est signalé par 1 à 12 employés fictifs, à
  des moments réalistes de la semaine.

Ce qui est versionné dans le dépôt (data/) contient uniquement les éléments
extraits et les liens DÉSAMORCÉS (hxxp, [.]), jamais les .eml d'origine.

  git clone --depth 1 https://github.com/rf-peixoto/phishing_pot.git
  python scripts/build_mailbox.py --corpus phishing_pot/email
"""
from __future__ import annotations

import argparse
import json
import random
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from phishtriage.benign import EXERCISES, TEMPLATES, build_eml  # noqa: E402
from phishtriage.cluster import norm_subject  # noqa: E402
from phishtriage.parse import URL_RE, defang, parse_eml  # noqa: E402

FIRST = ["Camille", "Léa", "Hugo", "Nora", "Yanis", "Inès", "Lucas", "Sarah", "Adam", "Chloé",
         "Mehdi", "Emma", "Louis", "Amira", "Jules", "Lina", "Théo", "Manon", "Rayan", "Zoé"]
LAST = ["Martin", "Bernard", "Petit", "Durand", "Leroy", "Moreau", "Simon", "Laurent",
        "Benali", "Garcia", "Roux", "Fournier", "Haddad", "Girard", "Mercier", "Nguyen"]
DEPTS = [("Audit", 30), ("Conseil", 40), ("Finance", 15), ("RH", 8), ("IT", 10),
         ("Juridique", 7), ("Direction", 5)]
WEEK_START = datetime(2026, 11, 2, 8, 0, tzinfo=timezone.utc)   # lundi
N_CAMPAIGNS, PER_CAMPAIGN, N_SINGLE = 10, 4, 50


def employees(rng):
    out, i = [], 0
    for dept, n in DEPTS:
        for _ in range(n):
            i += 1
            fn, ln = rng.choice(FIRST), rng.choice(LAST)
            out.append({"id": f"u{i:03d}", "name": f"{fn} {ln}", "first_name": fn,
                        "department": dept})
    return out


def work_time(rng):
    return WEEK_START + timedelta(days=rng.randint(0, 4), hours=rng.uniform(0, 10))


def n_reporters(rng):
    return rng.choices([1, 2, 3, 5, 8, 12], weights=[40, 25, 15, 10, 7, 3])[0]


WWW_RE = re.compile(r"\bwww\.[\w.-]+", re.I)


def defang_text(s: str) -> str:
    s = URL_RE.sub(lambda m: defang(m.group(0)), s)
    return WWW_RE.sub(lambda m: defang(m.group(0)), s)


def store(e):
    """Version publiable : aucun lien cliquable nulle part."""
    e = dict(e)
    e["urls"] = [dict(u, url=defang(u["url"]), anchor=defang_text(u["anchor"]))
                 for u in e["urls"]]
    e["text"] = defang_text(e["text"])
    return e


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True, help="dossier phishing_pot/email")
    ap.add_argument("--pool", type=int, default=3000, help="e-mails du corpus examinés")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    files = sorted(Path(args.corpus).glob("*.eml"), key=lambda p: p.name)
    pool = rng.sample(files, min(args.pool, len(files)))
    parsed = {}
    for f in pool:
        try:
            parsed[f.name] = parse_eml(f.read_bytes())
        except Exception:
            continue
    # Les pièces jointes dangereuses sont rares dans le corpus : on les cherche
    # dans tout le corpus pour que la procédure « malware » soit représentée.
    risky_re = re.compile(rb'filename="?[^"\r\n]*\.(html?|shtml|zip|rar|iso|img|svg|exe|js|'
                          rb'vbs|lnk|hta|docm|xlsm|one)"?', re.I)
    for f in files:
        if f.name not in parsed and risky_re.search(f.read_bytes()):
            try:
                parsed[f.name] = parse_eml(f.read_bytes())
            except Exception:
                pass
    print(f"{len(parsed)} e-mails du corpus lus")

    # Vérité terrain des campagnes : même objet EXACT (normalisé) ET même ensemble
    # de domaines de liens. Critère strict, différent de l'algorithme évalué.
    by_key = defaultdict(list)
    for name, e in parsed.items():
        key = (norm_subject(e["subject"]),
               tuple(sorted({u["domain"] for u in e["urls"] if u["domain"]})))
        if len(key[0]) >= 10:
            by_key[key].append(name)
    multi = [v for v in by_key.values() if len(v) >= 2]
    rng.shuffle(multi)
    chosen, truth_campaign = [], {}
    for ci, names in enumerate(sorted(multi, key=len, reverse=True)[:N_CAMPAIGNS]):
        for n in sorted(names)[:PER_CAMPAIGN]:
            chosen.append(n)
            truth_campaign[n] = f"camp-{ci:02d}"
    rest = [n for n in parsed if n not in truth_campaign]
    with_att = [n for n in rest if any(a["filename"].lower().endswith(
        (".html", ".htm", ".zip", ".shtml", ".svg", ".iso", ".rar")) for a in parsed[n]["attachments"])]
    print(f"{len(with_att)} e-mails avec pièce jointe à risque dans le lot examiné")
    singles = with_att[:5] + rng.sample([n for n in rest if n not in with_att], N_SINGLE)
    chosen += singles

    emp = employees(rng)
    emails, reports, truth = {}, [], {}

    def deliver(eid, e, label, campaign, k):
        emails[eid] = store(e)
        truth[eid] = {"label": label, "campaign": campaign}
        t0 = work_time(rng)
        for p in rng.sample(emp, k):
            reports.append({"email_id": eid, "reporter": p["id"], "name": p["first_name"],
                            "department": p["department"],
                            "reported_at": (t0 + timedelta(minutes=rng.expovariate(1 / 45)))
                            .isoformat(timespec="minutes")})

    for n in chosen:
        eid = "pp-" + n.removesuffix(".eml")
        deliver(eid, parsed[n], "malicious", truth_campaign.get(n, eid), n_reporters(rng))

    # Chaque message légitime revient 2 fois dans la semaine (notifications,
    # newsletters) ; l'exercice est envoyé une fois, à beaucoup de monde.
    j = 0
    for i, tpl in enumerate(TEMPLATES + EXERCISES):
        label = "exercise" if tpl in EXERCISES else "benign"
        for _ in range(1 if label == "exercise" else 2):
            e = parse_eml(build_eml(*tpl, work_time(rng)))
            k = rng.choice([9, 14]) if label == "exercise" else rng.choice([1, 1, 2])
            deliver(f"syn-{j:02d}", e, label, f"syn-t{i:02d}", k)
            j += 1

    reports.sort(key=lambda r: r["reported_at"])
    for i, r in enumerate(reports, 1):
        r["report_id"] = f"R{i:04d}"

    out = ROOT / "data"
    out.mkdir(exist_ok=True)
    with open(out / "emails.jsonl", "w", encoding="utf-8") as f:
        for eid in sorted(emails):
            f.write(json.dumps(dict(email_id=eid, **emails[eid]), ensure_ascii=False) + "\n")
    with open(out / "reports.jsonl", "w", encoding="utf-8") as f:
        for r in reports:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    (out / "ground_truth.json").write_text(json.dumps(truth, indent=1), encoding="utf-8")
    (out / "employees.json").write_text(json.dumps(emp, ensure_ascii=False, indent=1),
                                        encoding="utf-8")
    n_mal = sum(v["label"] == "malicious" for v in truth.values())
    print(f"{len(emails)} e-mails distincts ({n_mal} malveillants réels, "
          f"{len(emails) - n_mal} légitimes/exercices), {len(reports)} signalements, "
          f"{len(set(truth_campaign.values()))} campagnes multi-e-mails")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
