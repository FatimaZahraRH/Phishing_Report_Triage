"""Chaîne complète : signalements -> verdicts -> campagnes -> tickets -> réponses."""
from __future__ import annotations

import json
from itertools import combinations
from pathlib import Path

from .classify import MALICIOUS, classify
from .cluster import cluster
from .indicators import assess
from .reply import reply_for
from .tickets import build_tickets


def load(data_dir: Path):
    emails = {}
    for line in open(data_dir / "emails.jsonl", encoding="utf-8"):
        d = json.loads(line)
        emails[d.pop("email_id")] = d
    reports = [json.loads(x) for x in open(data_dir / "reports.jsonl", encoding="utf-8")]
    truth_p = data_dir / "ground_truth.json"
    truth = json.loads(truth_p.read_text()) if truth_p.exists() else {}
    return emails, reports, truth


def run(emails: dict, reports: list[dict]):
    categories = {eid: classify(e, assess(e)) for eid, e in emails.items()}
    groups = cluster(emails)
    tickets = build_tickets(groups, emails, categories, reports)
    replies = []
    for t in tickets:
        sender = t.senders[0] if t.senders else ""
        for r in t.reports:
            replies.append({"report_id": r["report_id"], "ticket": t.id,
                            "reporter": r["reporter"],
                            "text": reply_for(t.category, r["name"],
                                              sender.split("@")[-1], len(t.reporters))})
    return categories, groups, tickets, replies


def metrics(emails, reports, truth, categories, groups, tickets) -> dict:
    m = {"reports": len(reports), "emails": len(emails), "tickets": len(tickets)}
    m["reduction_pct"] = round(100 * (1 - len(tickets) / max(1, len(reports))), 1)
    m["auto_closed"] = sum(t.status != "ouvert" for t in tickets)
    m["queue_suspicious"] = sum(t.category == "suspicious" for t in tickets)
    m["queue_malicious"] = sum(t.category in MALICIOUS for t in tickets)
    m["by_priority"] = {p: sum(t.priority == p for t in tickets) for p in
                        ("P1", "P2", "P3", "P4")}
    m["by_category"] = {}
    for t in tickets:
        m["by_category"][t.category] = m["by_category"].get(t.category, 0) + 1

    if truth:
        lab = {eid: truth[eid]["label"] for eid in emails}
        m["malicious_auto_closed"] = sum(lab[e] == "malicious" and categories[e] in
                                         {"benign", "exercise"} for e in emails)
        m["malicious_to_human"] = sum(lab[e] == "malicious" and categories[e] == "suspicious"
                                      for e in emails)
        m["malicious_categorized"] = sum(lab[e] == "malicious" and categories[e] in MALICIOUS
                                         for e in emails)
        m["malicious_total"] = sum(v == "malicious" for v in lab.values())
        m["legit_total"] = sum(v != "malicious" for v in lab.values())
        m["legit_flagged_malicious"] = sum(lab[e] != "malicious" and categories[e] in MALICIOUS
                                           for e in emails)
        m["legit_to_human"] = sum(lab[e] != "malicious" and categories[e] == "suspicious"
                                  for e in emails)
        m["exercise_recognized"] = sum(lab[e] == "exercise" and categories[e] == "exercise"
                                       for e in emails)
        # Regroupement : précision / rappel par paires d'e-mails.
        pred = {e: i for i, g in enumerate(groups) for e in g}
        tp = fp = fn = 0
        for a, b in combinations(sorted(emails), 2):
            same_t = truth[a]["campaign"] == truth[b]["campaign"]
            same_p = pred[a] == pred[b]
            tp += same_t and same_p
            fp += same_p and not same_t
            fn += same_t and not same_p
        m["cluster_pairs"] = {"tp": tp, "fp": fp, "fn": fn,
                              "precision": round(tp / max(1, tp + fp), 3),
                              "recall": round(tp / max(1, tp + fn), 3)}
    mal = [t for t in tickets if t.category in MALICIOUS]
    m["avg_signals_explained"] = round(sum(len(t.signals) for t in mal) / max(1, len(mal)), 1)
    return m
