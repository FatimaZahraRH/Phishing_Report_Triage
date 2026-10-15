"""Transforme chaque campagne en un TICKET prêt à traiter.

Un ticket = ce qu'un analyste doit savoir pour décider en une minute :
quoi (catégorie), à quel point c'est urgent (priorité), pourquoi (signaux
expliqués), l'ampleur (combien d'employés, quels services), les indicateurs à
bloquer (désamorcés), et la procédure à suivre.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from .classify import CATEGORIES, MALICIOUS
from .indicators import assess, strip_hidden
from .parse import defang
from .playbooks import PLAYBOOKS

BASE_PRIORITY = {"malware": 1, "credential_phishing": 2, "invoice_fraud": 2,
                 "extortion": 3, "suspicious": 3, "scam_spam": 4}
SEVERITY = ["malware", "credential_phishing", "invoice_fraud", "extortion",
            "suspicious", "scam_spam", "exercise", "benign"]
WIDE_CAMPAIGN = 5  # nombre de signaleurs à partir duquel la priorité monte


@dataclass
class Ticket:
    id: str
    category: str
    priority: str | None
    status: str
    emails: list[str]
    reports: list[dict]
    score: int
    signals: list[tuple[str, str]]
    subjects: list[str]
    senders: list[str]
    urls: list[str]
    link_domains: list[str]
    attachments: list[dict]
    departments: dict = field(default_factory=dict)
    first_report: str = ""
    last_report: str = ""

    @property
    def reporters(self) -> list[str]:
        return sorted({r["reporter"] for r in self.reports})


def _category(cats: list[str]) -> str:
    """Catégorie d'une campagne = la plus grave parmi ses e-mails."""
    return min(cats, key=SEVERITY.index)


def _priority(cat: str, reports: list[dict]) -> str | None:
    if cat not in BASE_PRIORITY:
        return None
    p = BASE_PRIORITY[cat]
    if len({r["reporter"] for r in reports}) >= WIDE_CAMPAIGN:
        p -= 1        # campagne large : plus de personnes exposées
    if cat == "invoice_fraud" and any(r["department"] == "Finance" for r in reports):
        p = 1         # la cible a le pouvoir de payer
    return f"P{max(1, p)}"


def build_tickets(groups, emails, categories, reports) -> list[Ticket]:
    by_email: dict[str, list[dict]] = {}
    for r in reports:
        by_email.setdefault(r["email_id"], []).append(r)
    tickets = []
    for g in groups:
        reps = sorted((r for eid in g for r in by_email.get(eid, [])),
                      key=lambda r: r["reported_at"])
        if not reps:
            continue
        cat = _category([categories[eid] for eid in g])
        best = max(g, key=lambda eid: assess(emails[eid]).score)
        a = assess(emails[best])
        urls, doms, atts = [], Counter(), {}
        for eid in g:
            for u in emails[eid]["urls"]:
                if u["url"] not in urls:
                    urls.append(u["url"])
                if u["domain"]:
                    doms[u["domain"]] += 1
            for x in emails[eid]["attachments"]:
                atts[x["sha256"]] = x
        tickets.append(Ticket(
            id="", category=cat, priority=_priority(cat, reps),
            status="ouvert" if cat in MALICIOUS or cat == "suspicious" else "clos automatiquement",
            emails=g, reports=reps, score=a.score,
            signals=[(s.id, s.why) for s in a.signals],
            subjects=list(dict.fromkeys(strip_hidden(emails[e]["subject"]) for e in g))[:5],
            senders=list(dict.fromkeys(emails[e]["from_addr"] or "(vide)" for e in g))[:8],
            urls=urls[:15], link_domains=[d for d, _ in doms.most_common(10)],
            attachments=list(atts.values()),
            departments=dict(Counter(r["department"] for r in reps).most_common()),
            first_report=reps[0]["reported_at"], last_report=reps[-1]["reported_at"],
        ))
    order = {f"P{i}": i for i in range(1, 5)}
    tickets.sort(key=lambda t: (order.get(t.priority, 9), -len(t.reporters), t.first_report))
    for i, t in enumerate(tickets, 1):
        t.id = f"TCK-{i:04d}"
    return tickets


def _fmt(ts: str) -> str:
    return datetime.fromisoformat(ts).strftime("%d/%m %H:%M")


def to_markdown(t: Ticket) -> str:
    L = [f"# {t.id} — {CATEGORIES[t.category]}", "",
         f"| Priorité | Statut | Score | Signaleurs | Signalements | E-mails distincts |",
         f"|---|---|---|---|---|---|",
         f"| **{t.priority or '—'}** | {t.status} | {t.score}/100 | {len(t.reporters)} | "
         f"{len(t.reports)} | {len(t.emails)} |", "",
         f"**Premier signalement :** {_fmt(t.first_report)} — **dernier :** "
         f"{_fmt(t.last_report)}  ",
         "**Services touchés :** " + ", ".join(f"{d} ({n})" for d, n in t.departments.items()),
         "", "## Pourquoi ce verdict"]
    L += [f"- {why}" for _, why in t.signals] or ["- Aucun signal : expéditeur connu et "
                                                  "authentifié."]
    L += ["", "## Objet(s)"] + [f"- {s or '(vide)'}" for s in t.subjects]
    L += ["", "## Indicateurs (désamorcés, à bloquer / rechercher)",
          "Expéditeurs : " + ", ".join(f"`{defang(s)}`" for s in t.senders)]
    if t.link_domains:
        L.append("Domaines des liens : " + ", ".join(f"`{defang(d)}`" for d in t.link_domains))
    if t.urls:
        L.append("")
        L += [f"- `{u}`" for u in t.urls[:8]]
        if len(t.urls) > 8:
            L.append(f"- … {len(t.urls) - 8} autres")
    for x in t.attachments:
        L.append(f"Pièce jointe : `{x['filename']}` ({x['content_type']}, {x['size']} o) "
                 f"— SHA-256 `{x['sha256']}`")
    L += ["", "## Procédure"] + [f"{i}. {s}" for i, s in enumerate(PLAYBOOKS[t.category], 1)]
    L += ["", "## Signaleurs", ", ".join(r for r in t.reporters[:30])
          + (f" … (+{len(t.reporters) - 30})" if len(t.reporters) > 30 else "")]
    return "\n".join(L) + "\n"
