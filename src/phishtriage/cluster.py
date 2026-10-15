"""Regroupe les e-mails signalés en CAMPAGNES : un dossier par attaque.

Quarante employés qui signalent le même e-mail ne doivent pas créer quarante
tickets. Lain et al. (IEEE S&P 2022) montrent que ces signalements multiples
sont précieux : ils mesurent l'ampleur d'une campagne et permettent de réagir
vite. On les fusionne donc, sans perdre l'information « combien et qui ».

Deux e-mails appartiennent à la même campagne s'ils partagent :
  - une pièce jointe identique (même SHA-256), ou
  - le même expéditeur (domaine) et un objet très proche, ou
  - un domaine de lien peu courant et un objet proche, ou
  - exactement le même objet (normalisé, assez long) : les campagnes changent
    souvent d'expéditeur mais gardent leur texte.
"""
from __future__ import annotations

import re
from difflib import SequenceMatcher

from .indicators import is_known_sender, strip_hidden
from .parse import registrable_domain

# Domaines présents partout (réseaux sociaux, CDN) : partager l'un d'eux ne
# prouve rien.
GENERIC_LINK_DOMAINS = {"facebook.com", "twitter.com", "x.com", "instagram.com",
                        "linkedin.com", "youtube.com", "google.com", "googleapis.com",
                        "microsoft.com", "apple.com", "t.co", "w3.org", "gstatic.com",
                        "cloudfront.net", "amazonaws.com", "sendgrid.net", "bit.ly"}


def norm_subject(s: str) -> str:
    s = strip_hidden(s).lower()
    s = re.sub(r"^((re|fw|fwd|tr|enc|aw|wg)\s*:\s*)+", "", s)
    s = re.sub(r"\S+@\S+", " ", s)          # adresse de la victime insérée dans l'objet
    s = re.sub(r"[#\d]+", " ", s)           # numéros de suivi, montants, références
    s = re.sub(r"[^\w\s]", " ", s)
    return " ".join(s.split())


def _link_domains(e: dict) -> set:
    return {u["domain"] for u in e["urls"] if u["domain"]} - GENERIC_LINK_DOMAINS


def _same_campaign(a: dict, b: dict) -> bool:
    if is_known_sender(a) != is_known_sender(b):
        return False
    ha = {x["sha256"] for x in a["attachments"] if x["size"]}
    if ha & {x["sha256"] for x in b["attachments"] if x["size"]}:
        return True
    sa, sb = norm_subject(a["subject"]), norm_subject(b["subject"])
    sim = SequenceMatcher(None, sa, sb).ratio() if sa and sb else 0.0
    if len(sa) >= 15 and sa == sb:
        return True
    da, db = registrable_domain(a["from_domain"]), registrable_domain(b["from_domain"])
    if da and da == db and "." in da and sim >= 0.8:
        return True
    if _link_domains(a) & _link_domains(b) and sim >= 0.6:
        return True
    return False


def cluster(emails: dict[str, dict]) -> list[list[str]]:
    """emails : {email_id: caractéristiques}. Renvoie des groupes d'email_id."""
    ids = sorted(emails)
    parent = {i: i for i in ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            if find(a) != find(b) and _same_campaign(emails[a], emails[b]):
                parent[find(b)] = find(a)
    groups: dict[str, list[str]] = {}
    for i in ids:
        groups.setdefault(find(i), []).append(i)
    return sorted(groups.values(), key=lambda g: g[0])
