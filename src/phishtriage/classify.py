"""Catégorie de l'e-mail signalé : elle décide de la procédure à suivre.

La distinction compte en opérationnel : un spam se bloque et se clôt ; un vol
d'identifiants impose de vérifier qui a cliqué et de réinitialiser des comptes.

Règle de prudence : l'outil ne clôt JAMAIS un signalement sur une simple
absence d'indices. « Légitime » exige une preuve positive :
  - expéditeur connu de l'organisation ET authentifié (DMARC=pass),
  - tous les liens pointent vers des domaines connus,
  - pas de réponse détournée ni de pièce jointe à risque.
Un expéditeur connu qui ne remplit pas tout (compte fournisseur compromis ?)
part chez l'analyste, jamais en clôture automatique.
Tout le reste va soit dans une catégorie malveillante, soit dans la file
« suspect ». Un faux « légitime » laisserait une vraie attaque sans réponse.
"""
from __future__ import annotations

from .indicators import KNOWN_SENDERS, ORG_DOMAIN, Assessment, is_known_sender

CATEGORIES = {
    "malware": "Pièce jointe malveillante probable",
    "credential_phishing": "Hameçonnage (usurpation, vol d'identifiants ou de paiement)",
    "invoice_fraud": "Fraude au paiement / fausse facture",
    "extortion": "Chantage / extorsion",
    "scam_spam": "Arnaque ou spam (gains, casino, crypto)",
    "suspicious": "Suspect, à analyser par un humain",
    "benign": "Légitime (faux signalement)",
    "exercise": "Exercice de sensibilisation interne (bon réflexe !)",
}
MALICIOUS = {"malware", "credential_phishing", "invoice_fraud", "extortion", "scam_spam"}
LOW = 15     # sous ce score, rien de concret : l'analyste regarde (pas de clôture)
HIGH = 30    # à partir de ce score, on nomme une catégorie malveillante


def _trusted(e: dict, a: Assessment) -> bool:
    if not (is_known_sender(e) and e["auth"]["dmarc"] == "pass"):
        return False
    known = KNOWN_SENDERS | {ORG_DOMAIN}
    links_ok = all(u["domain"] in known for u in e["urls"] if u["domain"])
    return links_ok and not a.has("reply_to_mismatch")


def classify(e: dict, a: Assessment) -> str:
    lex = a.lexicon
    authenticated_known = is_known_sender(e) and e["auth"]["dmarc"] == "pass"
    # L'en-tête d'exercice seul ne suffit pas (un attaquant peut l'ajouter).
    if e.get("exercise") and authenticated_known:
        return "exercise"
    if a.has("risky_attachment"):
        return "malware"
    if _trusted(e, a):
        return "benign"
    if authenticated_known:
        return "suspicious"          # connu mais incohérent : un humain tranche
    if a.has("extortion"):
        return "extortion"
    impersonation = any(a.has(x) for x in ("brand_impersonation", "lookalike_domain",
                                           "fake_internal", "freemail_brand"))
    if a.has("credential_lure") and (impersonation or lex["credential"] >= 2) \
            and a.score >= LOW:
        return "credential_phishing"
    if impersonation and a.score >= HIGH:
        return "credential_phishing"
    if a.has("money_lure") and a.score >= LOW:
        return "scam_spam"
    if a.score < HIGH:
        return "suspicious"
    if lex["invoice"] >= 2:
        return "invoice_fraud"
    if a.has("credential_lure"):
        return "credential_phishing"
    return "suspicious"
