"""Réponse au collaborateur qui a signalé un e-mail (FR / EN).

Toujours remercier, quel que soit le verdict. Un signalement de message
légitime n'est pas une erreur : c'est le bon réflexe. Lain et al. (IEEE S&P
2022) montrent que les signalements des employés détectent vite les vraies
campagnes ; décourager un signaleur, c'est perdre un capteur.
"""
from __future__ import annotations

FR = {
    "malicious": (
        "Bonjour {name},\n\nMerci pour votre signalement : vous avez bien fait. Ce message est "
        "{label_lower} et fait partie d'une campagne signalée par {n} personne(s). Nous le "
        "retirons de toutes les boîtes.\n\n"
        "Si vous avez cliqué sur un lien, saisi un mot de passe ou ouvert une pièce jointe, "
        "pas de panique, mais prévenez-nous tout de suite en répondant à ce message : plus on agit "
        "tôt, plus c'est simple.\n\nL'équipe Sécurité"),
    "suspicious": (
        "Bonjour {name},\n\nMerci pour votre signalement. Un analyste l'examine et revient vers "
        "vous rapidement. En attendant, ne cliquez sur aucun lien de ce message.\n\n"
        "L'équipe Sécurité"),
    "benign": (
        "Bonjour {name},\n\nMerci pour votre vigilance, c'est exactement le bon réflexe. Ce "
        "message est légitime : il vient bien de {sender}, et son authenticité a été vérifiée. "
        "Vous pouvez l'utiliser normalement.\n\nAu moindre doute, continuez à nous signaler "
        "les messages : nous préférons dix vérifications à un incident.\n\nL'équipe Sécurité"),
    "exercise": (
        "Bonjour {name},\n\nBravo ! Ce message faisait partie d'un exercice de sensibilisation, "
        "et vous l'avez repéré. Signaler, c'est le geste qui protège le plus l'entreprise.\n\n"
        "L'équipe Sécurité"),
}
EN = {
    "malicious": (
        "Hello {name},\n\nThank you for reporting this — you did the right thing. This message is "
        "{label_en} and is part of a campaign reported by {n} people. We are removing it "
        "from all mailboxes.\n\nIf you clicked a link, entered a password or opened an "
        "attachment, that's okay, but please tell us right away by replying to this email: "
        "the sooner we act, the easier it is.\n\nThe Security Team"),
    "suspicious": (
        "Hello {name},\n\nThank you for your report. An analyst is reviewing it and will get "
        "back to you shortly. In the meantime, please do not click any link in this message."
        "\n\nThe Security Team"),
    "benign": (
        "Hello {name},\n\nThank you for being vigilant — that's exactly the right reflex. This "
        "message is legitimate: it really comes from {sender}, and its authenticity was "
        "verified. You can use it normally.\n\nWhenever in doubt, keep reporting: we'd rather "
        "check ten emails than handle one incident.\n\nThe Security Team"),
    "exercise": (
        "Hello {name},\n\nWell done! This message was part of an awareness exercise, and you "
        "spotted it. Reporting is the single most protective thing you can do.\n\n"
        "The Security Team"),
}
LABEL_EN = {"malware": "malicious (dangerous attachment)",
            "credential_phishing": "a phishing attempt to steal your credentials",
            "invoice_fraud": "a payment fraud attempt", "extortion": "an extortion scam",
            "scam_spam": "a scam / spam"}
LABEL_FR = {"malware": "malveillant (pièce jointe dangereuse)",
            "credential_phishing": "une tentative de vol d'identifiants",
            "invoice_fraud": "une tentative de fraude au paiement",
            "extortion": "une tentative d'arnaque au chantage",
            "scam_spam": "une arnaque / un spam"}


def reply_for(category: str, name: str, sender: str, n_reporters: int,
              lang: str = "fr") -> str:
    kind = category if category in {"suspicious", "benign", "exercise"} else "malicious"
    tpl = (FR if lang == "fr" else EN)[kind]
    return tpl.format(name=name, sender=sender, n=n_reporters,
                      label_lower=LABEL_FR.get(category, ""),
                      label_en=LABEL_EN.get(category, ""))
