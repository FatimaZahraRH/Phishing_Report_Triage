"""E-mails LÉGITIMES signalés à tort, et e-mails d'exercice interne.

Aucun corpus public d'e-mails d'entreprise récents n'est disponible : ces
messages sont donc écrits à la main, pour représenter ce qu'une équipe SecOps
reçoit réellement dans sa boîte « signalements » (notifications d'outils
internes, fournisseurs connus, newsletters, exercices de sensibilisation).
Ils sont générés au format .eml puis passent par le MÊME analyseur que les
vrais e-mails de phishing : aucun traitement de faveur.
"""
from __future__ import annotations

import hashlib
from email.message import EmailMessage
from email.utils import format_datetime

ORG = "acme-conseil.fr"

# (expéditeur, nom affiché, objet, texte, liens [(url, texte)], dmarc, extra)
TEMPLATES = [
    (f"it-annonces@{ORG}", "Service informatique ACME", "Maintenance VPN samedi 8h-12h",
     "Bonjour, le VPN sera indisponible samedi de 8h à 12h pour une mise à jour. "
     "Aucune action n'est requise de votre part. L'équipe IT.", [], "pass", {}),
    (f"rh@{ORG}", "Ressources humaines ACME", "Entretiens annuels : calendrier",
     "Bonjour à toutes et à tous, les entretiens annuels auront lieu du 2 au 20 décembre. "
     "Votre manager vous proposera un créneau.",
     [(f"https://intranet.{ORG}/rh/entretiens", "Page intranet RH")], "pass", {}),
    ("no-reply@payfit.fr", "PayFit", "Votre bulletin de paie est disponible",
     "Votre bulletin de paie de novembre est disponible dans votre espace.",
     [("https://app.payfit.fr/payslips", "Voir mon bulletin")], "pass", {}),
    ("notifications@slack.com", "Slack", "Nouveaux messages dans #projet-alpha",
     "Vous avez 3 messages non lus dans #projet-alpha.",
     [("https://acme-conseil.slack.com/archives/C01", "Ouvrir Slack")], "pass", {}),
    ("dse@docusign.net", "Marie Leroy via DocuSign", "Contrat cadre à signer",
     "Marie Leroy vous a envoyé un document à signer : Contrat cadre 2027.",
     [("https://eu.docusign.net/Signing/?ti=abc", "Consulter le document")], "pass", {}),
    ("account-security-noreply@accountprotection.microsoft.com", "Microsoft",
     "Nouvelle connexion à votre compte",
     "Nous avons détecté une connexion depuis un nouvel appareil. Si c'était vous, "
     "vous pouvez ignorer ce message. Sinon, vérifiez votre activité récente.",
     [("https://account.microsoft.com/activity", "Vérifier l'activité")], "pass", {}),
    ("jira@acme-conseil.atlassian.net", "Jira", "[SEC-412] Ticket assigné",
     "Le ticket SEC-412 « Revue des droits d'accès » vous a été assigné.",
     [("https://acme-conseil.atlassian.net/browse/SEC-412", "SEC-412")], "pass", {}),
    ("no-reply@zoom.us", "Zoom", "Enregistrement de réunion disponible",
     "L'enregistrement de « Point hebdo SSI » est disponible pendant 30 jours.",
     [("https://zoom.us/rec/share/xyz", "Voir l'enregistrement")], "pass", {}),
    ("messages-noreply@linkedin.com", "LinkedIn", "Vous avez une nouvelle invitation",
     "Paul Martin souhaite rejoindre votre réseau.",
     [("https://www.linkedin.com/mynetwork/", "Voir l'invitation")], "pass", {}),
    ("no-reply@swile.co", "Swile", "Votre carte a été rechargée",
     "Vos titres-restaurant du mois ont été crédités.",
     [("https://app.swile.co", "Mon compte")], "pass", {}),
    (f"communication@{ORG}", "Communication ACME", "La lettre interne de novembre",
     "Au programme : nouveaux arrivants, bilan du séminaire, agenda du mois.",
     [(f"https://intranet.{ORG}/news/novembre", "Lire la lettre")], "pass", {}),
    (f"securite@{ORG}", "Équipe Sécurité ACME", "Rappel : verrouillez votre poste",
     "Petit rappel : pensez à verrouiller votre poste (Windows + L) dès que vous "
     "vous absentez.", [], "pass", {}),
]

# Exercices de sensibilisation : envoyés par l'équipe sécurité elle-même.
EXERCISES = [
    (f"exercices@{ORG}", "Planning ACME", "Mise à jour de votre planning",
     "Votre planning de la semaine a été modifié. Consultez-le ici.",
     [(f"https://formation.{ORG}/exercice/planning", "Consulter le planning")], "pass",
     {"X-Acme-Exercise": "awareness-2026-11"}),
]


def build_eml(sender, name, subject, text, links, dmarc, extra, when) -> bytes:
    m = EmailMessage()
    m["From"] = f"{name} <{sender}>"
    m["To"] = f"collaborateur@{ORG}"
    m["Subject"] = subject
    m["Date"] = format_datetime(when)
    mid = hashlib.sha1(f"{sender}|{subject}|{when.isoformat()}".encode()).hexdigest()[:12]
    m["Message-ID"] = f"<{mid}@{sender.split('@')[1]}>"
    dom = sender.split("@")[1]
    m["Authentication-Results"] = (f"mx.{ORG}; spf=pass smtp.mailfrom={dom}; "
                                   f"dkim=pass header.d={dom}; dmarc={dmarc} header.from={dom}")
    for k, v in extra.items():
        m[k] = v
    html = "<p>" + text + "</p>" + "".join(f'<p><a href="{u}">{t}</a></p>' for u, t in links)
    m.set_content(text + "\n" + "\n".join(u for u, _ in links))
    m.add_alternative(html, subtype="html")
    return bytes(m)
