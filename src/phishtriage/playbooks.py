"""Procédures de traitement par catégorie (version courte, utilisée dans les tickets).

La version détaillée, avec le circuit complet, est dans docs/playbook.md.
"""

PLAYBOOKS = {
    "malware": [
        "Retirer le message de toutes les boîtes (recherche par expéditeur + SHA-256 de la pièce jointe).",
        "Bloquer le hash de la pièce jointe dans l'EDR et la passerelle mail.",
        "Analyser la pièce jointe en bac à sable (jamais sur un poste de travail).",
        "Contacter chaque destinataire : a-t-il ouvert la pièce jointe ? Si oui, isoler le poste.",
        "Escalader au SOC si une ouverture est confirmée (incident de sécurité).",
    ],
    "credential_phishing": [
        "Retirer le message de toutes les boîtes (recherche par objet + expéditeur).",
        "Bloquer les domaines des liens sur le proxy / filtrage DNS.",
        "Chercher dans les journaux proxy/DNS qui a visité ces domaines.",
        "Pour chaque visiteur : réinitialiser le mot de passe, révoquer les sessions, vérifier la MFA.",
        "Vérifier les connexions inhabituelles sur ces comptes (Entra ID / journaux de connexion).",
    ],
    "invoice_fraud": [
        "Prévenir immédiatement la Direction financière : aucun paiement ni changement de RIB.",
        "Vérifier par un canal connu (téléphone habituel) auprès du fournisseur supposé.",
        "Retirer le message des boîtes et bloquer l'expéditeur.",
        "Si un paiement est parti : contacter la banque sans délai (rappel de fonds).",
    ],
    "extortion": [
        "Rassurer le signaleur : ces messages sont presque toujours du bluff envoyé en masse.",
        "Ne pas payer, ne pas répondre. Retirer le message et bloquer l'expéditeur.",
        "Si un mot de passe réel est cité : le faire changer partout où il est utilisé.",
    ],
    "scam_spam": [
        "Bloquer l'expéditeur et les domaines des liens.",
        "Retirer le message des boîtes si la campagne est large.",
        "Clore le ticket : pas d'incident si personne n'a fourni d'informations.",
    ],
    "suspicious": [
        "Analyse manuelle : en-têtes complets, réputation des domaines, contenu.",
        "Décider : malveillant (appliquer la procédure correspondante) ou légitime (clore).",
        "Si légitime : répondre au signaleur en expliquant comment le reconnaître.",
    ],
    "benign": [
        "Clore le ticket : expéditeur connu et authentifié.",
        "Répondre au signaleur : le remercier et expliquer pourquoi le message est légitime.",
    ],
    "exercise": [
        "Comptabiliser le signalement dans les résultats de l'exercice en cours.",
        "Répondre au signaleur : bravo, c'était un exercice, et c'est le bon réflexe.",
    ],
}
