"""Signaux de triage, chacun avec son explication pour l'analyste.

Chaque signal dit *pourquoi* il s'allume. C'est le « contexte » qui manque
le plus aux analystes SOC selon Alahmadi et al. (USENIX Security 2022) :
un score seul ne permet pas de décider vite ; un score expliqué, si.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from .parse import registrable_domain

ORG_DOMAIN = "acme-conseil.fr"          # organisation fictive du labo

# Expéditeurs connus de l'organisation (interne + fournisseurs utilisés).
# Liste PRÉCISE de domaines exacts : une liste trop large deviendrait une porte
# d'entrée (cf. « The Exclusion Ratchet », arXiv:2608.31062).
KNOWN_SENDERS = {ORG_DOMAIN, "microsoft.com", "docusign.net", "slack.com",
                 "atlassian.net", "linkedin.com", "payfit.fr", "swile.co",
                 "welcometothejungle.com", "zoom.us", "service-public.fr"}

# Marques souvent usurpées -> domaines légitimes (registrables).
BRANDS = {
    "microsoft": {"microsoft.com", "office.com", "outlook.com", "live.com",
                  "microsoftonline.com", "office365.com", "sharepoint.com"},
    "office 365": {"microsoft.com", "office.com", "office365.com"},
    "outlook": {"microsoft.com", "outlook.com"},
    "paypal": {"paypal.com", "paypal.fr"},
    "amazon": {"amazon.com", "amazon.fr", "amazonses.com"},
    "apple": {"apple.com", "icloud.com"},
    "netflix": {"netflix.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dhl": {"dhl.com", "dhl.fr"},
    "chronopost": {"chronopost.fr"},
    "la poste": {"laposte.fr", "laposte.net"},
    "ledger": {"ledger.com"},
    "trust wallet": {"trustwallet.com"},
    "binance": {"binance.com"},
    "correios": {"correios.com.br"},
    "geico": {"geico.com"},
    "state farm": {"statefarm.com"},
    "ameli": {"ameli.fr", "assurance-maladie.fr"},
    "impots": {"impots.gouv.fr", "dgfip.finances.gouv.fr"},
    "wetransfer": {"wetransfer.com"},
    "linkedin": {"linkedin.com"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
}
FREEMAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com",
            "proton.me", "protonmail.com", "gmx.com", "mail.ru", "yandex.ru",
            "icloud.com", "live.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
              "rebrand.ly", "ow.ly", "rb.gy", "shorturl.at"}
# Hébergements gratuits / cloud souvent détournés pour héberger une fausse page
# ou envoyer depuis un locataire jetable. Légitimes en soi : c'est un indice.
ABUSABLE_HOSTING = {"onmicrosoft.com", "firebaseapp.com", "web.app", "run.app",
                    "googleapis.com", "amazonaws.com", "blogspot.com", "weebly.com",
                    "wixsite.com", "r2.dev", "pages.dev", "workers.dev", "glitch.me",
                    "ngrok.io", "ngrok-free.app", "000webhostapp.com", "netlify.app",
                    "vercel.app", "github.io", "sharepoint.com", "ipfs.io", "dweb.link",
                    "square.site", "godaddysites.com", "azurewebsites.net",
                    "windows.net", "herokuapp.com", "repl.co", "framer.app"}
RISKY_TLD = {"shop", "xyz", "top", "click", "online", "site", "live", "icu", "buzz",
             "cfd", "sbs", "rest", "store", "monster", "quest", "cyou", "bond", "lol",
             "work", "fun", "space", "website", "today", "life", "pw", "tk", "ml", "ga"}
RISKY_EXT = {".html", ".htm", ".shtml", ".svg", ".iso", ".img", ".vhd", ".zip", ".rar",
             ".7z", ".exe", ".scr", ".js", ".vbs", ".wsf", ".lnk", ".hta", ".bat",
             ".cmd", ".ps1", ".docm", ".xlsm", ".pptm", ".one", ".msi", ".jar"}

# Lexiques multilingues (FR, EN, DE, ES, PT, NL, IT) : les campagnes réelles du
# corpus sont rarement en une seule langue.
LEX = {
    "urgency": r"urgent|immédiat|immediate(ly)?|within 24 ?h|sous 24 ?h|dernier (avis|rappel)|"
               r"final (notice|warning)|expire[sd]?|expir|suspend|bloqu|désactiv|deactivat|"
               r"action (required|requise)|unusual|inhabituel|mandatory|obligatoire|"
               r"dringend|sofort|gesperrt|wichtig|urgente|inmediat|bloquead|"
               r"suspens|dringend|onmiddellijk|geblokkeerd|ends soon|last chance|"
               r"nur heute|only today|aujourd'hui seulement",
    "credential": r"password|mot de passe|sign[ -]?in|log[ -]?in|connexion|verify your|"
                  r"vérifie[rz]? votre|confirm(ez)? (your|votre)|identifiant|credentials|"
                  r"mailbox|boîte (mail|aux lettres)|quota|re-?activate|kennwort|passwort|"
                  r"bestätigen sie|anmelden|konto|contraseña|verifica|senha|confirme|"
                  r"wachtwoord|bevestig|account (verification|update|suspended)|"
                  r"update your (account|payment|billing)|seed phrase|recovery phrase|"
                  r"firmware update|wallet",
    "money": r"free spins?|freispiel|giros gratis|rodadas grátis|gratis spins|bonus|casino|"
             r"jackpot|winner|gagnant|gewinn|ganador|ganhador|winnaar|vincitore|lottery|"
             r"loterie|lotto|prize|prix|preis|prêmio|premio|you have been selected|"
             r"sie wurden ausgewählt|selecionado|seleccionado|geselecteerd|promo code|"
             r"deposit|einzahlung|depósito|storting|\$ ?\d|€ ?\d|\d ?€|reward|cadeau|"
             r"gutschein|voucher|gift card|carte cadeau|inheritance|héritage|investment|"
             r"crypto|airdrop|no deposit",
    "extortion": r"\bbitcoin\b.*\b(pay|payer|zahlen|pagar)|btc wallet|i (have )?hacked|"
                 r"j'ai piraté|webcam|video of you|vidéo de vous|your device was infected|"
                 r"48 hours to pay|ich habe ihr|hackeé|hackeei",
    "invoice": r"invoice|facture|payment (due|overdue)|paiement|remittance|wire transfer|"
               r"virement|bank details|\brib\b|rechnung|factura|fatura|overschrijving",
}


# Caractères invisibles insérés pour casser les filtres par mots-clés
# (« Amazo\u200dn », « V\U000e0139erify ») : invisibles pour l'humain,
# mais « amazon » n'est plus reconnu par une recherche naïve.
HIDDEN_RE = re.compile("[\u00ad\u034f\u180e\u200b-\u200f\u2060-\u2064\ufeff"
                       "\ufe00-\ufe0f\U000e0000-\U000e007f\U000e0100-\U000e01ef]")


def strip_hidden(s: str) -> str:
    return HIDDEN_RE.sub("", s or "")


@dataclass
class Signal:
    id: str
    weight: int
    why: str


@dataclass
class Assessment:
    score: int
    signals: list[Signal] = field(default_factory=list)
    lexicon: dict = field(default_factory=dict)

    def has(self, sid: str) -> bool:
        return any(s.id == sid for s in self.signals)


def is_known_sender(e: dict) -> bool:
    return registrable_domain(e["from_domain"]) in KNOWN_SENDERS


def _brand_in(text: str):
    t = text.lower()
    return [b for b in BRANDS if re.search(rf"\b{re.escape(b)}\b", t)]


def _lookalike(domain: str) -> str | None:
    """Domaine proche d'un domaine légitime (paypa1.com, acme-conseii.fr)."""
    if not domain:
        return None
    legit = {ORG_DOMAIN} | set().union(*BRANDS.values())
    if domain in legit or domain in ABUSABLE_HOSTING:
        return None
    base = domain.split(".")[0]
    for good in legit:
        g = good.split(".")[0]
        if len(g) >= 5 and (SequenceMatcher(None, base, g).ratio() >= 0.8
                            or (g in base and base != g)):
            return good
    return None


def assess(e: dict) -> Assessment:
    sig: list[Signal] = []
    hidden = len(HIDDEN_RE.findall(e["subject"] + e["from_name"]))
    if hidden:
        sig.append(Signal("hidden_characters", 20, f"{hidden} caractère(s) invisible(s) dans "
                                                   f"l'objet ou le nom : technique pour "
                                                   f"échapper aux filtres."))
    e = dict(e, subject=strip_hidden(e["subject"]), from_name=strip_hidden(e["from_name"]),
             text=strip_hidden(e["text"]))
    a = e["auth"]
    fdom = registrable_domain(e["from_domain"])
    text = f"{e['subject']} {e['text']}".lower()
    lex = {k: len(re.findall(v, text, re.I)) for k, v in LEX.items()}
    link_domains = {u["domain"] for u in e["urls"] if u["domain"]}

    if a["dmarc"] in {"fail", "none", "permerror", "temperror"} and a["spf"] not in {"pass"}:
        sig.append(Signal("auth_fail", 20, f"Expéditeur non authentifié : SPF={a['spf']}, "
                                           f"DKIM={a['dkim']}, DMARC={a['dmarc']}."))
    elif a["spf"] in {"fail", "softfail"} or a["dmarc"] == "fail":
        sig.append(Signal("auth_partial", 10, f"Authentification partielle : SPF={a['spf']}, "
                                              f"DMARC={a['dmarc']}."))

    if e["from_addr"] and "." not in e["from_domain"]:
        sig.append(Signal("malformed_sender", 15, f"Adresse d'expéditeur invalide "
                                                  f"({e['from_addr'][:40]})."))
    tld = fdom.rsplit(".", 1)[-1] if "." in fdom else ""
    if tld in RISKY_TLD:
        sig.append(Signal("risky_tld", 10, f"Domaine en .{tld}, extension très utilisée "
                                           f"par les campagnes jetables."))
    if fdom in FREEMAIL and _brand_in(e["from_name"] + " " + e["subject"]):
        sig.append(Signal("freemail_brand", 15, f"Une « entreprise » qui écrit depuis une "
                                                f"messagerie gratuite ({fdom})."))

    rdom = registrable_domain(e["reply_to"].rsplit("@", 1)[-1]) if e["reply_to"] else ""
    if rdom and rdom != fdom:
        extra = " (messagerie gratuite)" if rdom in FREEMAIL else ""
        sig.append(Signal("reply_to_mismatch", 15,
                          f"Les réponses partent vers {rdom}{extra}, pas vers {fdom}."))

    rp = registrable_domain(e["return_path_domain"])
    if rp and fdom and rp != fdom and not rp.endswith(("amazonses.com", "sendgrid.net",
                                                       "mailchimp.com", "mcsv.net")):
        sig.append(Signal("return_path_mismatch", 5,
                          f"Domaine d'envoi technique ({rp}) différent de l'expéditeur affiché."))

    brands = _brand_in(f"{e['from_name']} {e['subject']}")
    spoofed = [b for b in brands if fdom not in BRANDS[b]]
    if spoofed:
        sig.append(Signal("brand_impersonation", 20,
                          f"Se présente comme « {spoofed[0]} » mais écrit depuis {fdom or '?'}."))

    look = _lookalike(fdom) or next((_lookalike(d) for d in link_domains if _lookalike(d)), None)
    if look:
        sig.append(Signal("lookalike_domain", 20, f"Domaine qui imite {look}."))

    if ORG_DOMAIN not in fdom and re.search(r"\b(it support|it service|service it|helpdesk|help desk|"
                                            r"service informatique|support informatique|"
                                            r"ressources humaines|human resources|acme)\b",
                                            e["from_name"].lower()):
        sig.append(Signal("fake_internal", 15, "Se fait passer pour un service interne "
                                               "mais vient de l'extérieur."))

    mism = []
    for u in e["urls"]:
        anchor = u["anchor"].lower().replace("[.]", ".")   # texte éventuellement désamorcé
        m = re.search(r"([a-z0-9-]+\.)+[a-z]{2,}", anchor)
        if m and registrable_domain(m.group(0)) not in {u["domain"], ""} and "." in m.group(0):
            mism.append((m.group(0), u["domain"]))
    if mism:
        sig.append(Signal("link_text_mismatch", 15, f"Le lien affiche {mism[0][0]} mais mène "
                                                    f"vers {mism[0][1]}."))
    hosted = sorted(({fdom} | link_domains) & ABUSABLE_HOSTING)
    if hosted:
        sig.append(Signal("abusable_hosting", 10, f"Utilise un hébergement gratuit/cloud "
                                                  f"souvent détourné ({hosted[0]})."))
    if any(re.fullmatch(r"[\d.]+", u["host"]) for u in e["urls"]):
        sig.append(Signal("ip_url", 10, "Lien vers une adresse IP brute, sans nom de domaine."))
    if link_domains & SHORTENERS:
        sig.append(Signal("shortener", 5, "Lien raccourci qui masque la destination."))

    risky = [x["filename"] for x in e["attachments"]
             if any(x["filename"].lower().endswith(ext) for ext in RISKY_EXT)
             or re.search(r"\.(pdf|docx?|xlsx?)\.\w{2,4}$", x["filename"].lower())]
    if risky:
        sig.append(Signal("risky_attachment", 30, f"Pièce jointe à risque : {risky[0]}."))

    if lex["urgency"]:
        sig.append(Signal("urgency", 10, "Pression temporelle (urgence, suspension, expiration)."))
    if lex["credential"] and e["urls"]:
        sig.append(Signal("credential_lure", 15, "Demande de se connecter / vérifier un compte "
                                                 "via un lien."))
    if lex["extortion"] >= 2:
        sig.append(Signal("extortion", 25, "Vocabulaire de chantage / rançon."))
    if lex["money"] >= 1:
        sig.append(Signal("money_lure", 15 if lex["money"] >= 4 else 10,
                          "Promesse de gain (bonus, lot, crypto)."))

    score = min(100, sum(s.weight for s in sig))
    return Assessment(score=score, signals=sig, lexicon=lex)
