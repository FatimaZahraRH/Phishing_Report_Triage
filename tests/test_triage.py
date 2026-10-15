import sys
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishtriage.benign import build_eml  # noqa: E402
from phishtriage.classify import classify  # noqa: E402
from phishtriage.cluster import cluster  # noqa: E402
from phishtriage.indicators import assess  # noqa: E402
from phishtriage.parse import defang, parse_eml, registrable_domain  # noqa: E402
from phishtriage.pipeline import load, metrics, run  # noqa: E402
from phishtriage.reply import reply_for  # noqa: E402
from phishtriage.tickets import build_tickets  # noqa: E402

WHEN = datetime(2026, 11, 2, 9, 0, tzinfo=timezone.utc)


def mail(sender, name, subject, html, auth="spf=fail; dkim=none; dmarc=fail",
         reply_to=None, attachment=None, headers=None):
    m = EmailMessage()
    m["From"] = f"{name} <{sender}>"
    m["To"] = "collaborateur@acme-conseil.fr"
    m["Subject"] = subject
    m["Authentication-Results"] = f"mx; {auth}"
    if reply_to:
        m["Reply-To"] = reply_to
    for k, v in (headers or {}).items():
        m[k] = v
    m.set_content("texte")
    m.add_alternative(html, subtype="html")
    if attachment:
        m.add_attachment(b"contenu", maintype="application", subtype="octet-stream",
                         filename=attachment)
    return parse_eml(bytes(m))


def verdict(e):
    return classify(e, assess(e))


# --- Lecture ---------------------------------------------------------------

def test_parse_extracts_links_anchor_auth_and_attachment():
    e = mail("a@evil.example", "X", "Hello",
             '<a href="https://login.evil.example/x">www.paypal.com</a>',
             attachment="facture.pdf.html")
    assert e["auth"]["dmarc"] == "fail"
    assert e["urls"][0]["domain"] == "evil.example"
    assert e["urls"][0]["anchor"] == "www.paypal.com"
    assert e["attachments"][0]["filename"] == "facture.pdf.html"
    assert len(e["attachments"][0]["sha256"]) == 64


def test_defang_and_registrable_domain():
    assert defang("https://a.b.com/x") == "hxxps://a[.]b[.]com/x"
    assert registrable_domain("mail.paypal.com") == "paypal.com"
    assert registrable_domain("x.correios.com.br") == "correios.com.br"


# --- Verdicts : la règle de prudence --------------------------------------

def test_known_authenticated_sender_with_known_links_is_benign():
    e = parse_eml(build_eml("no-reply@payfit.fr", "PayFit", "Bulletin disponible",
                            "Votre bulletin est disponible.",
                            [("https://app.payfit.fr/p", "Voir")], "pass", {}, WHEN))
    assert verdict(e) == "benign"


def test_known_sender_linking_to_unknown_domain_goes_to_human_not_closed():
    # Compte fournisseur compromis : expéditeur connu, mais lien inconnu.
    e = parse_eml(build_eml("no-reply@payfit.fr", "PayFit", "Bulletin disponible",
                            "Votre bulletin est disponible.",
                            [("https://payfit-secure.example/login", "Voir")], "pass", {},
                            WHEN))
    assert verdict(e) == "suspicious"


def test_unknown_sender_with_no_signal_is_never_auto_closed():
    e = mail("bob@unknown.example", "Bob", "Bonjour", "<p>Salut</p>",
             auth="spf=pass; dkim=pass; dmarc=pass")
    assert verdict(e) not in {"benign", "exercise"}


def test_exercise_header_from_outside_is_not_trusted():
    e = mail("exercices@evil.example", "Planning", "Planning", "<p>x</p>",
             auth="spf=pass; dkim=pass; dmarc=pass",
             headers={"X-Acme-Exercise": "awareness"})
    assert verdict(e) != "exercise"


def test_real_internal_exercise_is_recognized():
    e = parse_eml(build_eml("exercices@acme-conseil.fr", "Planning", "Planning", "x",
                            [], "pass", {"X-Acme-Exercise": "awareness"}, WHEN))
    assert verdict(e) == "exercise"


# --- Signaux --------------------------------------------------------------

def test_lookalike_and_impersonation_give_credential_phishing():
    e = mail("security@paypa1.com", "PayPal", "Verify your account",
             '<a href="https://paypa1.com/login">Sign in</a> Please verify your account '
             'and confirm your password')
    a = assess(e)
    assert a.has("lookalike_domain")
    assert verdict(e) == "credential_phishing"


def test_hidden_characters_are_flagged_and_do_not_hide_the_brand():
    e = mail("billing@shop.example", "Amazo‍n Prim‍e", "Amazo‍n Prim‍e "
             "payment failed", '<a href="https://shop.example/a">Update</a>')
    a = assess(e)
    assert a.has("hidden_characters")
    assert a.has("brand_impersonation")


def test_double_extension_attachment_is_malware():
    e = mail("a@x.example", "Compta", "Facture", "<p>Ci-joint</p>",
             attachment="Facture_2026.pdf.exe")
    assert verdict(e) == "malware"


# --- Campagnes, tickets, réponses ----------------------------------------

def test_same_lure_from_rotating_senders_is_one_campaign():
    a = mail("x@s1.example", "Banque", "Votre compte est suspendu #123", "<p>a</p>")
    b = mail("y@s2.example", "Banque", "Votre compte est suspendu #987", "<p>b</p>")
    c = mail("z@s3.example", "Promo", "Gagnez un voyage", "<p>c</p>")
    groups = cluster({"a": a, "b": b, "c": c})
    assert sorted(map(sorted, groups)) == [["a", "b"], ["c"]]


def _reports(eid, n, dept="Conseil"):
    return [{"email_id": eid, "reporter": f"u{i}", "name": "Léa", "department": dept,
             "reported_at": f"2026-11-02T09:{i:02d}", "report_id": f"R{i}"}
            for i in range(n)]


def test_wide_campaign_raises_priority():
    e = mail("x@s1.example", "Promo", "Bonus casino", "<p>free spins bonus</p>")
    one = build_tickets([["e"]], {"e": e}, {"e": "scam_spam"}, _reports("e", 1))[0]
    many = build_tickets([["e"]], {"e": e}, {"e": "scam_spam"}, _reports("e", 6))[0]
    assert (one.priority, many.priority) == ("P4", "P3")


def test_invoice_fraud_reaching_finance_is_p1():
    e = mail("x@s1.example", "Fournisseur", "Facture", "<p>facture</p>")
    t = build_tickets([["e"]], {"e": e}, {"e": "invoice_fraud"},
                      _reports("e", 1, "Finance"))[0]
    assert t.priority == "P1"


def test_every_reply_thanks_the_reporter():
    for cat in ("credential_phishing", "suspicious", "benign", "exercise"):
        fr = reply_for(cat, "Léa", "payfit.fr", 3).lower()
        en = reply_for(cat, "Léa", "payfit.fr", 3, "en").lower()
        assert ("merci" in fr or "bravo" in fr) and ("thank" in en or "well done" in en)


# --- Garantie sur les données du dépôt -----------------------------------

def test_repo_data_no_real_phishing_closed_and_no_legit_flagged():
    emails, reports, truth = load(ROOT / "data")
    cats, groups, tickets, _ = run(emails, reports)
    m = metrics(emails, reports, truth, cats, groups, tickets)
    assert m["malicious_auto_closed"] == 0
    assert m["legit_flagged_malicious"] == 0
    assert m["tickets"] < m["reports"]
