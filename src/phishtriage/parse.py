"""Lecture d'un e-mail signalé (.eml) et extraction des éléments utiles au triage.

Bibliothèque standard uniquement. Aucune URL n'est jamais ouverte : on lit le
texte, on n'interagit avec rien.
"""
from __future__ import annotations

import hashlib
import re
from email import message_from_bytes, policy
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
_MULTI_SUFFIX = {"co.uk", "com.br", "com.au", "co.jp", "com.mx", "co.za", "com.tr",
                 "org.uk", "gouv.fr", "co.in", "com.cn", "com.ar", "ac.uk"}


def registrable_domain(host: str) -> str:
    """Domaine « organisation » approximatif : mail.paypal.com -> paypal.com."""
    host = (host or "").lower().strip(".").split(":")[0]
    if not host or re.fullmatch(r"[\d.]+", host):
        return host
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">\"' ") if "@" in (addr or "") else ""


def defang(s: str) -> str:
    """Rend un indicateur non cliquable pour le partager sans risque."""
    return (s.replace("http://", "hxxp://").replace("https://", "hxxps://")
             .replace(".", "[.]"))


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self._href, self._text = [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), " ".join("".join(self._text).split())))
            self._href = None


def _text_of(part) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", "replace")


def _auth(msg) -> dict:
    raw = " ".join(str(v) for v in (msg.get_all("Authentication-Results") or []))
    raw += " " + " ".join(str(v) for v in (msg.get_all("Received-SPF") or [])[:1])
    out = {}
    for k in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{k}=(\w+)", raw, re.I)
        out[k] = m.group(1).lower() if m else "absent"
    if out["spf"] == "absent":
        m = re.match(r"\s*(\w+)", " ".join(str(v) for v in (msg.get_all("Received-SPF") or [])))
        if m:
            out["spf"] = m.group(1).lower()
    return out


def parse_eml(data: bytes, max_text: int = 3000) -> dict:
    msg = message_from_bytes(data, policy=policy.default)

    def h(name):
        try:
            return str(msg.get(name, "") or "")
        except Exception:
            return ""

    from_name, from_addr = (getaddresses([h("From")]) or [("", "")])[0]
    reply_to = (getaddresses([h("Reply-To")]) or [("", "")])[0][1]
    return_path = (getaddresses([h("Return-Path")]) or [("", "")])[0][1]
    try:
        date = parsedate_to_datetime(h("Date")).isoformat()
    except Exception:
        date = None

    texts, links, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        fname = part.get_filename()
        if part.get_content_disposition() == "attachment" or fname:
            payload = part.get_payload(decode=True) or b""
            attachments.append({"filename": fname or "(sans nom)", "content_type": ctype,
                                "size": len(payload),
                                "sha256": hashlib.sha256(payload).hexdigest()})
            continue
        if ctype == "text/html":
            html = _text_of(part)
            p = _Links()
            try:
                p.feed(html)
            except Exception:
                pass
            links += [(u, t) for u, t in p.links if u.lower().startswith("http")]
            texts.append(re.sub(r"<[^>]+>", " ", html))
        elif ctype == "text/plain":
            texts.append(_text_of(part))

    text = " ".join(" ".join(texts).split())
    seen = {u for u, _ in links}
    links += [(u, "") for u in URL_RE.findall(text) if u not in seen]
    urls = []
    for href, anchor in links[:200]:
        host = (urlparse(href).hostname or "").lower()
        urls.append({"url": href, "host": host, "domain": registrable_domain(host),
                     "anchor": anchor[:120]})

    return {
        "message_id": h("Message-ID").strip(),
        "date": date,
        "subject": " ".join(h("Subject").split())[:300],
        "from_name": " ".join((from_name or "").split())[:120],
        "from_addr": (from_addr or "").lower(),
        "from_domain": domain_of(from_addr),
        "reply_to": (reply_to or "").lower(),
        "return_path_domain": domain_of(return_path),
        "auth": _auth(msg),
        "urls": urls,
        "attachments": attachments,
        "text": text[:max_text],
        # Exercice de sensibilisation interne (campagne de phishing d'entraînement)
        "exercise": bool(h("X-Acme-Exercise")),
    }
