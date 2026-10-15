# Résultats

Commande : `python scripts/run.py` (métriques brutes : [`metrics.json`](metrics.json)).

## Jeu de données

Une semaine (2–6 novembre 2026) de la boîte « signalements » d'une
organisation fictive de 115 personnes (Audit, Conseil, Finance, RH, IT,
Juridique, Direction).

| | E-mails distincts | Signalements |
|---|---|---|
| Vrais e-mails de phishing (Phishing Pot) | 95 | 320 |
| E-mails légitimes signalés à tort (écrits à la main) | 24 | 33 |
| Exercice de sensibilisation interne | 1 | 9 |
| **Total** | **120** | **362** |

Les 95 e-mails réels comprennent 10 campagnes de 4 e-mails (même texte,
expéditeurs différents) et 55 e-mails isolés, dont 5 avec pièce jointe à
risque.

## 1. Charge de travail

| | |
|---|---|
| Signalements reçus | 362 |
| Tickets créés | **75** (−79 %) |
| Clos automatiquement (légitimes prouvés + exercice) | 13 tickets / 42 signalements |
| Tickets malveillants à traiter | 38 |
| Tickets « suspect » pour l'analyste | 24 |
| Répartition | P1 : 11 · P2 : 10 · P3 : 28 · P4 : 13 |

## 2. Sécurité du triage

| | |
|---|---|
| Vrais phishing clos à tort comme légitimes | **0 / 95** |
| Vrais phishing avec catégorie précise | 66 / 95 |
| Vrais phishing envoyés à l'analyste (« suspect ») | 29 / 95 |
| Légitimes classés malveillants | **0 / 24** |
| Légitimes envoyés à l'analyste | 0 / 24 |
| Exercice reconnu | 1 / 1 |

**Contrôle à grande échelle** (`scripts/corpus_check.py`, 2 998 vrais e-mails
de phishing) : **0** classé légitime. Arnaque/spam 37,8 % · hameçonnage
20,8 % · pièce jointe 0,1 % · fraude au paiement 0,1 % · suspect 41,2 %.

## 3. Regroupement en campagnes

Évalué par paires d'e-mails contre une vérité terrain **stricte** (même objet
exact ET mêmes domaines de liens) : précision **0,947**, rappel **1,000**
(72 vraies paires, 4 fusions en trop, 0 oubli).

Les 4 fusions en trop, vérifiées à la main :
- **3 e-mails** aux objets différents mais avec les **4 mêmes images** (même
  SHA-256) et le même domaine de lien : très probablement le **même acteur**
  avec plusieurs leurres. Fusion défendable.
- **2 e-mails** néerlandais au texte identique (« Bevestiging van
  verzending ») dont les domaines de liens changent : **même campagne** avec
  rotation de domaines, que la vérité terrain stricte sépare.

## 4. Contexte donné à l'analyste

En moyenne **3,5 signaux expliqués** par ticket malveillant. Signaux les plus
fréquents sur les 2 998 e-mails : authentification échouée, promesse de gain,
hébergement cloud détourné (`onmicrosoft.com`, `firebaseapp.com`…), urgence,
adresse d'expéditeur invalide, réponse détournée. **91 e-mails** utilisent des
caractères invisibles pour échapper aux filtres.

## Limites

Voir le [README](../README.md#limites-assumées) : légitimes écrits à la main,
signalements simulés, règles ajustées en lisant le corpus, pas de réputation
externe. La part de « suspect » (41 % sur le corpus) est le prix assumé de la
règle de prudence.
