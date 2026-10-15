# Données

| Fichier | Contenu |
|---|---|
| `emails.jsonl` | 120 e-mails distincts, sous forme **extraite** (en-têtes, authentification, liens désamorcés, empreintes des pièces jointes, début du texte). Aucun `.eml` d'origine, aucune pièce jointe. |
| `reports.jsonl` | 362 signalements : qui (employé fictif), quel service, quand, quel e-mail. |
| `ground_truth.json` | Vérité terrain : malveillant / légitime / exercice, et campagne d'appartenance. Sert uniquement à l'évaluation. |
| `employees.json` | 115 employés fictifs. |

## Provenance

- E-mails `pp-*` : **vrais e-mails de phishing** du corpus
  [Phishing Pot](https://github.com/rf-peixoto/phishing_pot) (R. Peixoto),
  collectés par pots de miel et déjà anonymisés (`phishing@pot`). Licence
  **CC BY-NC 4.0** : ces données dérivées restent sous cette licence, usage
  non commercial, avec attribution.
- E-mails `syn-*` : légitimes et exercice, **écrits à la main**
  (`src/phishtriage/benign.py`), passés par le même analyseur.
- Employés et signalements : **fictifs**, tirés au hasard avec une graine fixe.

Régénérer : `python scripts/build_mailbox.py --corpus phishing_pot/email`
