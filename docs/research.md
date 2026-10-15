# De la recherche aux choix de conception

Ce projet ne reproduit pas une étude : il applique leurs constats à un outil
de travail quotidien. Voici, pour chaque choix, l'étude qui le justifie.

## 1. L'employé est un capteur — Lain et al., IEEE S&P 2022

*Phishing in Organizations: Findings from a Large-Scale and Long-Term Study*,
D. Lain, K. Kostiainen, S. Čapkun (ETH Zurich). 14 733 employés, 15 mois.

Constats utilisés :
- Les signalements arrivent **vite** : environ 10 % en moins de 5 minutes,
  30 à 40 % en moins de 30 minutes. Ils ont révélé **252 vraies campagnes**.
- Pas de « fatigue du signalement » sur 15 mois, et un **retour positif**
  encourage à signaler davantage.
- La précision des signalements est d'environ **68 %** : un tiers ne sont pas
  du phishing. Il faut donc les trier efficacement.
- Une formation intégrée affichée après un clic n'a **pas** rendu les
  employés plus résistants, et a même été associée à **plus** de clics dans
  le groupe concerné.

Ce qu'en fait le projet :
- **Regroupement en campagnes** (`cluster.py`) : N signalements du même
  e-mail = un seul ticket, mais le nombre de signaleurs est conservé et fait
  **monter la priorité** (`tickets.py`, seuil `WIDE_CAMPAIGN = 5`).
- **Clôture automatique des faux signalements prouvés légitimes**, pour que le
  tiers « non phishing » n'occupe pas l'analyste.
- **Une réponse à chaque signaleur** (`reply.py`), toujours un remerciement,
  jamais de reproche, y compris pour un faux signalement ou un clic avoué.

## 2. Le contexte avant le score — Alahmadi et al., USENIX Security 2022

*99% False Positives: A Qualitative Study of SOC Analysts' Perspectives on
Security Alarms*, B. A. Alahmadi, L. Axon, I. Martinovic (Oxford).

Constats utilisés : les analystes sont submergés de fausses alertes, et ce
qui leur manque le plus pour décider vite, c'est le **contexte** ; ils
perdent confiance dans les outils qui donnent un verdict sans le justifier.

Ce qu'en fait le projet :
- Chaque signal (`indicators.py`) porte sa **phrase d'explication** :
  « Le lien affiche paypal.com mais mène vers … », « Les réponses partent vers
  une messagerie gratuite ». Le ticket liste ces phrases en tête.
- Un ticket regroupe tout ce qu'il faut pour agir : ampleur (signaleurs,
  services), indicateurs **désamorcés** prêts à bloquer, procédure.
- Une file « suspect » assumée : l'outil dit quand il ne sait pas, au lieu de
  produire un faux verdict.

## 3. Ne pas tout miser sur la formation — Ho et al., IEEE S&P 2025

*Understanding the Efficacy of Phishing Training in Practice*, G. Ho,
A. Mirian, E. Luo, K. Tong, E. Lee, L. Liu, C. A. Longhurst, C. Dameff,
S. Savage, G. M. Voelker (UC San Diego). 19 789 employés, 8 mois.

Constats utilisés : la formation intégrée ne réduit le taux d'échec que
d'environ 1,7 point ; la formation annuelle n'a aucun lien mesurable avec les
échecs.

Ce qu'en fait le projet :
- Les procédures (`playbooks.py`, `docs/playbook.md`) partent du principe que
  **quelqu'un a cliqué** : retirer le message des boîtes, bloquer les domaines,
  chercher dans les journaux proxy/DNS qui a visité les liens, réinitialiser.
- La sensibilisation passe par le **renforcement positif au moment du
  signalement** (exercices reconnus et félicités), plutôt que par une
  formation punitive après un clic.

## Autres choix

- **Preuve positive pour « légitime ».** Une liste d'expéditeurs connus,
  exacte et courte (`KNOWN_SENDERS`). Une liste trop large deviendrait une
  porte d'entrée, comme les exclusions trop larges des règles de détection
  (*The Exclusion Ratchet*, arXiv:2608.31062, déjà étudié dans
  [soc-detection-lab](https://github.com/FatimaZahraRH/soc-detection-lab)).
- **Caractères invisibles.** Des campagnes réelles du corpus insèrent des
  caractères sans largeur (« Amazo‍n ») pour casser les filtres par
  mots-clés. Ils sont détectés, puis retirés avant l'analyse, pour que la
  marque usurpée soit quand même reconnue.
- **Exercices internes.** L'en-tête d'exercice n'est cru que s'il vient d'un
  expéditeur interne authentifié : sinon, un attaquant n'aurait qu'à
  l'ajouter pour faire clore son e-mail.
