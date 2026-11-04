# Avant ouverture au public

Points à traiter ou à revoir avant la mise en production ou la distribution.
Retirer ou dater un point une fois fait.

## Nœud Storj (ajouté le 04/11/2026)

- **Premier déploiement réel à observer** : `deploy-storj.yml` n'a été testé que par
  morceaux (validation, collecteur, règles) — jamais sur un hôte avec Docker.
  À jouer d'abord sur une machine de test : génération d'identité, `SETUP`, conteneur,
  tableau de bord, sonde svcprobe.
- **Sauvegarde hors du poste de contrôle** de `~/.config/fleetforge/storj/<hôte>/`
  (`identity/ca.key`, `identity/identity.key`) : le rôle ne les copie qu'en 0600 sur ce poste.
- **Paiements** : Storj paie en USDC sur Ethereum L1 depuis octobre 2026 (zkSync arrêté le
  01/09/2026, plus de STORJ). Seuil minimum par wallet lié aux frais L1 ; un résident UE ne
  peut pas utiliser une adresse de plateforme d'échange (MiCA). À relire sur storj.dev/node/payouts.
- **Watchtower** (`storj_watchtower`, activé par défaut) monte le socket Docker :
  décider de le garder ou de mettre à jour l'image à la main.
- **Redirection routeur 28967 TCP + UDP** si l'hôte est derrière un NAT (hors Ansible).
- **Règles d'alerte `storj`** non validées par `promtool` : vérifier le chargement
  sur la supervision après le premier déploiement (`count(storj_disk_used_bytes)`).
