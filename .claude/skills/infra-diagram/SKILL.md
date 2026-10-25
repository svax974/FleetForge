---
name: infra-diagram
description: Documenter ou mettre à jour l'architecture d'un parc FleetForge (machines, services, flux réseau, supervision, sauvegardes, DNS) sous forme de document Markdown avec diagrammes Mermaid, en comparant ce que l'inventaire DÉCLARE à ce que les machines MONTRENT. À utiliser quand on demande un schéma d'infrastructure, une cartographie des flux, « qui parle à qui », un état des lieux d'un parc, ou la mise à jour d'un tel document après une migration.
---

# infra-diagram

Produit `Ansible/.private/docs/<parc>-infrastructure.md` : une description complète et PRÉCISE d'un
parc, avec des diagrammes Mermaid (rendus par GitHub et par la plupart des éditeurs Markdown).

Le principe qui fait la valeur du document : **deux sources, et l'écart entre elles**.
- **Déclaré** : l'inventaire, les `host_vars`, les rôles. Ce que le parc *devrait* être.
- **Observé** : ce que les machines montrent (ports en écoute, conteneurs, crons, DNS réel).
  Ce que le parc *est*.
Un schéma tiré du seul inventaire ment : ce parc a déjà eu un back « déployé » dont personne
n'écoutait le port, des alertes sur des séries inexistantes, une base copiée mais pas encore
supervisée. Chaque affirmation du document porte donc sa provenance.

## Où écrire (MANDATORY)

Le document contient des adresses, des ports et la topologie réelle : il va dans le dépôt
**PRIVÉ** du parc (`Ansible/.private/docs/`), jamais dans le dépôt public. Le skill et ses scripts,
eux, sont génériques et restent dans le dépôt public : ne jamais y écrire une IP ou un nom réel.
Ne jamais reproduire de secret, de mot de passe, de jeton, de clé, ni d'adresse e-mail
(« une boîte d'exploitation » suffit).

## Procédure

1. **Faits déclarés** (aucune connexion) :
   `python3 .claude/skills/infra-diagram/scripts/infra_facts.py <parc>` (`--format json` pour
   un traitement). Donne machines (une adresse = une machine), noms publics, règles de ports
   Docker, sauvegardes déclarées, vhosts, et une liste d'*incohérences d'inventaire* détectées.
2. **Faits observés** (lecture seule, facultatif mais c'est lui qui trouve les écarts) :
   `.claude/skills/infra-diagram/scripts/probe_fleet.sh <parc>`.
   - Si un SSH échoue, **ne pas contourner** : noter la machine « non vérifiée » et pourquoi
     (port, clé d'hôte inconnue, IP source non autorisée). Jamais `StrictHostKeyChecking=no`,
     jamais de modification d'un pare-feu pour se faire ouvrir l'accès.
   - Si TOUT échoue d'un coup, le poste a changé de réseau (VPN) : le dire et s'arrêter, ne pas
     produire un document « tout est injoignable ».
   - Compléter par le DNS réel (`dig +short <nom> @1.1.1.1`) et, pour la supervision, les
     répertoires `file_sd` de Prometheus : un job sans cible n'alerte jamais.
3. **Flux** : ils ne sont pas dans l'inventaire, il faut les lire dans les rôles. Sources de vérité,
   par couche :
   - accès entrant des services en conteneur → `host_vars/<hôte canonique>.yml`
     (`docker_ports_rules`) et rôle `docker-ports-security` (chaîne `DOCKER-USER`) ;
   - accès des services natifs → rôles `<famille>-security` (ufw) ; SSH → `security-ssh`
     (ufw **et** tcpwrappers `hosts.allow`/`hosts.deny`, deux couches indépendantes) ;
   - publication → `Ansible/parcs/<parc>/nginx/sites-enabled/*.conf` (amont, `allow`/`deny`) ;
   - clients applicatifs → les `.env` du service (noms d'hôtes et ports SEULEMENT, jamais les
     valeurs sensibles) ;
   - supervision → rôles `*-monitoring`, `prometheus.yml`, `file_sd`, groupes d'alertes ;
   - sauvegardes → rôles `*-backup-install` (`defaults/main.yml` : cron, intervalle, rétention,
     destination) et crons observés.
4. **Rédiger** avec la structure ci-dessous, puis relire chaque ligne : « d'où je tiens ça ? ».
5. **Valider les diagrammes** (voir « Mermaid ») avant de rendre la main.

## Structure du document

1. En-tête : parc, date de la dernière vérification, légende de provenance, machines non vérifiées.
2. Résumé : ce que fait le parc en cinq lignes, ses points uniques de défaillance.
3. Machines : adresse, entrées d'inventaire, hébergeur, services **observés**, ports non-loopback.
4. Diagramme d'ensemble (utilisateurs → DNS/CDN → proxies → services → données → SaaS externes).
5. Chaînes de données / flux applicatifs (un diagramme par chaîne métier).
6. Filtrage : par service, chaque couche (ufw, `DOCKER-USER`, nginx, tcpwrappers, TLS) et qui passe.
7. Supervision : jobs, cibles RÉELLES, règles d'alerte, destinataires, couverture et trous.
8. Sauvegardes : source, planning, rétention, destination, métrique de santé, procédure de restauration.
9. DNS et noms de service : nom → type → cible, proxifié ou non, qui le gère.
10. Environnements (prod / préprod / dev) en matrice.
11. **Écarts et risques**, classés par gravité, chacun avec la preuve et la correction proposée.
12. Mise à jour du document : renvoyer vers ce skill.

## Provenance (obligatoire sur chaque fait)

| Marque | Sens |
|---|---|
| ✔ | observé sur la machine ou dans le DNS à la date d'en-tête |
| ◻ | déclaré (inventaire / rôles), non observé |
| ✖ | écart : déclaré ≠ observé |
| ? | non vérifié (machine injoignable, information absente) |

## Mermaid

- `flowchart` (TB ou LR), un `subgraph` par MACHINE (pas par entrée d'inventaire), son adresse
  dans le titre. Plusieurs entrées sur la même adresse = un seul cadre.
- Flèche pleine = flux applicatif ; pointillée (`-.->`) = supervision ; tiretée épaisse (`==>`) =
  sauvegarde. Étiqueter **port / protocole / filtre** : `-->|"9744 TLS, ufw+nginx"|`.
- Libellés entre guillemets ; pas de `(` `)` `[` `]` `#` non guillemetés ; `<br/>` pour les retours à
  la ligne. Un nœud arrêté ou absent : style `classDef down stroke-dasharray:4 3,color:#999`.
- Un diagramme ≤ ~25 nœuds : au-delà, scinder par chaîne métier.
- Valider : `npx -y @mermaid-js/mermaid-cli -i doc.md -o /tmp/out.md` (rend chaque bloc, échoue sur une
  erreur de syntaxe). Sans réseau, relire les guillemets et les identifiants (pas d'espace, pas de
  mot réservé comme `end` en minuscules).

## Pièges propres à ce dépôt

- **Même adresse = même machine** : brk1, rpcbtc1, esplora1 et papangmetrics1 sont UN serveur ;
  proxy1, vpn1 et mail aussi. Ne pas dessiner trois serveurs.
- **`hostname` ≠ nom public** : `hostname` est l'identité machine (A), `proxy_hostname` le nom de
  service (CNAME vers le front des proxies, ou nom de service déplaçable comme celui de la base).
  Un `proxy_hostname` égal au front du parc est hérité des `group_vars`, pas un service.
- **Ports publiés par Docker** : ufw ne les filtre pas ; seul `DOCKER-USER` compte. Un `ufw status`
  « actif » ne prouve rien pour un conteneur.
- **tcpwrappers** : un SSH ouvert dans ufw peut quand même être coupé par `hosts.deny: sshd: ALL`.
- **Un job Prometheus sans cible n'est pas une alerte qui veille** : vérifier les `file_sd`.
- **Inventaire ≠ réalité** : un hôte déclaré peut n'avoir rien de déployé (aucune famille de rôles),
  une adresse peut être un gabarit (`xxx.xxx.xxx.xxx`), un service peut tourner sur une autre
  machine que celle de son entrée. Le signaler en écart, ne pas « corriger » le schéma pour que
  tout ait l'air cohérent.
- Un playbook de migration laisse des traces : anciennes entrées arrêtées mais encore servies par
  un vhost, destinations de sauvegarde sur la machine qu'on retire, cibles de supervision orphelines.

## Mise à jour d'un document existant

1. Lire le document et sa date de vérification.
2. Relancer les étapes 1 et 2 ; comparer avec le contenu du document, ligne par ligne.
3. Ne modifier que ce qui a changé : ne pas réécrire le texte stable (le diff doit rester lisible).
4. Mettre à jour la date, déplacer en « résolu » les écarts corrigés (avec la date et le commit),
   ajouter les nouveaux.
5. Après une migration, redessiner le diagramme concerné ET rechercher les traces listées ci-dessus.
6. Committer dans le dépôt privé du parc (`git -C Ansible/.private …`).
