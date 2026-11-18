# Suivi du nœud Storj (`station`)

> Ouvert le 15/11/2026. Nœud déployé le 07/11/2026 sur `station` (parc web3c), 512 Go alloués.
> Signaux : séries `storj_*` de svcprobe (job `svcprobe`, hôte `station`), alertes du groupe `storj`,
> tableau de bord local `127.0.0.1:14002`.

## État au 15/11/2026 (VALIDÉ par lecture directe sur l'hôte)

- Conteneur up depuis 8 jours, 0 redémarrage, version 1.164.2 à jour.
- Ping satellite < 1 min, QUIC OK : la redirection routeur 28967 TCP+UDP fonctionne.
- 4 satellites, aucun disqualifié ni suspendu ; audit et suspension à 1 ; disponibilité 0,98 à 1.
- 48,9 Go utilisés + 9 Go de corbeille sur 512 Go ; sonde `service_up{service="storj"}` = 1.

## Reste à observer

| Point | Signal qui le valide | Condition de départ |
|---|---|---|
| Alertes chargées côté Prometheus | `count(storj_disk_used_bytes)` = 1 et `count(storj_satellite_audit_score)` = 4 sur `monitor` ; groupe `storj` présent dans `/api/v1/rules` | Aucune, à lire dès l'accès Prometheus |
| Fin du vetting | `storj_satellite_vetted` = 1 sur les 4 satellites | Environ 100 audits par satellite : attendu vers la mi-décembre 2026 |
| Disponibilité stable | `storj_satellite_online_score` ≥ 0,98 sur les 4 | Les 0,98 de saltlake/ap1 viennent du démarrage du 07/11 ; ne doivent plus baisser |
| Premier versement USDC | Réception sur le wallet de l'inventaire | Fin du mois suivant la première activité ; relire seuil et frais L1 sur storj.dev/node/payouts |
| Mise à jour automatique | `storj_up_to_date` = 1 après une nouvelle version ; image `:latest` + watchtower | Prochaine version publiée |

## Anomalies à signaler si vues

`storj_last_pinged_age_seconds` qui grimpe (redirection routeur ou IP publique changée),
`storj_satellite_audit_score` < 1 (pièces illisibles), `storj_disk_overused_bytes` > 0.
