/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Ce qu'on peut faire sur un élément, et pourquoi on ne le peut pas.
//!
//! Cette décision vivait en trois endroits : `HintContext::of` côté TUI, les
//! conditions JSX côté GUI (boutons masqués), et les refus tardifs de
//! `input.rs` (« aucun hôte ciblé »). Chacun pouvait annoncer une action que
//! l'autre refusait. Les trois frontaux lisent désormais ce catalogue.
//!
//! Le module ne connaît ni les hébergeurs ni le registre des rôles : il reçoit
//! des faits (`ActionContext`) et rend des actions. Une action INDISPONIBLE est
//! rendue avec sa raison plutôt que retirée — une entrée absente ne dit pas si
//! l'action n'existe pas ou si une condition manque.

use serde::{Deserialize, Serialize};

/// Nature de l'élément désigné.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Subject {
    /// Une machine : plusieurs entrées d'inventaire derrière une adresse.
    Machine,
    /// Une entrée d'inventaire.
    Host,
    /// Un service installé sur un hôte.
    Service,
    /// Un rôle du catalogue.
    Role,
    /// Un playbook du catalogue.
    Playbook,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionId {
    Start,
    Stop,
    Reboot,
    /// Choisir un rôle à déployer sur l'élément.
    DeployRole,
    /// Choisir un playbook à lancer, limité à l'élément.
    RunPlaybook,
    ExemptAlert,
    ViewHosts,
    ViewServices,
    ViewFindings,
    Remove,
    Purge,
    /// Rôle : choisir où le déployer.
    DeployOn,
    /// Playbook : le lancer.
    Run,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemAction {
    pub id: ActionId,
    pub label: String,
    /// Raccourci direct, quand il en existe un dans le TUI.
    pub key: Option<String>,
    /// À confirmer : coupe, supprime ou écrase quelque chose.
    pub destructive: bool,
    pub enabled: bool,
    /// Pourquoi l'action est indisponible. Toujours présent quand `enabled`
    /// est faux.
    pub reason: Option<String>,
}

/// Ce que l'hébergeur permet de piloter sur la machine désignée. `None` côté
/// contexte = machine non rapprochée d'une instance.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerState {
    pub can_start: bool,
    pub can_stop: bool,
    pub can_reboot: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionContext {
    pub power: Option<PowerState>,
    /// Le catalogue de rôles / de playbooks n'est pas vide.
    pub has_roles: bool,
    pub has_playbooks: bool,
    /// Constats rattachés à l'élément.
    pub findings: usize,
    /// Service : rôles `-remove` / `-purge` résolus par le catalogue.
    pub can_remove: bool,
    pub can_purge: bool,
    /// Rôle / playbook : hôtes que l'action viserait (sélection marquée, sinon
    /// aucun — le choix des cibles se fait alors dans l'action).
    pub marked: usize,
}

struct Builder(Vec<ItemAction>);

impl Builder {
    fn new() -> Builder {
        Builder(Vec::new())
    }

    fn add(&mut self, id: ActionId, label: &str, key: Option<&str>, destructive: bool) {
        self.0.push(ItemAction {
            id,
            label: label.to_string(),
            key: key.map(str::to_string),
            destructive,
            enabled: true,
            reason: None,
        });
    }

    /// Ajoute l'action, activée seulement si `ok`.
    fn gated(
        &mut self,
        id: ActionId,
        label: &str,
        key: Option<&str>,
        destructive: bool,
        ok: bool,
        reason: &str,
    ) {
        self.add(id, label, key, destructive);
        if !ok {
            let last = self.0.last_mut().expect("action venant d'être ajoutée");
            last.enabled = false;
            last.reason = Some(reason.to_string());
        }
    }
}

const NOT_RECONCILED: &str = "machine non rapprochée d'une instance — connecter son hébergeur";

/// Catalogue d'actions de `subject`, dans l'ordre où elles sont proposées.
pub fn actions_for(subject: Subject, ctx: &ActionContext) -> Vec<ItemAction> {
    let mut b = Builder::new();

    match subject {
        Subject::Machine | Subject::Host => {
            let power = ctx.power;
            b.gated(
                ActionId::Start,
                "Démarrer",
                Some("S"),
                false,
                power.is_some_and(|p| p.can_start),
                power.map_or(NOT_RECONCILED, |_| "déjà démarrée, ou non pilotable chez l'hébergeur"),
            );
            b.gated(
                ActionId::Stop,
                "Arrêter",
                Some("A"),
                true,
                power.is_some_and(|p| p.can_stop),
                power.map_or(NOT_RECONCILED, |_| "déjà arrêtée, ou non pilotable chez l'hébergeur"),
            );
            b.gated(
                ActionId::Reboot,
                "Redémarrer",
                Some("R"),
                true,
                power.is_some_and(|p| p.can_reboot),
                power.map_or(NOT_RECONCILED, |_| "non pilotable chez l'hébergeur"),
            );
            b.gated(
                ActionId::DeployRole,
                "Déployer un rôle…",
                Some("d"),
                true,
                ctx.has_roles,
                "aucun rôle dans le catalogue — renseigner le chemin des playbooks",
            );
            b.gated(
                ActionId::RunPlaybook,
                "Lancer un playbook…",
                Some("p"),
                true,
                ctx.has_playbooks,
                "aucun playbook dans le catalogue — renseigner le chemin des playbooks",
            );
            // Les exemptions portent sur une ENTRÉE d'inventaire (`alert_exclude`) :
            // sur une machine, il faudrait dire laquelle.
            b.gated(
                ActionId::ExemptAlert,
                "Exemptions d'alertes…",
                Some("e"),
                false,
                subject == Subject::Host,
                "porte sur une entrée d'inventaire — descendre dans les hôtes",
            );
            if subject == Subject::Machine {
                b.add(ActionId::ViewHosts, "Voir les hôtes", Some("↵"), false);
            } else {
                b.add(ActionId::ViewServices, "Voir les services", Some("↵"), false);
            }
            b.gated(
                ActionId::ViewFindings,
                "Voir les constats",
                None,
                false,
                ctx.findings > 0,
                "aucun constat sur cet élément",
            );
        }
        Subject::Service => {
            b.gated(
                ActionId::Remove,
                "Retirer (binaire + service)",
                Some("x"),
                true,
                ctx.can_remove,
                "pas de rôle -remove pour ce service",
            );
            b.gated(
                ActionId::Purge,
                "Purger (données + configuration)",
                Some("X"),
                true,
                ctx.can_purge,
                "pas de rôle -purge pour ce service",
            );
        }
        Subject::Role => {
            b.add(ActionId::DeployOn, "Déployer sur…", Some("d"), true);
        }
        Subject::Playbook => {
            b.add(ActionId::Run, "Lancer", Some("↵"), true);
        }
    }

    b.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ActionContext {
        ActionContext {
            has_roles: true,
            has_playbooks: true,
            ..Default::default()
        }
    }

    fn find(list: &[ItemAction], id: ActionId) -> &ItemAction {
        list.iter().find(|a| a.id == id).expect("action absente")
    }

    #[test]
    fn an_unreconciled_machine_keeps_power_actions_but_says_why() {
        let list = actions_for(Subject::Machine, &ctx());
        let start = find(&list, ActionId::Start);
        assert!(!start.enabled);
        assert!(start.reason.as_deref().unwrap().contains("rapprochée"));
    }

    #[test]
    fn power_follows_what_the_provider_allows() {
        let mut c = ctx();
        c.power = Some(PowerState { can_start: false, can_stop: true, can_reboot: true });
        let list = actions_for(Subject::Host, &c);
        assert!(!find(&list, ActionId::Start).enabled);
        assert!(find(&list, ActionId::Stop).enabled);
        assert!(find(&list, ActionId::Reboot).enabled);
    }

    #[test]
    fn every_disabled_action_carries_a_reason() {
        for subject in [Subject::Machine, Subject::Host, Subject::Service, Subject::Role, Subject::Playbook] {
            for a in actions_for(subject, &ActionContext::default()) {
                assert_eq!(a.enabled, a.reason.is_none(), "{:?} {:?}", subject, a.id);
            }
        }
    }

    #[test]
    fn exemptions_need_a_host_not_a_machine() {
        assert!(!find(&actions_for(Subject::Machine, &ctx()), ActionId::ExemptAlert).enabled);
        assert!(find(&actions_for(Subject::Host, &ctx()), ActionId::ExemptAlert).enabled);
    }

    #[test]
    fn a_service_without_purge_role_cannot_be_purged() {
        let mut c = ActionContext::default();
        c.can_remove = true;
        let list = actions_for(Subject::Service, &c);
        assert!(find(&list, ActionId::Remove).enabled);
        assert!(!find(&list, ActionId::Purge).enabled);
    }

    #[test]
    fn destructive_actions_are_flagged() {
        let list = actions_for(Subject::Machine, &ctx());
        assert!(find(&list, ActionId::Stop).destructive);
        assert!(!find(&list, ActionId::Start).destructive);
    }
}
