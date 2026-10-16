/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Machines physiques — `custom`.
//!
//! Absent de la spec du prototype, alors qu'il figure dans la liste fermée des
//! `provider` et dans les inventaires : `hub`, `nuc`, `proxy2` et `station`
//! sont des machines de bureau derrière un NAT domestique.
//!
//! Il n'y a pas d'API : on ne peut ni les allumer ni les éteindre à distance.
//! Le déclarer explicitement vaut mieux que de les omettre — la vue Providers
//! les montre, avec leurs actions grisées et la raison affichée.

use crate::provider::*;
use async_trait::async_trait;
use fleetforge_core::model::ProviderKind;

#[derive(Default)]
pub struct CustomProvider;

impl CustomProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Provider for CustomProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Custom
    }

    /// Aucune capacité : ces machines n'ont pas d'API d'alimentation. Leur
    /// santé vient de Prometheus, pas d'un hébergeur.
    fn capabilities(&self) -> Capabilities {
        Capabilities::NONE
    }

    fn auth_methods(&self) -> Vec<AuthMethod> {
        Vec::new()
    }

    async fn connect(&mut self, _credentials: &Credentials) -> Result<()> {
        // Toujours « connecté » : il n'y a rien à quoi se connecter, et
        // renvoyer une erreur ferait apparaître comme en panne un parc qui va
        // parfaitement bien.
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    fn disconnect(&mut self) {}

    /// Ces machines n'existent que dans l'inventaire : c'est lui qui les
    /// énumère, pas un hébergeur.
    async fn list_instances(&self) -> Result<Vec<Instance>> {
        Ok(Vec::new())
    }

    async fn get_instance(&self, _reference: &InstanceRef) -> Result<Instance> {
        Err(ProviderError::Unsupported {
            provider: ProviderKind::Custom,
            action: "consultation d'instance",
        })
    }

    async fn power(&self, _reference: &InstanceRef, action: PowerAction) -> Result<()> {
        Err(ProviderError::Unsupported {
            provider: ProviderKind::Custom,
            action: action.label(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn power_actions_are_refused_with_a_readable_reason() {
        let p = CustomProvider::new();
        let r = InstanceRef {
            account: "default".into(),
            provider: ProviderKind::Custom,
            id: "hub".into(),
            zone: None,
            region: String::new(),
        };
        let err = p.power(&r, PowerAction::Start).await.unwrap_err();
        assert!(err.to_string().contains("démarrage"));
        assert!(err.to_string().contains("custom"));
    }

    #[test]
    fn a_physical_machine_is_never_reported_as_disconnected() {
        // Sinon tout un parc sain apparaîtrait en panne.
        assert!(CustomProvider::new().is_connected());
    }
}
