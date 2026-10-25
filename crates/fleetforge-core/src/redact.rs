/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Caviardage des sorties remises au compte d'automatisation (AgentHub).
//!
//! Ce qui sort vers AgentHub part chez le fournisseur d'un modèle. Même règle,
//! mêmes FORMES que la passerelle `ro-gate`
//! (`readonly-user-install/files/ro-gate.py`, `REDACTIONS`) : défense en
//! profondeur, PAS une garantie — un secret court, sans nom révélateur ni
//! préfixe connu, passe en clair. Le cas visé ici est surtout `--diff`, qui
//! montre le contenu des gabarits rendus (identifiants SMTP d'Alertmanager,
//! fichiers d'environnement) quand la tâche n'est pas en `no_log`.
//!
//! Les deux listes doivent évoluer ENSEMBLE : un motif ajouté d'un seul côté
//! laisse passer par l'autre ce que l'on croyait masqué.
//!
//! Un écart, assumé : la règle des chaînes opaques longues (`[REDACTED-BLOB]`)
//! épargne ce qui COMMENCE par `/`. Les messages d'erreur d'Ansible citent le
//! chemin absolu du fichier fautif (`/home/srvc/…/tasks/main.yml': line 3`),
//! qu'elle masquerait sinon — c'est l'information dont le diagnostic a besoin.
//! Contrepartie : une clé base64 qui commencerait elle-même par `/` (une sur
//! soixante-quatre) passerait.

use regex::{Captures, Regex};
use std::sync::OnceLock;

/// Noms de clés révélateurs (`password=`, `api_key:`…), comme `SECRET_KEY`.
const SECRET_KEY: &str = r"(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|auth(?:orization)?|credentials?|private[_-]?key|access[_-]?key|session[_-]?id|cookie|dsn)";

/// Nombre maximal de lignes écartées après un début de clé PEM sans fin.
const MAX_PEM_LINES: usize = 100;

fn rules() -> &'static [(Regex, &'static str)] {
    static RULES: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    RULES.get_or_init(|| {
        let key_value = format!(r#"(?i)({SECRET_KEY}[\w-]*["']?\s*[:=]\s*["']?)[^\s"',;&]+"#);
        [
            (r"(?i)\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{8,}", "${1} [REDACTED]"),
            (r"(://)[^/\s:@]+:[^/\s@]+@", "${1}[REDACTED]@"),
            (key_value.as_str(), "${1}[REDACTED]"),
            (
                r"\b(?:sk|nvapi|llmpt|ghp|gho|github_pat|xox[abprs])[-_][A-Za-z0-9_-]{16,}",
                "[REDACTED-KEY]",
            ),
            (r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED-KEY]"),
            (
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
                "[REDACTED-JWT]",
            ),
            (r"\b[A-Fa-f0-9]{32,}\b", "[REDACTED-HEX]"),
        ]
        .into_iter()
        .map(|(pattern, replacement)| {
            (Regex::new(pattern).expect("motif de caviardage valide"), replacement)
        })
        .collect()
    })
}

/// Chaînes opaques longues — appliquée en dernier, chemins absolus épargnés.
fn blob() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| Regex::new(r"[A-Za-z0-9+/_-]{40,}={0,2}").expect("motif de caviardage valide"))
}

fn pem_begin() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").expect("motif PEM"))
}

fn pem_end() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| Regex::new(r"-----END [A-Z ]*PRIVATE KEY-----").expect("motif PEM"))
}

/// Caviardeur ligne à ligne. Garde l'état d'un bloc de clé privée ouvert :
/// une clé PEM s'étale sur plusieurs lignes, toutes écartées.
#[derive(Debug, Default)]
pub struct Redactor {
    pem: usize,
}

impl Redactor {
    pub fn new() -> Self {
        Self::default()
    }

    /// La ligne caviardée, ou `None` si elle appartient à un bloc de clé.
    pub fn line(&mut self, line: &str) -> Option<String> {
        if pem_begin().is_match(line) {
            self.pem = MAX_PEM_LINES;
        }
        if self.pem > 0 {
            self.pem = if pem_end().is_match(line) { 0 } else { self.pem - 1 };
            return None;
        }
        let mut out = line.to_string();
        for (rx, replacement) in rules() {
            out = rx.replace_all(&out, *replacement).into_owned();
        }
        let out = blob().replace_all(&out, |caps: &Captures| {
            let found = &caps[0];
            if found.starts_with('/') {
                found.to_string()
            } else {
                "[REDACTED-BLOB]".to_string()
            }
        });
        Some(out.into_owned())
    }
}

/// Caviarde un texte de plusieurs lignes.
pub fn redact_text(text: &str) -> String {
    let mut redactor = Redactor::new();
    text.lines()
        .filter_map(|l| redactor.line(l))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(line: &str) -> String {
        Redactor::new().line(line).unwrap()
    }

    #[test]
    fn named_secrets_are_masked_but_their_name_stays() {
        assert_eq!(
            one("+  smtp_auth_password: 'hunter2'"),
            "+  smtp_auth_password: '[REDACTED]'"
        );
        assert_eq!(one("DB_PASSWORD=s3cr3t-value"), "DB_PASSWORD=[REDACTED]");
        assert_eq!(one("api_key: abc"), "api_key: [REDACTED]");
    }

    #[test]
    fn credentials_in_urls_and_headers_are_masked() {
        assert_eq!(
            one("url: https://user:pa55@example.org/x"),
            "url: https://[REDACTED]@example.org/x"
        );
        // `Authorization` est lui-même un nom révélateur : le mot qui suit est
        // masqué aussi, comme dans ro-gate.
        let header = one("Authorization: Bearer abcdefgh12345678");
        assert!(!header.contains("abcdefgh12345678"), "{header}");
        assert_eq!(one("curl -H 'Bearer abcdefgh12345678'"), "curl -H 'Bearer [REDACTED]'");
    }

    #[test]
    fn known_key_shapes_and_long_opaque_strings_are_masked() {
        assert!(one("key sk-abcdefghijklmnopqrstuv").contains("[REDACTED-KEY]"));
        assert!(one(&"a1".repeat(20)).contains("[REDACTED-HEX]"));
        assert!(one(&format!("x {}", "Xy9".repeat(15))).contains("[REDACTED-BLOB]"));
    }

    #[test]
    fn a_private_key_block_disappears_entirely() {
        let text = "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----\nafter";
        assert_eq!(redact_text(text), "before\nafter");
    }

    #[test]
    fn absolute_paths_survive_the_opaque_string_rule() {
        let line = "The error appears to be in '/home/srvc/fleetforge/Ansible/playbooks/roles/x/tasks/main.yml': line 3";
        assert_eq!(one(line), line);
        assert!(one("key ab/cdefghijklmnopqrstuvwxyz0123456789ABCDEFG").contains("[REDACTED-BLOB]"));
    }

    #[test]
    fn an_ordinary_ansible_line_is_left_alone() {
        let line = "TASK [fleetforge-install : Deploy the systemd unit] ***";
        assert_eq!(one(line), line);
        assert_eq!(one("ok: [proxy1]"), "ok: [proxy1]");
    }
}
