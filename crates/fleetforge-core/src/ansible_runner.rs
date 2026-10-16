/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Lancement d'`ansible-playbook`.
//!
//! Le runner reproduisait à moitié `play.sh` : il appelait le
//! binaire en direct, sans leur `cwd` (tous leurs chemins sont relatifs) ni
//! `OBJC_DISABLE_INITIALIZE_FORK_SAFETY`, que `play.sh` pose et sans lequel
//! les workers forkés d'Ansible cassent sur macOS. [`AnsibleEnv`] réunit ce que
//! les wrappers apportent, en un seul endroit.

use crate::models::*;
use crate::parc::Parc;
use anyhow::Result;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

/// Ce que les wrappers shell apportent à `ansible-playbook`.
#[derive(Debug, Clone, Default)]
pub struct AnsibleEnv {
    /// Racine du dépôt Ansible — le `cwd` que supposent les wrappers.
    pub root: Option<PathBuf>,
    /// Chemin des rôles, exporté en `ANSIBLE_ROLES_PATH`.
    pub roles_path: Option<String>,
}

impl AnsibleEnv {
    pub fn at_root(root: Option<PathBuf>) -> Self {
        Self { root, roles_path: None }
    }

    pub fn with_roles(mut self, roles_path: impl Into<String>) -> Self {
        self.roles_path = Some(roles_path.into());
        self
    }

    fn apply(&self, cmd: &mut Command) {
        if let Some(root) = &self.root {
            if root.is_dir() {
                cmd.current_dir(root);
            }
        }
        if let Some(roles) = &self.roles_path {
            cmd.env("ANSIBLE_ROLES_PATH", roles);
        }
        // Sur macOS, les workers forkés d'Ansible meurent sans cette variable
        // dès qu'une bibliothèque Objective-C est chargée dans le parent.
        // `play.sh` la pose ; l'application l'oubliait.
        #[cfg(target_os = "macos")]
        cmd.env("OBJC_DISABLE_INITIALIZE_FORK_SAFETY", "YES");
    }
}

/// Check whether ansible-playbook is available in PATH.
pub fn check_ansible_installed() -> bool {
    Command::new("ansible-playbook")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Stream stdout+stderr line by line via `on_line`, return (combined_output, success).
fn execute_with_streaming<F>(mut cmd: Command, on_line: F) -> Result<(String, bool)>
where
    F: Fn(String) + Send + Sync + 'static,
{
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn()?;

    let on_line = Arc::new(on_line);
    let stdout_lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let stderr_lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let stdout_thread = child.stdout.take().map(|stdout| {
        let lines = stdout_lines.clone();
        let cb = on_line.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                cb(line.clone());
                lines.lock().unwrap().push(line);
            }
        })
    });

    let stderr_thread = child.stderr.take().map(|stderr| {
        let lines = stderr_lines.clone();
        let cb = on_line.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                cb(line.clone());
                lines.lock().unwrap().push(line);
            }
        })
    });

    let status = child.wait()?;
    if let Some(t) = stdout_thread {
        let _ = t.join();
    }
    if let Some(t) = stderr_thread {
        let _ = t.join();
    }

    let stdout = stdout_lines.lock().unwrap().join("\n");
    let stderr = stderr_lines.lock().unwrap().join("\n");
    let combined = if stderr.is_empty() {
        stdout
    } else {
        format!("{}\n--- STDERR ---\n{}", stdout, stderr)
    };

    Ok((combined, status.success()))
}

/// Un `-i` par fichier du parc — JAMAIS `-i a,b`, qu'Ansible lirait comme une
/// liste d'HÔTES et non de fichiers.
fn add_inventories(cmd: &mut Command, parc: &Parc) {
    for file in &parc.files {
        cmd.arg("-i").arg(file);
    }
}

fn failed_run(
    inventory_path: &str,
    roles: Vec<String>,
    hosts: Vec<String>,
    started_at: String,
    message: String,
) -> AnsibleRun {
    AnsibleRun {
        id: None,
        inventory: inventory_path.to_string(),
        roles,
        hosts,
        status: "failed".to_string(),
        output: message,
        started_at,
        finished_at: Some(chrono::Utc::now().to_rfc3339()),
    }
}

/// Execute an existing playbook file, streaming each output line via `on_line`.
pub fn run_existing_playbook_streaming<F>(
    playbook_path: &str,
    parc: &Parc,
    limit_hosts: Option<Vec<String>>,
    extra_vars: Option<HashMap<String, String>>,
    env: &AnsibleEnv,
    on_line: F,
) -> Result<AnsibleRun>
where
    F: Fn(String) + Send + Sync + 'static,
{
    let started_at = chrono::Utc::now().to_rfc3339();
    let playbook_name = Path::new(playbook_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(playbook_path)
        .to_string();
    let hosts_recorded = match &limit_hosts {
        Some(h) if !h.is_empty() => h.clone(),
        _ => vec!["all".to_string()],
    };

    let mut cmd = Command::new("ansible-playbook");
    env.apply(&mut cmd);
    add_inventories(&mut cmd, parc);
    cmd.arg(playbook_path);
    if let Some(ref hosts) = limit_hosts {
        if !hosts.is_empty() {
            cmd.arg("--limit").arg(hosts.join(","));
        }
    }
    if let Some(vars) = extra_vars {
        for (k, v) in vars {
            cmd.arg("-e").arg(format!("{}={}", k, v));
        }
    }

    let (combined, success) = match execute_with_streaming(cmd, on_line) {
        Ok(r) => r,
        Err(e) => {
            return Ok(failed_run(
                &parc.name,
                vec![playbook_name],
                hosts_recorded,
                started_at,
                format!("Failed to execute ansible-playbook: {e}"),
            ))
        }
    };

    Ok(AnsibleRun {
        id: None,
        inventory: parc.name.clone(),
        roles: vec![playbook_name],
        hosts: hosts_recorded,
        status: if success { "success" } else { "failed" }.to_string(),
        output: combined,
        started_at,
        finished_at: Some(chrono::Utc::now().to_rfc3339()),
    })
}

/// Compose a temporary playbook from a set of roles and run it, streaming output.
///
/// Le playbook temporaire est écrit à côté de `group_vars/` pour qu'Ansible les
/// résolve, et retiré quoi qu'il advienne.
pub fn run_playbook_streaming<F>(
    playbooks_path: &str,
    parc: &Parc,
    roles: &[String],
    hosts: &[String],
    extra_vars: Option<HashMap<String, String>>,
    env: &AnsibleEnv,
    on_line: F,
) -> Result<AnsibleRun>
where
    F: Fn(String) + Send + Sync + 'static,
{
    let started_at = chrono::Utc::now().to_rfc3339();
    let hosts_str = hosts.join(",");
    let roles_yaml: String = roles
        .iter()
        .map(|r| format!("    - {r}"))
        .collect::<Vec<_>>()
        .join("\n");
    let playbook_content =
        format!("---\n- hosts: {hosts_str}\n  become: yes\n  roles:\n{roles_yaml}\n");

    let temp_path = Path::new(playbooks_path).join(format!(
        "fleetforge_playbook_{}.yml",
        chrono::Utc::now().timestamp_millis()
    ));
    std::fs::write(&temp_path, &playbook_content)?;

    let mut cmd = Command::new("ansible-playbook");
    env.clone()
        .with_roles(format!("{playbooks_path}/roles"))
        .apply(&mut cmd);
    add_inventories(&mut cmd, parc);
    cmd.arg(&temp_path);
    if let Some(vars) = extra_vars {
        for (k, v) in vars {
            cmd.arg("-e").arg(format!("{}={}", k, v));
        }
    }

    let result = execute_with_streaming(cmd, on_line);
    let _ = std::fs::remove_file(&temp_path);

    let (combined, success) = match result {
        Ok(r) => r,
        Err(e) => {
            return Ok(failed_run(
                &parc.name,
                roles.to_vec(),
                hosts.to_vec(),
                started_at,
                format!("Failed to execute ansible-playbook: {e}"),
            ))
        }
    };

    Ok(AnsibleRun {
        id: None,
        inventory: parc.name.clone(),
        roles: roles.to_vec(),
        hosts: hosts.to_vec(),
        status: if success { "success" } else { "failed" }.to_string(),
        output: combined,
        started_at,
        finished_at: Some(chrono::Utc::now().to_rfc3339()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_parc_file_gets_its_own_inventory_flag() {
        let parc = Parc {
            name: "web3c".into(),
            organization: "web3c".into(),
            files: vec!["a/web3c_inventory.yml".into(), "a/web3c_oracle.yml".into()],
        };
        let mut cmd = Command::new("ansible-playbook");
        add_inventories(&mut cmd, &parc);
        let args: Vec<_> = cmd.get_args().map(|a| a.to_string_lossy().to_string()).collect();
        assert_eq!(args, vec!["-i", "a/web3c_inventory.yml", "-i", "a/web3c_oracle.yml"]);
        assert!(!args.iter().any(|a| a.contains(',')), "jamais de liste séparée par des virgules");
    }
}
