/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Lecture de la sortie d'`ansible-playbook` : bilan par hôte (PLAY RECAP) et
//! tâches en échec.
//!
//! Analyse de la sortie du callback PAR DÉFAUT, et non un callback JSON : le
//! flux humain reste celui que lisent l'opérateur, le flux SSE et
//! `output_tail`, et rien ne change dans la façon de lancer Ansible. Les deux
//! formes d'erreur sont reconnues — `fatal: [h]: FAILED! => {…}` seule (Ansible
//! ≤ 2.18) ou précédée d'un bloc `[ERROR]: Task failed: …` (2.19 et suivants) —
//! ainsi qu'un `--check` (même sortie, tâches `skipping` en plus).
//!
//! Les messages rendus sont caviardés (`redact`) et bornés : ils partent chez
//! le fournisseur d'un modèle.

use crate::redact::redact_text;
use serde::Serialize;
use std::collections::BTreeMap;

/// Échecs rendus au plus.
pub const MAX_FAILURES: usize = 50;
/// Longueur maximale d'un message d'échec, en caractères.
pub const MAX_MSG_CHARS: usize = 500;

/// Bilan d'un hôte, ligne du PLAY RECAP.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct HostRecap {
    pub ok: u32,
    pub changed: u32,
    pub failed: u32,
    pub unreachable: u32,
    pub skipped: u32,
}

/// Une tâche en échec sur un hôte. `host` et `task` sont `None` pour une
/// erreur qui précède tout play (playbook illisible, variable de parc
/// absente) ; `role` l'est pour une tâche écrite dans le playbook même.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaskFailure {
    pub host: Option<String>,
    pub task: Option<String>,
    pub role: Option<String>,
    pub msg: String,
}

/// Ce que la sortie dit du run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RunReport {
    /// Vide tant que le PLAY RECAP n'est pas paru (run en cours, interrompu).
    pub recap: BTreeMap<String, HostRecap>,
    pub failures: Vec<TaskFailure>,
}

/// `TASK [rôle : nom]` → (rôle, nom). Le rôle n'est retenu que s'il a la forme
/// d'un nom de rôle : un nom de tâche peut lui-même contenir « : ».
fn task_header(line: &str) -> Option<(Option<String>, String)> {
    let rest = line
        .strip_prefix("TASK [")
        .or_else(|| line.strip_prefix("RUNNING HANDLER ["))?;
    let inner = &rest[..rest.rfind(']')?];
    if let Some((role, task)) = inner.split_once(" : ") {
        let role_like = !role.is_empty()
            && role.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c));
        if role_like {
            return Some((Some(role.to_string()), task.trim().to_string()));
        }
    }
    Some((None, inner.trim().to_string()))
}

/// `fatal: [h]: FAILED! => {…}`, `fatal: [h -> d]: UNREACHABLE! => {…}`,
/// `failed: [h] (item=x) => {…}` → (hôte, reste après `=>`).
fn failure_line(line: &str) -> Option<(String, String)> {
    let rest = line
        .strip_prefix("fatal: [")
        .or_else(|| line.strip_prefix("failed: ["))?;
    let close = rest.find(']')?;
    let host = rest[..close].split(" -> ").next().unwrap_or_default().trim().to_string();
    let after = &rest[close + 1..];
    let payload = after.split_once("=>").map(|(_, p)| p.trim()).unwrap_or_default();
    (!host.is_empty()).then(|| (host, payload.to_string()))
}

/// Le message d'un résultat d'échec : `msg`, complété de `stderr` quand il
/// l'éclaire (un `command` en échec dit seulement « non-zero return code »).
fn failure_message(payload: &str) -> String {
    let Ok(serde_json::Value::Object(result)) = serde_json::from_str::<serde_json::Value>(payload) else {
        return payload.to_string();
    };
    let text = |key: &str| {
        result
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
    };
    let detail = text("stderr").or_else(|| text("module_stderr"));
    match (text("msg"), detail) {
        (Some(msg), Some(detail)) if !msg.contains(&detail) => format!("{msg} — {detail}"),
        (Some(msg), _) => msg,
        (None, Some(detail)) => detail,
        (None, None) => text("stdout").or_else(|| text("reason")).unwrap_or_else(|| payload.to_string()),
    }
}

/// Caviarde puis borne un message à [`MAX_MSG_CHARS`] caractères.
fn bounded(message: &str) -> String {
    let one_line = message.split_whitespace().collect::<Vec<_>>().join(" ");
    let redacted = redact_text(&one_line);
    match redacted.char_indices().nth(MAX_MSG_CHARS) {
        Some((cut, _)) => format!("{}…", &redacted[..cut]),
        None => redacted,
    }
}

/// Ligne du PLAY RECAP : `h : ok=1 changed=0 unreachable=0 failed=0 skipped=2 …`.
fn recap_line(line: &str) -> Option<(String, HostRecap)> {
    let (host, counters) = line.split_once(" : ")?;
    let host = host.trim();
    if host.is_empty() || host.contains(char::is_whitespace) {
        return None;
    }
    let mut recap = HostRecap::default();
    let mut seen_ok = false;
    for pair in counters.split_whitespace() {
        let (key, value) = pair.split_once('=')?;
        let value: u32 = value.parse().ok()?;
        match key {
            "ok" => {
                recap.ok = value;
                seen_ok = true;
            }
            "changed" => recap.changed = value,
            "failed" => recap.failed = value,
            "unreachable" => recap.unreachable = value,
            "skipped" => recap.skipped = value,
            _ => {}
        }
    }
    seen_ok.then(|| (host.to_string(), recap))
}

/// Une erreur d'Ansible lui-même (pas d'une tâche) : `ERROR! …` (≤ 2.18) ou
/// `[ERROR]: …` qui n'est pas l'en-tête d'un échec de tâche (2.19+).
fn global_error(line: &str) -> Option<&str> {
    if let Some(rest) = line.strip_prefix("ERROR! ") {
        return Some(rest);
    }
    let rest = line.strip_prefix("[ERROR]: ")?;
    (!rest.starts_with("Task failed")).then_some(rest)
}

/// Analyse une sortie complète ou partielle, ligne par ligne.
pub fn parse<'a>(lines: impl IntoIterator<Item = &'a str>) -> RunReport {
    let mut report = RunReport::default();
    let mut role: Option<String> = None;
    let mut task: Option<String> = None;
    let mut in_recap = false;
    let mut global: Option<String> = None;

    for raw in lines {
        let line = raw.trim_end();
        if line.starts_with("PLAY RECAP") {
            in_recap = true;
            continue;
        }
        if in_recap {
            if let Some((host, recap)) = recap_line(line) {
                report.recap.insert(host, recap);
                continue;
            }
            if line.trim().is_empty() {
                continue;
            }
            in_recap = false;
        }
        if line.starts_with("PLAY [") {
            role = None;
            task = None;
            continue;
        }
        if let Some((r, t)) = task_header(line) {
            role = r;
            task = Some(t);
            continue;
        }
        if line.trim() == "...ignoring" {
            // L'échec qui précède était couvert par `ignore_errors` — tous ceux
            // de la même tâche sur le même hôte (une boucle en laisse un par
            // élément).
            if let Some(last) = report.failures.pop() {
                while report.failures.last().is_some_and(|f| f.host == last.host && f.task == last.task) {
                    report.failures.pop();
                }
            }
            continue;
        }
        if let Some((host, payload)) = failure_line(line) {
            report.failures.push(TaskFailure {
                host: Some(host),
                task: task.clone(),
                role: role.clone(),
                msg: bounded(&failure_message(&payload)),
            });
            continue;
        }
        if global.is_none() {
            if let Some(error) = global_error(line) {
                global = Some(error.to_string());
            }
        }
    }

    // Un échec rattrapé (`rescue`) ou ignoré ailleurs reste dans la sortie ; le
    // bilan, quand il existe, fait foi sur les hôtes réellement en échec.
    if !report.recap.is_empty() {
        let recap = &report.recap;
        report.failures.retain(|f| {
            f.host
                .as_ref()
                .and_then(|h| recap.get(h))
                .is_none_or(|r| r.failed > 0 || r.unreachable > 0)
        });
    }
    if report.failures.is_empty() {
        if let Some(error) = global {
            report.failures.push(TaskFailure { host: None, task: None, role: None, msg: bounded(&error) });
        }
    }
    report.failures.truncate(MAX_FAILURES);
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = include_str!("../tests/fixtures/ansible/ok.txt");
    const FAIL: &str = include_str!("../tests/fixtures/ansible/fail.txt");
    const CHECK: &str = include_str!("../tests/fixtures/ansible/check.txt");
    const ERR: &str = include_str!("../tests/fixtures/ansible/err.txt");

    fn recap(ok: u32, changed: u32, failed: u32, unreachable: u32, skipped: u32) -> HostRecap {
        HostRecap { ok, changed, failed, unreachable, skipped }
    }

    #[test]
    fn a_successful_run_has_a_recap_and_no_failure() {
        let report = parse(OK.lines());
        assert_eq!(report.recap.len(), 2);
        assert_eq!(report.recap["local1"], recap(2, 1, 0, 0, 0));
        assert_eq!(report.recap["local2"], recap(2, 1, 0, 0, 0));
        assert!(report.failures.is_empty(), "{:?}", report.failures);
    }

    #[test]
    fn failed_tasks_and_unreachable_hosts_are_named_with_their_role() {
        let report = parse(FAIL.lines());
        assert_eq!(report.recap["ghost1"], recap(0, 0, 0, 1, 0));
        assert_eq!(report.recap["local1"], recap(2, 2, 1, 0, 1));
        assert_eq!(report.recap["local2"], recap(1, 1, 1, 0, 0));

        let found: Vec<(&str, &str, Option<&str>)> = report
            .failures
            .iter()
            .map(|f| (f.host.as_deref().unwrap(), f.task.as_deref().unwrap(), f.role.as_deref()))
            .collect();
        assert_eq!(
            found,
            vec![
                ("ghost1", "Write a marker", Some("demo")),
                ("local2", "Check the service config", Some("demo")),
                ("local1", "Loop with one failing item", Some("demo")),
            ],
            "l'échec ignoré (`...ignoring`) n'en est pas un"
        );
        assert!(report.failures[0].msg.contains("Connection refused"), "{}", report.failures[0].msg);
        assert_eq!(
            report.failures[1].msg,
            "The command exited with a non-zero return code. — bad config line 3",
            "stderr complète le message d'un command"
        );
    }

    #[test]
    fn a_check_run_is_read_the_same_way_and_its_messages_are_redacted() {
        let report = parse(CHECK.lines());
        assert_eq!(report.recap["local1"], recap(1, 1, 1, 0, 4));
        assert_eq!(report.recap["local2"], recap(1, 1, 0, 0, 4));
        let plain = report.failures.iter().find(|f| f.task.as_deref() == Some("Plain failure")).unwrap();
        assert_eq!((plain.host.as_deref(), plain.role.as_deref()), (Some("local1"), None));
        assert_eq!(plain.msg, "password=[REDACTED] boom");
        assert_eq!(report.failures.len(), 2, "{:?}", report.failures);
    }

    #[test]
    fn an_error_before_any_play_is_one_hostless_failure() {
        let report = parse(ERR.lines());
        assert!(report.recap.is_empty());
        assert_eq!(report.failures.len(), 1);
        let failure = &report.failures[0];
        assert_eq!((failure.host.clone(), failure.task.clone()), (None, None));
        assert!(failure.msg.contains("could not be found"), "{}", failure.msg);

        let older = "ERROR! the playbook: x.yml could not be found";
        assert!(parse([older]).failures[0].msg.starts_with("the playbook: x.yml"));
    }

    #[test]
    fn the_older_output_format_is_understood_too() {
        let older = "\
PLAY [x] ***
TASK [proxy-update : Reload nginx] ***
fatal: [proxy1 -> localhost]: FAILED! => {\"changed\": false, \"msg\": \"nginx: [emerg] unknown directive\"}
TASK [Rescued step] ***
fatal: [proxy2]: FAILED! => {\"msg\": \"rescued later\"}
PLAY RECAP ***
proxy1                     : ok=3    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0
proxy2                     : ok=4    changed=1    unreachable=0    failed=0    skipped=0    rescued=1    ignored=0
";
        let report = parse(older.lines());
        assert_eq!(report.failures.len(), 1, "proxy2 a été rattrapé : {:?}", report.failures);
        let f = &report.failures[0];
        assert_eq!(
            (f.host.as_deref(), f.role.as_deref(), f.task.as_deref()),
            (Some("proxy1"), Some("proxy-update"), Some("Reload nginx"))
        );
        assert_eq!(f.msg, "nginx: [emerg] unknown directive");
    }

    #[test]
    fn an_ignored_loop_failure_leaves_no_trace_but_a_neighbour_stays() {
        let out = "\
TASK [x : Loop] ***
failed: [h1] (item=a) => {\"msg\": \"one\"}
failed: [h1] (item=b) => {\"msg\": \"two\"}
...ignoring
TASK [x : Real] ***
fatal: [h1]: FAILED! => {\"msg\": \"real\"}
PLAY RECAP ***
h1                         : ok=1    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=1
";
        let report = parse(out.lines());
        assert_eq!(report.failures.len(), 1, "{:?}", report.failures);
        assert_eq!(report.failures[0].task.as_deref(), Some("Real"));
    }

    #[test]
    fn failures_and_messages_are_bounded() {
        let mut lines = vec!["TASK [x] ***".to_string()];
        let long = "word ".repeat(MAX_MSG_CHARS);
        for i in 0..(MAX_FAILURES + 10) {
            lines.push(format!("fatal: [h{i}]: FAILED! => {{\"msg\": \"{long} {i}\"}}"));
        }
        let report = parse(lines.iter().map(String::as_str));
        assert_eq!(report.failures.len(), MAX_FAILURES);
        assert!(report.failures[0].msg.chars().count() <= MAX_MSG_CHARS + 1);
    }

    #[test]
    fn a_task_name_with_a_colon_is_not_taken_for_a_role() {
        assert_eq!(task_header("TASK [Check: the port is open] ***"), Some((None, "Check: the port is open".into())));
        assert_eq!(
            task_header("TASK [Wait for it : 10 s] ***"),
            Some((None, "Wait for it : 10 s".into()))
        );
        assert_eq!(
            task_header("RUNNING HANDLER [fleetforge-install : restart fleetforge] ***"),
            Some((Some("fleetforge-install".into()), "restart fleetforge".into()))
        );
    }
}
