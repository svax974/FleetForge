/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Sous-processus bornés (durée et volume de sortie).
//!
//! Jamais de shell : l'appelant construit une [`Command`] aux arguments
//! séparés. Un processus qui dépasse son délai est tué ; sa sortie est lue par
//! deux fils et plafonnée, de sorte qu'un processus bavard ne remplit ni la
//! mémoire ni un tube que personne ne vide.

use anyhow::{Context, Result};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Ce qu'un sous-processus a rendu.
#[derive(Debug, Clone)]
pub struct Captured {
    /// `None` : tué par un signal, ou par le délai.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl Captured {
    pub fn success(&self) -> bool {
        self.code == Some(0) && !self.timed_out
    }
}

fn drain(mut reader: impl Read + Send + 'static, max: usize) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    // On continue de LIRE au-delà du plafond, pour ne pas
                    // bloquer le processus sur un tube plein.
                    let room = max.saturating_sub(kept.len());
                    kept.extend_from_slice(&buf[..n.min(room)]);
                }
            }
        }
        kept
    })
}

/// Lance `cmd` et attend sa fin, au plus `timeout`. `max_bytes` borne chaque
/// flux (le reste est lu et jeté).
pub fn run_bounded(mut cmd: Command, timeout: Duration, max_bytes: usize) -> Result<Captured> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().with_context(|| format!("lancement de {:?}", cmd.get_program()))?;
    let out = child.stdout.take().map(|s| drain(s, max_bytes));
    let err = child.stderr.take().map(|s| drain(s, max_bytes));

    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            let _ = child.kill();
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let text = |handle: Option<std::thread::JoinHandle<Vec<u8>>>| {
        handle
            .and_then(|h| h.join().ok())
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    };
    Ok(Captured { code: status.code(), stdout: text(out), stderr: text(err), timed_out })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_captured_and_the_code_is_known() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo out; echo err >&2; exit 3"]);
        let got = run_bounded(cmd, Duration::from_secs(10), 1024).unwrap();
        assert_eq!((got.code, got.stdout.trim(), got.stderr.trim()), (Some(3), "out", "err"));
        assert!(!got.success());
    }

    #[test]
    fn a_slow_process_is_killed_at_the_deadline() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let started = Instant::now();
        let got = run_bounded(cmd, Duration::from_millis(200), 1024).unwrap();
        assert!(got.timed_out && !got.success());
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_chatty_process_is_capped_without_blocking() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "yes x | head -c 2000000"]);
        let got = run_bounded(cmd, Duration::from_secs(20), 1000).unwrap();
        assert_eq!(got.stdout.len(), 1000);
        assert!(got.success());
    }
}
