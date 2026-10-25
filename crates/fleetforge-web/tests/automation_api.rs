/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! API d'automatisation (AgentHub), de bout en bout.
//!
//! Le VRAI binaire `fleetforge-web` est lancé contre un parc factice : un
//! inventaire, des playbooks vides, un `ansible-playbook` et un `ssh` de
//! substitution (scripts qui consignent leurs arguments), un Alertmanager
//! simulé. Aucune machine n'est contactée. L'environnement du processus est
//! vidé : ni les réglages ni la base du poste ne sont lus (`HOME` factice).

use axum::extract::RawQuery;
use axum::routing::get;
use axum::{Json, Router};
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const OPERATOR: (&str, &str) = ("operateur", "mot-de-passe-operateur");
const AGENTHUB: (&str, &str) = ("agenthub", "mot-de-passe-agenthub");

/// Processus serveur, tué à la fin du test quoi qu'il arrive.
struct Server {
    child: Child,
    base: String,
    root: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn script(path: &Path, content: &str) {
    write(path, content);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

const INVENTORY: &str = "\
all:
  vars:
    ansible_roles: []
  children:
    web3c:
      children:
        proxies:
          hosts:
            proxy1:
              ansible_host: 10.0.0.1
              ansible_port: 2222
              provider: contabo
              ansible_roles: [proxy]
            proxy2:
              ansible_host: 10.0.0.9
              provider: contabo
              ansible_roles: [proxy]
        monitoring:
          hosts:
            alertmanager1:
              ansible_host: 127.0.0.1
              provider: custom
              ansible_roles: [alertmanager]
";

/// `ansible-playbook` de substitution : consigne ses arguments, émet un faux
/// secret (pour le caviardage), dort sur un playbook « slow », échoue (code 2)
/// sur un playbook « fail ».
const ANSIBLE_STUB: &str = r#"#!/bin/sh
echo "$*" >> "$FF_STUB_LOG"
echo "PLAY [stub] $*"
echo "smtp_auth_password: hunter2-secret"
case "$*" in *slow*) sleep 3 ;; esac
case "$*" in *fail*) echo "fatal: [proxy1]: FAILED!"; exit 2 ;; esac
echo "PLAY RECAP"
exit 0
"#;

/// `ssh` de substitution : renvoie sa ligne de commande ; 255 (échec de
/// connexion de ssh lui-même) pour 10.0.0.9.
const SSH_STUB: &str = r#"#!/bin/sh
case "$*" in *10.0.0.9*) echo "ssh: connect to host 10.0.0.9 port 22: Connection refused" >&2; exit 255 ;; esac
echo "SSH_ARGS: $*"
echo "DB_PASSWORD=hunter2"
exit 0
"#;

fn hash_with_binary(password: &str) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fleetforge-web"))
        .arg("hash-password")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(password.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// Parc factice, serveur lancé, `/healthz` attendu.
async fn start(alertmanager_port: u16) -> Server {
    let root = std::env::temp_dir().join(format!(
        "ff-automation-api-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let ansible = root.join("ansible");
    write(&ansible.join("inventories/web3c_inventory.yml"), INVENTORY);
    write(
        &ansible.join("playbooks/group_vars/web3c.yml"),
        &format!("parc_name: web3c\nalertmanager_host: alertmanager1\nalertmanager_port: {alertmanager_port}\n"),
    );
    for playbook in ["deploy-demo", "remove-demo", "update-security-ssh", "deploy-slow", "deploy-fail"] {
        write(&ansible.join(format!("playbooks/{playbook}.yml")), "---\n- hosts: all\n  tasks: []\n");
    }
    write(&ansible.join("playbooks/roles/demo-install/tasks/main.yml"), "---\n");
    write(&root.join("static/index.html"), "<!doctype html><title>t</title>");
    write(&root.join("ro-key"), "clé factice");
    script(&root.join("bin/ansible-playbook"), ANSIBLE_STUB);
    script(&root.join("bin/ssh"), SSH_STUB);
    std::fs::create_dir_all(root.join("home")).unwrap();

    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_fleetforge-web"))
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", root.join("bin").display()))
        .env("HOME", root.join("home"))
        .env("FLEETFORGE_LOG_DIR", root.join("logs"))
        .env("FLEETFORGE_WEB_BIND", "127.0.0.1")
        .env("FLEETFORGE_WEB_PORT", port.to_string())
        .env("FLEETFORGE_WEB_STATIC", root.join("static"))
        .env("FLEETFORGE_WEB_USER", OPERATOR.0)
        .env("FLEETFORGE_WEB_PASSWORD", OPERATOR.1)
        .env("FLEETFORGE_API_USER", AGENTHUB.0)
        .env("FLEETFORGE_API_PASSWORD_HASH", hash_with_binary(AGENTHUB.1))
        .env("FLEETFORGE_ANSIBLE_DIR", &ansible)
        .env("FLEETFORGE_RO_SSH_KEY", root.join("ro-key"))
        .env("FLEETFORGE_RO_KNOWN_HOSTS", root.join("known_hosts"))
        .env("FF_STUB_LOG", root.join("stub.log"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("lancement de fleetforge-web");
    let server = Server { child, base: format!("http://127.0.0.1:{port}"), root };

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(r) = reqwest::get(format!("{}/healthz", server.base)).await {
            if r.status().is_success() {
                break;
            }
        }
        assert!(Instant::now() < deadline, "le serveur n'a pas démarré");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    server
}

/// Alertmanager simulé : rend une alerte, garde la requête reçue.
async fn fake_alertmanager() -> (u16, Arc<Mutex<Option<String>>>) {
    let seen = Arc::new(Mutex::new(None));
    let record = seen.clone();
    let app = Router::new().route(
        "/api/v2/alerts",
        get(move |RawQuery(query): RawQuery| {
            let record = record.clone();
            async move {
                *record.lock().unwrap() = query;
                Json(json!([{
                    "labels": { "alertname": "TargetDown", "instance": "proxy1", "severity": "critical" },
                    "annotations": { "summary": "proxy1 ne répond plus" },
                    "status": { "state": "active", "silencedBy": [], "inhibitedBy": [] },
                    "startsAt": "2026-10-25T10:00:00Z",
                    "fingerprint": "abc"
                }]))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (port, seen)
}

/// Requêtes reçues par le Prometheus simulé : (chaîne de requête, en-tête
/// Authorization).
type PromCalls = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// Prometheus simulé : vecteur de deux séries ; matrice si la requête porte
/// une plage ; `bad_data` (400) si elle contient « bad ».
async fn fake_prometheus() -> (u16, PromCalls) {
    let calls: PromCalls = Arc::new(Mutex::new(Vec::new()));
    let record = calls.clone();
    let app = Router::new().route(
        "/api/v1/query",
        get(move |RawQuery(query): RawQuery, headers: axum::http::HeaderMap| {
            let record = record.clone();
            async move {
                let query = query.unwrap_or_default();
                let auth = headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);
                record.lock().unwrap().push((query.clone(), auth));
                if query.contains("bad") {
                    return (
                        axum::http::StatusCode::BAD_REQUEST,
                        Json(json!({ "status": "error", "errorType": "bad_data", "error": "parse error" })),
                    );
                }
                if query.contains("%5B") {
                    return (
                        axum::http::StatusCode::OK,
                        Json(json!({ "status": "success", "data": { "resultType": "matrix", "result": [] } })),
                    );
                }
                (
                    axum::http::StatusCode::OK,
                    Json(json!({ "status": "success", "data": { "resultType": "vector", "result": [
                        { "metric": { "__name__": "up", "instance": "proxy1", "job": "exporter" }, "value": [1729850000.0, "1"] },
                        { "metric": { "__name__": "up", "instance": "proxy2", "job": "exporter" }, "value": [1729850000.0, "0"] }
                    ] } })),
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (port, calls)
}

struct Api<'a> {
    http: Client,
    server: &'a Server,
}

impl Api<'_> {
    async fn call(&self, who: (&str, &str), command: &str, body: Value) -> (StatusCode, Value) {
        let r = self
            .http
            .post(format!("{}/api/{command}", self.server.base))
            .basic_auth(who.0, Some(who.1))
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = r.status();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    async fn agent(&self, command: &str, body: Value) -> (StatusCode, Value) {
        self.call(AGENTHUB, command, body).await
    }

    /// Attend la fin d'un run et rend son `run_status`.
    async fn wait_run(&self, run_id: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let (status, body) = self.agent("run_status", json!({ "run_id": run_id })).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            if body["state"] != "running" {
                return body;
            }
            assert!(Instant::now() < deadline, "run {run_id} interminable");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn stub_log(&self) -> String {
        std::fs::read_to_string(self.server.root.join("stub.log")).unwrap_or_default()
    }
}

fn code(body: &Value) -> &str {
    body["code"].as_str().unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_automation_api_end_to_end() {
    let (am_port, am_query) = fake_alertmanager().await;
    let server = start(am_port).await;
    let api = Api { http: Client::new(), server: &server };

    // ── Authentification et périmètre ─────────────────────────────────────
    let anonymous = api
        .http
        .post(format!("{}/api/list_hosts", server.base))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(anonymous.json::<Value>().await.unwrap()["code"], "unauthorized");

    for forbidden in ["get_run_handle", "write_group_vars_file", "set_inventories_path", "run_ansible_deploy"] {
        let (status, body) = api.agent(forbidden, json!({})).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{forbidden}");
        assert_eq!(code(&body), "forbidden");
    }
    let (status, _) = api.call(OPERATOR, "list_ansible_inventories", json!({})).await;
    assert_eq!(status, StatusCode::OK, "l'opérateur garde toute l'application");

    // ── list_hosts ─────────────────────────────────────────────────────────
    let (status, hosts) = api.agent("list_hosts", json!({ "parc": "web3c" })).await;
    assert_eq!(status, StatusCode::OK, "{hosts}");
    let proxy1 = hosts.as_array().unwrap().iter().find(|h| h["name"] == "proxy1").unwrap();
    assert_eq!(
        proxy1,
        &json!({
            "name": "proxy1", "ip": "10.0.0.1", "port": 2222,
            "groups": ["web3c", "proxies"], "roles": ["proxy"], "provider": "contabo"
        })
    );
    let (status, body) = api.agent("list_hosts", json!({ "parc": "../etc" })).await;
    assert_eq!((status, code(&body)), (StatusCode::BAD_REQUEST, "invalid_argument"));
    let (status, body) = api.agent("list_hosts", json!({ "parc": "papanglabs" })).await;
    assert_eq!((status, code(&body)), (StatusCode::NOT_FOUND, "unknown_parc"));
    let (status, body) = api.agent("list_hosts", json!({})).await;
    assert_eq!((status, code(&body)), (StatusCode::BAD_REQUEST, "invalid_argument"));

    // ── query_prometheus (forme « parc ») ─────────────────────────────────
    let (prom_port, prom_calls) = fake_prometheus().await;
    let (status, body) = api.agent("query_prometheus", json!({ "parc": "web3c", "query": "up" })).await;
    assert_eq!((status, code(&body)), (StatusCode::SERVICE_UNAVAILABLE, "not_configured"));
    let (status, _) = api
        .call(
            OPERATOR,
            "set_fleet_prometheus",
            json!({
                "organization": "web3c", "url": format!("http://127.0.0.1:{prom_port}"),
                "user": "prom", "password": "prom-secret"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, answer) = api
        .agent("query_prometheus", json!({ "parc": "web3c", "query": "up{job=\"exporter\"}", "time": 1729850000 }))
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(
        answer,
        json!({ "parc": "web3c", "truncated": false, "result": [
            { "metric": { "__name__": "up", "instance": "proxy1", "job": "exporter" }, "timestamp": 1729850000.0, "value": "1" },
            { "metric": { "__name__": "up", "instance": "proxy2", "job": "exporter" }, "timestamp": 1729850000.0, "value": "0" }
        ] })
    );
    let (query, auth) = prom_calls.lock().unwrap().last().cloned().unwrap();
    assert!(query.contains("time=1729850000"), "{query}");
    assert_eq!(
        auth.as_deref(),
        Some("Basic cHJvbTpwcm9tLXNlY3JldA=="),
        "identifiants Prometheus posés par le serveur (prom:prom-secret)"
    );
    for (body, expected) in [
        (json!({ "query": "up" }), (StatusCode::BAD_REQUEST, "invalid_argument")),
        (json!({ "parc": "papanglabs", "query": "up" }), (StatusCode::NOT_FOUND, "unknown_parc")),
        (json!({ "parc": "web3c", "query": "" }), (StatusCode::BAD_REQUEST, "invalid_argument")),
        (json!({ "parc": "web3c", "query": "up", "time": "now&x=1" }), (StatusCode::BAD_REQUEST, "invalid_argument")),
        (json!({ "parc": "web3c", "query": "up[5m]" }), (StatusCode::BAD_REQUEST, "invalid_argument")),
        (json!({ "parc": "web3c", "query": "bad(" }), (StatusCode::BAD_REQUEST, "invalid_argument")),
    ] {
        let (status, answer) = api.agent("query_prometheus", body.clone()).await;
        assert_eq!((status, code(&answer)), expected, "{body} → {answer}");
    }

    // ── list_playbooks ─────────────────────────────────────────────────────
    let (status, playbooks) = api.agent("list_playbooks", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let find = |path: &str| playbooks.as_array().unwrap().iter().find(|p| p["path"] == path).cloned();
    assert_eq!(find("deploy-demo.yml").unwrap()["family"], "deploy");
    assert_eq!(find("deploy-demo.yml").unwrap()["service"], "demo");
    assert_eq!(find("remove-demo.yml").unwrap()["family"], "remove");
    assert_eq!(find("update-security-ssh.yml").unwrap()["family"], "security");

    // ── alertmanager_alerts ────────────────────────────────────────────────
    let (status, alerts) = api.agent("alertmanager_alerts", json!({ "parc": "web3c" })).await;
    assert_eq!(status, StatusCode::OK, "{alerts}");
    assert_eq!(alerts[0]["labels"]["alertname"], "TargetDown");
    assert_eq!(alerts[0]["fingerprint"], "abc", "JSON d'Alertmanager rendu tel quel");
    let query = am_query.lock().unwrap().clone().unwrap_or_default();
    for part in ["active=true", "silenced=false", "inhibited=false"] {
        assert!(query.contains(part), "requête Alertmanager : {query}");
    }

    // ── ssh_diagnose ───────────────────────────────────────────────────────
    let (status, diag) = api
        .agent("ssh_diagnose", json!({ "host": "proxy1", "verb": "logs", "args": ["docker", "searxng", "1h"] }))
        .await;
    assert_eq!(status, StatusCode::OK, "{diag}");
    let output = diag["output"].as_str().unwrap();
    assert!(output.contains("-F /dev/null"), "{output}");
    assert!(output.contains("-p 2222") && output.contains("-l openclaw-ro"), "{output}");
    assert!(output.contains("-- 10.0.0.1 logs docker searxng 1h"), "{output}");
    assert!(output.contains("DB_PASSWORD=[REDACTED]") && !output.contains("hunter2"), "{output}");
    assert_eq!((diag["exit_code"].clone(), diag["parc"].clone()), (json!(0), json!("web3c")));

    let (status, diag) = api.agent("ssh_diagnose", json!({ "host": "proxy1", "verb": "status nginx" })).await;
    assert_eq!(status, StatusCode::OK);
    assert!(diag["output"].as_str().unwrap().contains("10.0.0.1 status nginx"));

    for (body, expected) in [
        (json!({ "host": "proxy1", "verb": "rm", "args": ["-rf", "/"] }), (StatusCode::BAD_REQUEST, "invalid_argument")),
        (json!({ "host": "proxy1", "verb": "status", "args": ["x;id"] }), (StatusCode::BAD_REQUEST, "invalid_argument")),
        (json!({ "host": "ghost", "verb": "system" }), (StatusCode::NOT_FOUND, "unknown_host")),
        (json!({ "host": "proxy2", "verb": "system" }), (StatusCode::BAD_GATEWAY, "upstream_error")),
    ] {
        let (status, answer) = api.agent("ssh_diagnose", body.clone()).await;
        assert_eq!((status, code(&answer)), expected, "{body} → {answer}");
    }

    // ── run_ansible_playbook : refus avant tout lancement ─────────────────
    let launch = |extra: Value| {
        let mut body = json!({
            "parc": "web3c", "playbook": "deploy-demo.yml", "limit": ["proxy1"],
            "extra_vars": { "x": "1" }, "detach": true
        });
        body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        body
    };
    let (status, body) = api.agent("run_ansible_playbook", launch(json!({}))).await;
    assert_eq!((status, code(&body)), (StatusCode::CONFLICT, "check_required"));

    for (extra, expected) in [
        (json!({ "check": true, "extra_vars": { "ansible_ssh_common_args": "-oProxyCommand=id" } }), "invalid_argument"),
        (json!({ "check": true, "extra_vars": { "x": "{{ lookup('pipe', 'id') }}" } }), "invalid_argument"),
        (json!({ "check": true, "playbook": "../inventories/web3c_inventory.yml" }), "unknown_playbook"),
        (json!({ "check": true, "playbook": "roles/demo-install/tasks/main.yml" }), "unknown_playbook"),
        (json!({ "check": true, "limit": ["proxy*"] }), "unknown_host"),
        (json!({ "check": true, "parc": server.root.join("ansible/inventories/web3c_inventory.yml") }), "invalid_argument"),
        (json!({ "check": true, "run_id": "a b" }), "invalid_argument"),
    ] {
        let (_, answer) = api.agent("run_ansible_playbook", launch(extra.clone())).await;
        assert_eq!(code(&answer), expected, "{extra} → {answer}");
    }
    assert!(api.stub_log().is_empty(), "aucun refus ne doit atteindre ansible-playbook");

    // ── --check, puis run réel ─────────────────────────────────────────────
    let inventory_file = server.root.join("ansible/inventories/web3c_inventory.yml");
    let before = std::fs::read_to_string(&inventory_file).unwrap();
    // Identifiant à la forme d'AgentHub : `ih-` + 32 hexadécimaux minuscules.
    let agenthub_id = format!("ih-{}", "9f86d081884c7d659a2feaa0c55ad015");
    let (status, started) = api
        .agent("run_ansible_playbook", launch(json!({ "check": true, "run_id": agenthub_id })))
        .await;
    assert_eq!(status, StatusCode::OK, "{started}");
    assert_eq!((started["state"].clone(), started["check"].clone()), (json!("running"), json!(true)));
    assert_eq!(started["run_id"], json!(agenthub_id));
    let run_id = started["run_id"].as_str().unwrap().to_string();
    let done = api.wait_run(&run_id).await;
    assert_eq!((done["state"].clone(), done["exit_code"].clone()), (json!("success"), json!(0)));
    assert!(done["ended_at"].is_string() && done["started_at"].is_string());
    let tail = done["output_tail"].as_str().unwrap();
    assert!(tail.contains("--check") && tail.contains("--limit proxy1"), "{tail}");
    assert!(tail.contains(r#"-e {"x":"1"}"#), "variables en un objet JSON : {tail}");
    assert!(tail.contains("smtp_auth_password: [REDACTED]") && !tail.contains("hunter2"), "{tail}");
    assert_eq!(
        std::fs::read_to_string(&inventory_file).unwrap(),
        before,
        "un --check n'inscrit aucune famille dans l'inventaire"
    );

    // Le flux SSE d'un run fini : relecture caviardée, puis fin.
    let sse = api
        .http
        .get(format!("{}/api/events/{run_id}", server.base))
        .basic_auth(AGENTHUB.0, Some(AGENTHUB.1))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(sse.contains("PLAY [stub]") && sse.contains("event: end"), "{sse}");
    assert!(!sse.contains("hunter2"), "{sse}");

    let (status, real) = api.agent("run_ansible_playbook", launch(json!({ "diff": true }))).await;
    assert_eq!(status, StatusCode::OK, "le check récent autorise le run réel : {real}");
    let done = api.wait_run(real["run_id"].as_str().unwrap()).await;
    assert_eq!(done["state"], "success");
    let last = api.stub_log().lines().last().unwrap().to_string();
    assert!(last.contains("--diff") && !last.contains("--check"), "{last}");

    // Un autre lancement (autre limit) exige SON check.
    let (_, body) = api.agent("run_ansible_playbook", launch(json!({ "limit": ["proxy2"] }))).await;
    assert_eq!(code(&body), "check_required");

    // ── Code de sortie, parc occupé, identifiant en cours ─────────────────
    let (_, failing) = api
        .agent("run_ansible_playbook", launch(json!({ "check": true, "playbook": "deploy-fail.yml" })))
        .await;
    let done = api.wait_run(failing["run_id"].as_str().unwrap()).await;
    assert_eq!((done["state"].clone(), done["exit_code"].clone()), (json!("failed"), json!(2)));

    let (status, slow) = api
        .agent("run_ansible_playbook", launch(json!({ "check": true, "playbook": "deploy-slow.yml", "run_id": "slow-1" })))
        .await;
    assert_eq!(status, StatusCode::OK, "{slow}");
    let (status, body) = api
        .agent("run_ansible_playbook", launch(json!({ "check": true, "run_id": "slow-1" })))
        .await;
    assert_eq!((status, code(&body)), (StatusCode::CONFLICT, "run_id_in_use"));
    let (status, body) = api.agent("run_ansible_playbook", launch(json!({ "check": true }))).await;
    assert_eq!((status, code(&body)), (StatusCode::CONFLICT, "run_busy"));
    assert_eq!(api.wait_run("slow-1").await["state"], "success");

    let (status, body) = api.agent("run_status", json!({ "run_id": "nope" })).await;
    assert_eq!((status, code(&body)), (StatusCode::NOT_FOUND, "unknown_run"));

    // ── L'opérateur : forme du frontal, réponse au terme du run ───────────
    let playbook = server.root.join("ansible/playbooks/remove-demo.yml");
    let (status, run) = api
        .call(
            OPERATOR,
            "run_ansible_playbook",
            json!({
                "deployId": "gui-1", "playbookPath": playbook, "inventoryPath": "web3c",
                "limitHosts": null, "label": "Retirer demo"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{run}");
    assert_eq!((run["status"].clone(), run["run_id"].clone()), (json!("success"), json!("gui-1")));
    assert!(run["output"].as_str().unwrap().contains("hunter2"), "l'opérateur voit la sortie brute");
}

#[test]
fn a_half_configured_automation_account_refuses_to_start() {
    let out = Command::new(env!("CARGO_BIN_EXE_fleetforge-web"))
        .env_clear()
        .env("HOME", std::env::temp_dir())
        .env("FLEETFORGE_LOG_DIR", std::env::temp_dir().join("ff-automation-api-logs"))
        .env("FLEETFORGE_WEB_PORT", free_port().to_string())
        .env("FLEETFORGE_API_USER", "agenthub")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("FLEETFORGE_API_USER"));
}
