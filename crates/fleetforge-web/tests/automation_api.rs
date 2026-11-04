/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! API d'automatisation (AgentHub), de bout en bout — par REST
//! (`POST /api/<commande>`) et par le serveur MCP (`/mcp`).
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
              monitor: \"off\"
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

/// Répertoire de test neuf, propre à l'appel.
///
/// Le compteur est indispensable : les tests tournent en parallèle et
/// l'horloge de macOS ne va qu'à la microseconde — deux serveurs lancés
/// ensemble partageaient sinon leur `HOME`, donc leur base et leur arbre.
fn fresh_root() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "ff-automation-api-{}-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ))
}

/// Parc factice, serveur lancé, `/healthz` attendu.
async fn start(alertmanager_port: u16) -> Server {
    start_with(alertmanager_port, |_| Vec::new()).await
}

/// [`start`], avec des fichiers et variables d'environnement en plus :
/// `setup` reçoit la racine du test et rend les variables à poser.
async fn start_with(alertmanager_port: u16, setup: impl FnOnce(&Path) -> Vec<(String, String)>) -> Server {
    let root = fresh_root();
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
    let extra_env = setup(&root);

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
        .envs(extra_env)
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
            "groups": ["web3c", "proxies"], "roles": ["proxy"], "provider": "contabo",
            "monitored": true
        })
    );
    let proxy2 = hosts.as_array().unwrap().iter().find(|h| h["name"] == "proxy2").unwrap();
    assert_eq!(proxy2["monitored"], json!(false), "monitor: \"off\" : {proxy2}");
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

/// Version du protocole MCP annoncée par les appels après `initialize`.
const MCP_VERSION: &str = "2025-11-25";

impl Api<'_> {
    /// Message JSON-RPC sur `/mcp` : (statut HTTP, corps JSON ou `Null`).
    async fn mcp_raw(
        &self,
        who: Option<(&str, &str)>,
        headers: &[(&str, &str)],
        body: Value,
    ) -> (StatusCode, Value) {
        let mut request = self
            .http
            .post(format!("{}/mcp", self.server.base))
            .header("Accept", "application/json, text/event-stream")
            .json(&body);
        if let Some((user, password)) = who {
            request = request.basic_auth(user, Some(password));
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let r = request.send().await.unwrap();
        let status = r.status();
        let text = r.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn rpc(&self, who: (&str, &str), method: &str, params: Value) -> Value {
        let (status, body) = self
            .mcp_raw(
                Some(who),
                &[("MCP-Protocol-Version", MCP_VERSION)],
                json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{method} → {body}");
        assert_eq!(body["id"], 7, "{body}");
        body
    }

    /// `tools/call` : (erreur d'outil ?, texte de la réponse lu en JSON).
    async fn tool(&self, who: (&str, &str), name: &str, arguments: Value) -> (bool, Value) {
        let body = self.rpc(who, "tools/call", json!({ "name": name, "arguments": arguments })).await;
        let result = &body["result"];
        assert!(result.is_object(), "{name} → {body}");
        let text = result["content"][0]["text"].as_str().unwrap_or_else(|| panic!("{name} → {body}"));
        (result["isError"] == json!(true), serde_json::from_str(text).unwrap())
    }

    /// Attend la fin d'un run par l'outil `run_status`.
    async fn wait_run_mcp(&self, who: (&str, &str), run_id: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let (failed, status) = self.tool(who, "run_status", json!({ "run_id": run_id })).await;
            assert!(!failed, "{status}");
            if status["state"] != "running" {
                return status;
            }
            assert!(Instant::now() < deadline, "run {run_id} interminable");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_mcp_server_end_to_end() {
    let (am_port, _) = fake_alertmanager().await;
    let server = start(am_port).await;
    let api = Api { http: Client::new(), server: &server };

    // ── Authentification : la même que l'API ──────────────────────────────
    let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    let (status, _) = api.mcp_raw(None, &[], ping.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = api.mcp_raw(Some((AGENTHUB.0, "mauvais")), &[], ping).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // ── Cycle de vie : initialize, initialized, ping ──────────────────────
    let initialize = |version: &str| {
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": version, "capabilities": {},
                "clientInfo": { "name": "test", "version": "1.0" }
            }
        })
    };
    let (status, init) = api.mcp_raw(Some(AGENTHUB), &[], initialize("2025-06-18")).await;
    assert_eq!(status, StatusCode::OK, "{init}");
    let result = &init["result"];
    assert_eq!(result["protocolVersion"], "2025-06-18", "version du client retenue : {init}");
    assert_eq!(result["serverInfo"]["name"], "fleetforge");
    assert!(result["capabilities"]["tools"].is_object(), "{init}");
    assert!(result["instructions"].as_str().unwrap().contains("check_required"));
    // Version inconnue : repli sur la plus récente qui connaît `initialize`.
    let (_, init) = api.mcp_raw(Some(AGENTHUB), &[], initialize("2099-01-01")).await;
    assert_eq!(init["result"]["protocolVersion"], "2025-11-25", "{init}");

    let (status, _) = api
        .mcp_raw(
            Some(AGENTHUB),
            &[("MCP-Protocol-Version", MCP_VERSION)],
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(api.rpc(AGENTHUB, "ping", json!({})).await["result"], json!({}));

    // ── tools/list : les commandes d'automatisation, une par une ─────────
    let listed = api.rpc(AGENTHUB, "tools/list", json!({})).await;
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "list_hosts", "list_playbooks", "alertmanager_alerts", "query_prometheus", "ssh_diagnose",
            "describe_playbook", "read_tree", "search_tree", "tree_status",
            "run_ansible_playbook", "run_status", "syntax_check", "sync_tree"
        ]
    );
    for tool in listed["result"]["tools"].as_array().unwrap() {
        assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
    }

    // ── Mêmes réponses que l'API REST ─────────────────────────────────────
    let (failed, hosts) = api.tool(AGENTHUB, "list_hosts", json!({ "parc": "web3c" })).await;
    assert!(!failed, "{hosts}");
    assert_eq!(hosts, api.agent("list_hosts", json!({ "parc": "web3c" })).await.1);
    let (failed, alerts) = api.tool(AGENTHUB, "alertmanager_alerts", json!({ "parc": "web3c" })).await;
    assert!(!failed && alerts[0]["labels"]["alertname"] == "TargetDown", "{alerts}");

    // ── Refus = erreurs d'outil, avec le code de l'API ────────────────────
    for (name, arguments, expected) in [
        ("list_hosts", json!({ "parc": "papanglabs" }), "unknown_parc"),
        ("list_hosts", json!({}), "invalid_argument"),
        ("ssh_diagnose", json!({ "host": "proxy1", "verb": "rm", "args": ["-rf", "/"] }), "invalid_argument"),
        ("ssh_diagnose", json!({ "host": "ghost", "verb": "system" }), "unknown_host"),
        ("query_prometheus", json!({ "parc": "web3c", "query": "up" }), "not_configured"),
        ("run_status", json!({ "run_id": "nope" }), "unknown_run"),
        ("run_ansible_playbook", json!({ "parc": "web3c", "playbook": "deploy-demo.yml" }), "check_required"),
    ] {
        let (failed, error) = api.tool(AGENTHUB, name, arguments.clone()).await;
        assert!(failed, "{name} {arguments} → {error}");
        assert_eq!(error["code"], expected, "{name} {arguments} → {error}");
        assert!(error["error"].as_str().is_some_and(|m| !m.is_empty()), "{error}");
    }
    // Le compte opérateur n'ouvre pas la forme permissive du frontal par MCP.
    let (failed, error) = api.tool(OPERATOR, "query_prometheus", json!({ "query": "up" })).await;
    assert!(failed && error["code"] == "invalid_argument", "{error}");
    let (failed, error) = api
        .tool(OPERATOR, "run_ansible_playbook", json!({ "parc": "web3c", "playbook": "deploy-demo.yml" }))
        .await;
    assert!(failed && error["code"] == "check_required", "{error}");

    // Outil inconnu : erreur de protocole (-32602), pas d'outil.
    let unknown = api.rpc(AGENTHUB, "tools/call", json!({ "name": "rm_rf", "arguments": {} })).await;
    assert_eq!(unknown["error"]["code"], -32602, "{unknown}");

    // ── --check, détaché par défaut, puis run réel ────────────────────────
    let launch = json!({ "parc": "web3c", "playbook": "deploy-demo.yml", "limit": ["proxy1"], "check": true });
    let (failed, started) = api.tool(AGENTHUB, "run_ansible_playbook", launch).await;
    assert!(!failed, "{started}");
    assert_eq!((started["state"].clone(), started["check"].clone()), (json!("running"), json!(true)));
    let done = api.wait_run_mcp(AGENTHUB, started["run_id"].as_str().unwrap()).await;
    assert_eq!(done["state"], "success", "{done}");
    let tail = done["output_tail"].as_str().unwrap();
    assert!(tail.contains("smtp_auth_password: [REDACTED]") && !tail.contains("hunter2"), "{tail}");

    let (failed, real) = api
        .tool(AGENTHUB, "run_ansible_playbook", json!({ "parc": "web3c", "playbook": "deploy-demo.yml", "limit": ["proxy1"] }))
        .await;
    assert!(!failed, "le check fait par MCP autorise le run réel : {real}");
    assert_eq!(api.wait_run_mcp(AGENTHUB, real["run_id"].as_str().unwrap()).await["state"], "success");

    // ── Protocole 2026-07-28 : sans `initialize`, métadonnées par requête ─
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": { "name": "test", "version": "1.0" },
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let (status, discovered) = api
        .mcp_raw(
            Some(AGENTHUB),
            &[("MCP-Protocol-Version", "2026-07-28"), ("Mcp-Method", "server/discover")],
            json!({ "jsonrpc": "2.0", "id": 2, "method": "server/discover", "params": { "_meta": meta } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{discovered}");
    let versions = discovered["result"]["supportedVersions"].as_array().unwrap();
    for version in ["2025-06-18", "2025-11-25", "2026-07-28"] {
        assert!(versions.contains(&json!(version)), "{discovered}");
    }
    let (status, called) = api
        .mcp_raw(
            Some(AGENTHUB),
            &[("MCP-Protocol-Version", "2026-07-28"), ("Mcp-Method", "tools/call"), ("Mcp-Name", "list_playbooks")],
            json!({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": { "name": "list_playbooks", "arguments": {}, "_meta": meta }
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{called}");
    assert_eq!(called["result"]["isError"], json!(false), "{called}");
    assert!(called["result"]["content"][0]["text"].as_str().unwrap().contains("deploy-demo.yml"));
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

// ── Comptes bornés (`FLEETFORGE_API_ACCOUNTS_FILE`) ───────────────────────

const READER: (&str, &str) = ("lecteur", "mot-de-passe-lecteur");
const RUNNER: (&str, &str) = ("pilote", "mot-de-passe-pilote");

/// Second parc : `proxy1` y existe aussi (même nom, autre machine), `vpn1`
/// n'existe qu'ici.
const SECOND_INVENTORY: &str = "\
all:
  vars:
    ansible_roles: []
  children:
    papanglabs:
      children:
        proxies:
          hosts:
            proxy1:
              ansible_host: 10.1.0.1
              provider: ovh
        vpns:
          hosts:
            vpn1:
              ansible_host: 10.1.0.2
              provider: ovh
";

/// Fichier des comptes en 0600, tel que `fleetforge-install` le pose.
fn accounts_file(root: &Path, accounts: Value) -> PathBuf {
    let path = root.join("api-accounts.json");
    write(&path, &accounts.to_string());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

fn bounded_accounts() -> Value {
    json!([
        { "user": READER.0, "password_hash": hash_with_binary(READER.1), "parcs": ["web3c"], "mode": "read" },
        { "user": RUNNER.0, "password_hash": hash_with_binary(RUNNER.1), "parcs": ["papanglabs"], "mode": "run" }
    ])
}

#[tokio::test(flavor = "multi_thread")]
async fn bounded_accounts_keep_to_their_parcs_and_mode() {
    let (am_port, _) = fake_alertmanager().await;
    let accounts = bounded_accounts();
    let server = start_with(am_port, |root| {
        let ansible = root.join("ansible");
        write(&ansible.join("inventories/papanglabs_inventory.yml"), SECOND_INVENTORY);
        write(&ansible.join("playbooks/group_vars/papanglabs.yml"), "parc_name: papanglabs\n");
        let file = accounts_file(root, accounts);
        vec![("FLEETFORGE_API_ACCOUNTS_FILE".into(), file.display().to_string())]
    })
    .await;
    let api = Api { http: Client::new(), server: &server };
    let forbidden = |(status, body): (StatusCode, Value)| status == StatusCode::FORBIDDEN && code(&body) == "forbidden";

    // ── Lecture, borné à web3c ─────────────────────────────────────────────
    let (status, hosts) = api.call(READER, "list_hosts", json!({ "parc": "web3c" })).await;
    assert_eq!(status, StatusCode::OK, "{hosts}");
    for (command, body) in [
        ("list_hosts", json!({ "parc": "papanglabs" })),
        // Hors périmètre ET inexistant : même réponse, rien n'est révélé.
        ("list_hosts", json!({ "parc": "nulle-part" })),
        ("alertmanager_alerts", json!({ "parc": "papanglabs" })),
        ("query_prometheus", json!({ "parc": "papanglabs", "query": "up" })),
        ("ssh_diagnose", json!({ "host": "vpn1", "verb": "system" })),
        ("ssh_diagnose", json!({ "host": "proxy1", "verb": "system", "parc": "papanglabs" })),
        // Mode lecture : ni run, ni état de run.
        ("run_ansible_playbook", json!({ "parc": "web3c", "playbook": "deploy-demo.yml", "check": true })),
        ("run_status", json!({ "run_id": "nope" })),
        ("syntax_check", json!({ "parc": "web3c", "playbook": "deploy-demo.yml" })),
        ("sync_tree", json!({ "parc": "web3c" })),
        // La lecture de l'arbre aussi est bornée au parc du compte.
        ("read_tree", json!({ "parc": "papanglabs", "path": "" })),
        ("describe_playbook", json!({ "parc": "papanglabs", "playbook": "deploy-demo.yml" })),
        ("search_tree", json!({ "parc": "papanglabs", "pattern": "x" })),
        ("tree_status", json!({ "parc": "papanglabs" })),
    ] {
        let answer = api.call(READER, command, body.clone()).await;
        assert!(forbidden(answer.clone()), "{command} {body} → {answer:?}");
    }
    // `proxy1` est dans les deux parcs : sans `parc`, le lecteur ne voit que
    // le sien, sans ambiguïté…
    let (status, diag) = api.call(READER, "ssh_diagnose", json!({ "host": "proxy1", "verb": "system" })).await;
    assert_eq!((status, diag["parc"].clone()), (StatusCode::OK, json!("web3c")), "{diag}");
    assert!(diag["output"].as_str().unwrap().contains("10.0.0.1"), "{diag}");
    // … alors que le compte hérité, qui couvre tout, doit préciser.
    let (status, body) = api.agent("ssh_diagnose", json!({ "host": "proxy1", "verb": "system" })).await;
    assert_eq!((status, code(&body)), (StatusCode::BAD_REQUEST, "ambiguous_host"));

    // ── Pilotage, borné à papanglabs ───────────────────────────────────────
    let launch = |parc: &str, host: &str| {
        json!({ "parc": parc, "playbook": "deploy-demo.yml", "limit": [host], "check": true, "detach": true })
    };
    assert!(forbidden(api.call(RUNNER, "run_ansible_playbook", launch("web3c", "proxy1")).await));
    let (status, own) = api.call(RUNNER, "run_ansible_playbook", launch("papanglabs", "vpn1")).await;
    assert_eq!(status, StatusCode::OK, "{own}");
    let own_id = own["run_id"].as_str().unwrap().to_string();
    let (_, other) = api.agent("run_ansible_playbook", launch("web3c", "proxy1")).await;
    let other_id = other["run_id"].as_str().unwrap().to_string();

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let (status, run) = api.call(RUNNER, "run_status", json!({ "run_id": own_id })).await;
        assert_eq!(status, StatusCode::OK, "{run}");
        if run["state"] != "running" {
            break;
        }
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    api.wait_run(&other_id).await;
    assert!(
        forbidden(api.call(RUNNER, "run_status", json!({ "run_id": other_id })).await),
        "un run de web3c n'est pas visible d'un compte borné à papanglabs"
    );
    let stream = |who: (&str, &str), id: &str| {
        api.http
            .get(format!("{}/api/events/{id}", server.base))
            .basic_auth(who.0, Some(who.1))
            .send()
    };
    assert_eq!(stream(RUNNER, &own_id).await.unwrap().status(), StatusCode::OK);
    assert_eq!(stream(RUNNER, &other_id).await.unwrap().status(), StatusCode::FORBIDDEN);
    assert_eq!(stream(READER, &own_id).await.unwrap().status(), StatusCode::FORBIDDEN);
    assert_eq!(stream(AGENTHUB, &own_id).await.unwrap().status(), StatusCode::OK, "le compte hérité couvre tout");

    // ── Même périmètre par MCP ─────────────────────────────────────────────
    let tools = |listed: Value| -> Vec<String> {
        listed["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect()
    };
    assert_eq!(
        tools(api.rpc(READER, "tools/list", json!({})).await),
        [
            "list_hosts", "list_playbooks", "alertmanager_alerts", "query_prometheus", "ssh_diagnose",
            "describe_playbook", "read_tree", "search_tree", "tree_status"
        ]
    );
    assert_eq!(tools(api.rpc(RUNNER, "tools/list", json!({})).await).len(), 13);
    for (name, arguments) in [
        ("run_ansible_playbook", launch("web3c", "proxy1")),
        ("run_status", json!({ "run_id": own_id })),
        ("list_hosts", json!({ "parc": "papanglabs" })),
        ("ssh_diagnose", json!({ "host": "vpn1", "verb": "system" })),
    ] {
        let (failed, error) = api.tool(READER, name, arguments.clone()).await;
        assert!(failed && error["code"] == "forbidden", "{name} {arguments} → {error}");
    }
    let (failed, error) = api.tool(RUNNER, "run_status", json!({ "run_id": other_id })).await;
    assert!(failed && error["code"] == "forbidden", "{error}");
    let (failed, hosts) = api.tool(RUNNER, "list_hosts", json!({ "parc": "papanglabs" })).await;
    assert!(!failed && hosts.as_array().unwrap().len() == 2, "{hosts}");
}

/// Le serveur refuse de démarrer sur ce fichier de comptes ; `expected` doit
/// figurer dans son message.
fn refuses_accounts(accounts: Value, mode: u32, expected: &str) {
    let root = fresh_root();
    let file = accounts_file(&root, accounts);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    let out = Command::new(env!("CARGO_BIN_EXE_fleetforge-web"))
        .env_clear()
        .env("HOME", &root)
        .env("FLEETFORGE_LOG_DIR", root.join("logs"))
        .env("FLEETFORGE_WEB_PORT", free_port().to_string())
        .env("FLEETFORGE_WEB_USER", OPERATOR.0)
        .env("FLEETFORGE_WEB_PASSWORD", OPERATOR.1)
        .env("FLEETFORGE_API_ACCOUNTS_FILE", &file)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&root);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "démarrage accepté, attendu : {expected}");
    assert!(stderr.contains(expected), "{stderr}");
}

#[test]
fn a_flawed_accounts_file_refuses_to_start() {
    let hash = hash_with_binary("x");
    let entry = |user: &str, parcs: Value, mode: &str| json!({ "user": user, "password_hash": hash, "parcs": parcs, "mode": mode });
    refuses_accounts(json!([entry("a", json!(["web3c"]), "read")]), 0o644, "0600");
    refuses_accounts(json!([entry("a", json!(["web3c"]), "admin")]), 0o600, "comptes illisibles");
    refuses_accounts(json!([entry("a", json!([]), "read")]), 0o600, "aucun parc");
    refuses_accounts(json!([entry("a", json!(["../etc"]), "read")]), 0o600, "compte a");
    refuses_accounts(json!([entry(OPERATOR.0, json!(["web3c"]), "read")]), 0o600, "deux fois");
    refuses_accounts(
        json!([{ "user": "a", "password_hash": "clair", "parcs": ["web3c"], "mode": "read" }]),
        0o600,
        "empreinte invalide",
    );
    refuses_accounts(
        json!([{ "user": "a", "password": "clair", "parcs": ["web3c"], "mode": "read" }]),
        0o600,
        "comptes illisibles",
    );
}

// ═══ Arbre Ansible : lecture, étiquettes, comptes bornés, arbre git ═══════

/// Playbooks et rôles de l'arbre de lecture (livré par rsync).
fn write_tree_fixture(ansible: &Path) {
    write(
        &ansible.join("playbooks/deploy-tagged.yml"),
        "---\n- name: Tagged\n  hosts: proxies\n  tags: [play-level]\n  roles:\n    - demo-install\n    \
         - { role: tagged-install, tags: [by-role] }\n- name: Elsewhere\n  hosts: monitoring\n  tasks:\n    \
         - name: Needs a variable\n      ansible.builtin.debug:\n        msg: \"{{ model_name }} {{ optional | default('x') }}\"\n",
    );
    write(&ansible.join("playbooks/deploy-importer.yml"), "---\n- import_playbook: update-security-ssh.yml\n");
    write(
        &ansible.join("playbooks/roles/tagged-install/tasks/main.yml"),
        "---\n- name: Configure\n  ansible.builtin.debug:\n    msg: hello\n  tags: [configure]\n",
    );
    write(
        &ansible.join("playbooks/roles/demo-install/tasks/main.yml"),
        "---\n- name: Login\n  ansible.builtin.debug:\n    msg: x\n  vars:\n    smtp_password: hunter2-secret\n  tags: [login]\n",
    );
    write(&ansible.join("playbooks/roles/demo-install/files/private.json"), "{\"token\": \"abc\"}\n");
    write(&ansible.join("playbooks/roles/vaulted/vars/main.yml"), "$ANSIBLE_VAULT;1.1;AES256\n6162\n");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("../inventories/web3c_inventory.yml", ansible.join("playbooks/leak.yml")).unwrap();
        std::os::unix::fs::symlink("../playbooks/group_vars/web3c.yml", ansible.join("playbooks/roles/leak-gv.yml")).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_tree_tools_read_code_only_on_an_rsync_tree() {
    let (am_port, _) = fake_alertmanager().await;
    let server = start_with(am_port, |root| {
        write_tree_fixture(&root.join("ansible"));
        vec![(
            "FLEETFORGE_TREE_PRIVATE_FILES".to_string(),
            "playbooks/roles/demo-install/files/private.json".to_string(),
        )]
    })
    .await;
    let api = Api { http: Client::new(), server: &server };

    // ── tree_status : pas de git, pas de commit ───────────────────────────
    let (status, tree) = api.agent("tree_status", json!({ "parc": "web3c" })).await;
    assert_eq!(status, StatusCode::OK, "{tree}");
    assert_eq!(
        tree,
        json!({ "source": "rsync", "branch": null, "head": null, "synced_at": null, "commits_cached": 0 })
    );
    for (command, body) in [
        ("read_tree", json!({ "parc": "web3c", "path": "", "commit": "HEAD" })),
        ("describe_playbook", json!({ "parc": "web3c", "playbook": "deploy-tagged.yml", "commit": "HEAD" })),
        ("sync_tree", json!({ "parc": "web3c" })),
        ("syntax_check", json!({ "parc": "web3c", "playbook": "deploy-tagged.yml", "commit": "HEAD" })),
    ] {
        let (status, answer) = api.agent(command, body.clone()).await;
        assert_eq!((status, code(&answer)), (StatusCode::SERVICE_UNAVAILABLE, "not_configured"), "{command} → {answer}");
    }

    // ── read_tree : du code sous playbooks/, rien d'autre ─────────────────
    let (status, listing) = api.agent("read_tree", json!({ "parc": "web3c" })).await;
    assert_eq!(status, StatusCode::OK, "{listing}");
    assert_eq!((listing["kind"].clone(), listing["path"].clone(), listing["commit"].clone()), (json!("dir"), json!("playbooks"), Value::Null));
    let names: Vec<&str> = listing["entries"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"deploy-tagged.yml") && names.contains(&"roles"), "{names:?}");
    for hidden in ["group_vars", "host_vars", "leak.yml", "leak-gv.yml"] {
        assert!(!names.contains(&hidden), "{hidden} ne doit pas apparaître : {names:?}");
    }
    let (_, roles) = api.agent("read_tree", json!({ "parc": "web3c", "path": "playbooks/roles/demo-install/files" })).await;
    assert_eq!(roles["entries"], json!([]), "le fichier livré avec une donnée de parc est omis : {roles}");

    let (status, file) = api.agent("read_tree", json!({ "parc": "web3c", "path": "roles/tagged-install/tasks/main.yml" })).await;
    assert_eq!(status, StatusCode::OK, "{file}");
    assert_eq!((file["kind"].clone(), file["redacted"].clone()), (json!("file"), json!(false)));
    assert!(file["content"].as_str().unwrap().starts_with("---\n") && file["content"].as_str().unwrap().ends_with("hello\n  tags: [configure]\n"), "{file}");
    let (_, secretive) = api.agent("read_tree", json!({ "parc": "web3c", "path": "roles/demo-install/tasks/main.yml" })).await;
    assert_eq!(secretive["redacted"], json!(true), "{secretive}");
    assert!(secretive["content"].as_str().unwrap().contains("smtp_password: [REDACTED]") && !secretive["content"].as_str().unwrap().contains("hunter2"), "{secretive}");

    for path in [
        "../inventories/web3c_inventory.yml", "playbooks/../inventories/web3c_inventory.yml", "/etc/passwd",
        "group_vars/web3c.yml", "playbooks/group_vars", "host_vars", "inventories", "keys", "parcs", "leak.yml",
        "roles/leak-gv.yml", "roles/vaulted/vars/main.yml", "roles/demo-install/files/private.json", ".git/config",
    ] {
        let (status, answer) = api.agent("read_tree", json!({ "parc": "web3c", "path": path })).await;
        assert!(
            (status == StatusCode::FORBIDDEN && code(&answer) == "path_refused") || (status == StatusCode::NOT_FOUND && code(&answer) == "unknown_path"),
            "{path} → {status} {answer}"
        );
        assert!(!answer.to_string().contains("hunter2") && !answer.to_string().contains("10.0.0.1"), "{path} → {answer}");
    }
    let (status, answer) = api.agent("read_tree", json!({ "parc": "../etc", "path": "" })).await;
    assert_eq!((status, code(&answer)), (StatusCode::BAD_REQUEST, "invalid_argument"));

    // ── search_tree ───────────────────────────────────────────────────────
    let (status, found) = api.agent("search_tree", json!({ "parc": "web3c", "pattern": "model_name" })).await;
    assert_eq!(status, StatusCode::OK, "{found}");
    assert_eq!(found["hits"].as_array().unwrap().len(), 1, "{found}");
    assert_eq!(found["hits"][0]["path"], "playbooks/deploy-tagged.yml");
    let (_, found) = api.agent("search_tree", json!({ "parc": "web3c", "pattern": "web3c" })).await;
    assert!(
        found["hits"].as_array().unwrap().iter().all(|h| !h["path"].as_str().unwrap().contains("group_vars")),
        "group_vars/web3c.yml mentionne web3c : {found}"
    );
    let (_, found) = api.agent("search_tree", json!({ "parc": "web3c", "pattern": "hunter2" })).await;
    assert!(found["hits"][0]["text"].as_str().unwrap().contains("[REDACTED]"), "{found}");
    let (status, answer) = api.agent("search_tree", json!({ "parc": "web3c", "pattern": "" })).await;
    assert_eq!((status, code(&answer)), (StatusCode::BAD_REQUEST, "invalid_argument"));

    // ── describe_playbook ─────────────────────────────────────────────────
    let (status, d) = api.agent("describe_playbook", json!({ "parc": "web3c", "playbook": "deploy-tagged.yml" })).await;
    assert_eq!(status, StatusCode::OK, "{d}");
    assert_eq!(d["plays"][0]["hosts"], "proxies");
    assert_eq!(d["plays"][0]["roles"], json!(["demo-install", "tagged-install"]));
    for tag in ["play-level", "by-role", "configure", "login"] {
        assert!(d["tags"].as_array().unwrap().contains(&json!(tag)), "{tag} : {d}");
    }
    assert_eq!(d["needs_no_limit"], json!(true), "le play `monitoring` sort des cibles `proxies` : {d}");
    assert_eq!(d["vars"], json!(["model_name"]), "{d}");
    let (status, answer) = api.agent("describe_playbook", json!({ "parc": "web3c", "playbook": "../x.yml" })).await;
    assert_eq!((status, code(&answer)), (StatusCode::NOT_FOUND, "unknown_playbook"));

    // ── syntax_check n'existe pas sans commit… mais passe sans (arbre rsync) ─
    let (status, answer) = api.agent("syntax_check", json!({ "parc": "web3c", "playbook": "deploy-tagged.yml" })).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!((answer["ok"].clone(), answer["commit"].clone()), (json!(true), Value::Null));
    assert!(api.stub_log().contains("--syntax-check"), "{}", api.stub_log());

    // ── Les mêmes outils par MCP ──────────────────────────────────────────
    let (failed, tree) = api.tool(AGENTHUB, "read_tree", json!({ "parc": "web3c", "path": "deploy-tagged.yml" })).await;
    assert!(!failed && tree["content"].as_str().unwrap().contains("Tagged"), "{tree}");
    let (failed, error) = api.tool(AGENTHUB, "read_tree", json!({ "parc": "web3c", "path": "../inventories" })).await;
    assert!(failed && error["code"] == "path_refused", "{error}");
    let (failed, error) = api.tool(AGENTHUB, "read_tree", json!({ "parc": "web3c", "path": "", "extra": 1 })).await;
    assert!(failed || error["code"].is_string() || error.is_object(), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn tags_skip_tags_and_no_limit_belong_to_the_check_gate() {
    let (am_port, _) = fake_alertmanager().await;
    let server = start(am_port).await;
    let api = Api { http: Client::new(), server: &server };
    let launch = |extra: Value| {
        let mut body = json!({ "parc": "web3c", "playbook": "deploy-demo.yml", "limit": ["proxy1"], "detach": true });
        body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        body
    };
    let run = |body: Value| async {
        let (status, started) = api.agent("run_ansible_playbook", body).await;
        assert_eq!(status, StatusCode::OK, "{started}");
        api.wait_run(started["run_id"].as_str().unwrap()).await
    };

    // Grammaire des étiquettes : refus avant tout lancement.
    let long = "a".repeat(65);
    let too_many: Vec<String> = (0..21).map(|i| format!("t{i}")).collect();
    for (extra, label) in [
        (json!({ "check": true, "tags": ["a b"] }), "espace"),
        (json!({ "check": true, "tags": ["a;id"] }), "point-virgule"),
        (json!({ "check": true, "tags": [""] }), "vide"),
        (json!({ "check": true, "skip_tags": [long] }), "trop long"),
        (json!({ "check": true, "tags": too_many }), "trop nombreuses"),
        (json!({ "check": true, "tags": "a" }), "pas une liste"),
        (json!({ "check": true, "no_limit": true }), "no_limit avec limit"),
        (json!({ "check": true, "commit": "HEAD" }), "commit sans arbre git"),
        (json!({ "check": true, "commit": "0123456789abcdef0123456789abcdef01234567" }), "sha sans arbre git"),
    ] {
        let (status, answer) = api.agent("run_ansible_playbook", launch(extra)).await;
        assert!(status.is_client_error() || status.is_server_error(), "{label} : {answer}");
    }
    assert!(api.stub_log().is_empty(), "aucun refus ne doit atteindre ansible-playbook : {}", api.stub_log());

    // Un check avec tags autorise le run réel de CES tags, dans n'importe quel ordre.
    let done = run(launch(json!({ "check": true, "tags": ["b", "a"], "skip_tags": ["slow"] }))).await;
    assert_eq!(done["state"], "success");
    assert_eq!((done["tags"].clone(), done["skip_tags"].clone(), done["commit"].clone()), (json!(["a", "b"]), json!(["slow"]), Value::Null));
    let last = api.stub_log().lines().last().unwrap().to_string();
    assert!(last.contains("--tags=a,b") && last.contains("--skip-tags=slow") && last.contains("--check"), "{last}");

    let done = run(launch(json!({ "tags": ["a", "b", "a"], "skip_tags": ["slow"] }))).await;
    assert_eq!(done["state"], "success");
    let last = api.stub_log().lines().last().unwrap().to_string();
    assert!(last.contains("--tags=a,b") && !last.contains("--check"), "{last}");

    for (extra, label) in [
        (json!({ "tags": ["a"], "skip_tags": ["slow"] }), "autres tags"),
        (json!({ "tags": ["a", "b"] }), "sans skip_tags"),
        (json!({ "tags": ["a", "b"], "skip_tags": ["slow", "x"] }), "autres skip_tags"),
        (json!({ "skip_tags": ["slow"] }), "sans tags"),
    ] {
        let (status, answer) = api.agent("run_ansible_playbook", launch(extra)).await;
        assert_eq!((status, code(&answer)), (StatusCode::CONFLICT, "check_required"), "{label} : {answer}");
    }

    // `no_limit` : aucun --limit, et son propre check.
    let no_limit = |extra: Value| {
        let mut body = launch(extra);
        body.as_object_mut().unwrap().remove("limit");
        body["no_limit"] = json!(true);
        body
    };
    let (_, answer) = api.agent("run_ansible_playbook", no_limit(json!({}))).await;
    assert_eq!(code(&answer), "check_required", "un check avec limit n'autorise pas no_limit");
    run(no_limit(json!({ "check": true }))).await;
    let last = api.stub_log().lines().last().unwrap().to_string();
    assert!(!last.contains("--limit"), "{last}");
    assert_eq!(run(no_limit(json!({}))).await["state"], "success");
    let mut plain = launch(json!({}));
    plain.as_object_mut().unwrap().remove("limit");
    let (_, answer) = api.agent("run_ansible_playbook", plain).await;
    assert_eq!(code(&answer), "check_required", "le check no_limit n'autorise pas l'absence de limit");

    // run_status : recap et échecs, lus de la sortie (le bouchon n'en produit qu'un).
    let failing = run(launch(json!({ "check": true, "playbook": "deploy-fail.yml" }))).await;
    assert_eq!(failing["state"], "failed");
    assert_eq!(failing["failures"][0]["host"], "proxy1", "{failing}");
    assert_eq!(failing["recap"], json!({}), "pas de PLAY RECAP dans cette sortie : {failing}");
}

const DENIED_RUNNER: (&str, &str) = ("autonome", "mot-de-passe-autonome");

#[tokio::test(flavor = "multi_thread")]
async fn deny_playbooks_and_max_hosts_bound_an_account() {
    let (am_port, _) = fake_alertmanager().await;
    let accounts = json!([{
        "user": DENIED_RUNNER.0, "password_hash": hash_with_binary(DENIED_RUNNER.1), "parcs": ["web3c"], "mode": "run",
        "deny_playbooks": ["update-security-*.yml", "*-fleetforge.yml", "deploy-secret.yml"], "max_hosts": 2
    }]);
    let server = start_with(am_port, |root| {
        write_tree_fixture(&root.join("ansible"));
        write(&root.join("ansible/playbooks/deploy-fleetforge.yml"), "---\n- hosts: all\n  tasks: []\n");
        let file = accounts_file(root, accounts);
        vec![("FLEETFORGE_API_ACCOUNTS_FILE".into(), file.display().to_string())]
    })
    .await;
    let api = Api { http: Client::new(), server: &server };
    let run = |playbook: &str, extra: Value| {
        let mut body = json!({ "parc": "web3c", "playbook": playbook, "check": true, "detach": true });
        body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        body
    };

    // Playbooks interdits : par nom, et par ricochet (import_playbook).
    for playbook in ["update-security-ssh.yml", "deploy-fleetforge.yml", "deploy-importer.yml"] {
        let (status, answer) = api.call(DENIED_RUNNER, "run_ansible_playbook", run(playbook, json!({ "limit": ["proxy1"] }))).await;
        assert_eq!((status, code(&answer)), (StatusCode::FORBIDDEN, "forbidden_playbook"), "{playbook} → {answer}");
    }
    // Le compte hérité (sans borne) peut les lancer.
    let (status, _) = api.agent("run_ansible_playbook", run("update-security-ssh.yml", json!({ "limit": ["proxy1"] }))).await;
    assert_eq!(status, StatusCode::OK);
    api.wait_run_any().await;

    // Hôtes : limit obligatoire, no_limit refusé, groupes développés.
    for (extra, label) in [
        (json!({}), "pas de limit"),
        (json!({ "limit": [] }), "limit vide"),
        (json!({ "no_limit": true }), "no_limit"),
        (json!({ "limit": ["all"] }), "all = 3 hôtes"),
        (json!({ "limit": ["proxies", "alertmanager1"] }), "3 hôtes par un groupe et un hôte"),
        (json!({ "limit": ["web3c"] }), "l'organisation = 3 hôtes"),
    ] {
        let (status, answer) = api.call(DENIED_RUNNER, "run_ansible_playbook", run("deploy-demo.yml", extra)).await;
        assert_eq!((status, code(&answer)), (StatusCode::FORBIDDEN, "too_many_hosts"), "{label} → {answer}");
    }
    let (status, answer) = api.call(DENIED_RUNNER, "run_ansible_playbook", run("deploy-demo.yml", json!({ "limit": ["ghost"] }))).await;
    assert_eq!((status, code(&answer)), (StatusCode::NOT_FOUND, "unknown_host"), "{answer}");

    // Deux hôtes (un groupe de deux, ou deux noms) : admis.
    for limit in [json!(["proxies"]), json!(["proxy1", "alertmanager1"]), json!(["proxy1", "proxy1"])] {
        let (status, answer) = api.call(DENIED_RUNNER, "run_ansible_playbook", run("deploy-demo.yml", json!({ "limit": limit }))).await;
        assert_eq!(status, StatusCode::OK, "{limit} → {answer}");
        let done = api.wait_run_as(DENIED_RUNNER, answer["run_id"].as_str().unwrap()).await;
        assert_eq!(done["state"], "success");
    }
    // Et la borne vaut aussi pour le run réel.
    let (_, answer) = api.call(DENIED_RUNNER, "run_ansible_playbook", json!({
        "parc": "web3c", "playbook": "deploy-demo.yml", "limit": ["all"], "detach": true
    })).await;
    assert_eq!(code(&answer), "too_many_hosts", "avant même le check : {answer}");
    // Lectures et description restent ouvertes pour les playbooks interdits.
    let (status, d) = api.call(DENIED_RUNNER, "describe_playbook", json!({ "parc": "web3c", "playbook": "deploy-fleetforge.yml" })).await;
    assert_eq!(status, StatusCode::OK, "{d}");
}

impl Api<'_> {
    /// Attend que plus aucun run n'occupe le parc : un nouveau lancement ne
    /// serait sinon refusé `run_busy`.
    async fn wait_run_any(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let (_, runs) = self.call(OPERATOR, "get_active_runs", json!({})).await;
            if runs.as_array().is_none_or(|r| r.is_empty()) {
                return;
            }
            assert!(Instant::now() < deadline, "runs interminables");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn wait_run_as(&self, who: (&str, &str), run_id: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let (status, body) = self.call(who, "run_status", json!({ "run_id": run_id })).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            if body["state"] != "running" {
                return body;
            }
            assert!(Instant::now() < deadline, "run {run_id} interminable");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// `git` avec une identité fixe, hors des réglages de l'utilisateur.
fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.org")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.org")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?} : {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Dépôt « serveur », clone et données du parc d'un arbre git ; rend les
/// variables d'environnement qui font servir l'arbre depuis git.
fn git_tree_setup(root: &Path) -> Vec<(String, String)> {
    let origin = root.join("origin");
    std::fs::create_dir_all(&origin).unwrap();
    git(&origin, &["init", "-q", "-b", "main"]);
    write(&origin.join("Ansible/ansible.cfg"), "[defaults]\n");
    write(&origin.join("Ansible/playbooks/deploy-demo.yml"), "---\n- hosts: all\n  roles: [demo-install]\n");
    write(&origin.join("Ansible/playbooks/deploy-fail.yml"), "---\n- hosts: all\n  tasks: []\n");
    write(
        &origin.join("Ansible/playbooks/roles/demo-install/tasks/main.yml"),
        "---\n- name: A\n  debug: msg=one\n  tags: [one]\n",
    );
    git(&origin, &["add", "-A"]);
    git(&origin, &["commit", "-q", "-m", "first"]);
    let clone = root.join("ansible-git");
    let out = Command::new("git")
        .args(["clone", "-q", "--no-checkout", "--branch", "main"])
        .arg(&origin)
        .arg(&clone)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let data = root.join("ansible-data");
    write(&data.join("inventories/web3c_inventory.yml"), INVENTORY);
    write(&data.join("playbooks/group_vars/web3c.yml"), "parc_name: web3c\n");
    vec![
        ("FLEETFORGE_ANSIBLE_SOURCE".into(), "git".into()),
        ("FLEETFORGE_ANSIBLE_GIT_DIR".into(), clone.display().to_string()),
        ("FLEETFORGE_ANSIBLE_DATA_DIR".into(), data.display().to_string()),
        ("FLEETFORGE_ANSIBLE_TREES_DIR".into(), root.join("ansible-trees").display().to_string()),
        ("FLEETFORGE_ANSIBLE_CACHE_KEEP".into(), "3".into()),
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn a_git_tree_runs_one_precise_commit() {
    let (am_port, _) = fake_alertmanager().await;
    let server = start_with(am_port, git_tree_setup).await;
    let api = Api { http: Client::new(), server: &server };
    let origin = server.root.join("origin");
    let c1 = git(&origin, &["rev-parse", "HEAD"]);
    let launch = |extra: Value| {
        let mut body = json!({ "parc": "web3c", "playbook": "deploy-demo.yml", "limit": ["proxy1"], "detach": true });
        body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        body
    };

    // ── L'état de l'arbre, relu du clone ──────────────────────────────────
    let (status, tree) = api.agent("tree_status", json!({ "parc": "web3c" })).await;
    assert_eq!(status, StatusCode::OK, "{tree}");
    assert_eq!((tree["source"].clone(), tree["branch"].clone(), tree["head"].clone()), (json!("git"), json!("main"), json!(c1)));
    // L'arbre servi : la tête. Playbooks et inventaire se lisent.
    let (_, playbooks) = api.agent("list_playbooks", json!({})).await;
    assert!(playbooks.as_array().unwrap().iter().any(|p| p["path"] == "deploy-demo.yml"), "{playbooks}");
    let (_, hosts) = api.agent("list_hosts", json!({ "parc": "web3c" })).await;
    assert_eq!(hosts.as_array().unwrap().len(), 3, "{hosts}");
    let (_, file) = api.agent("read_tree", json!({ "parc": "web3c", "path": "roles/demo-install/tasks/main.yml" })).await;
    assert_eq!((file["commit"].clone(), file["content"].as_str().unwrap().contains("tags: [one]")), (json!(c1), true), "{file}");
    // Les données du parc sont liées dans l'arbre, mais ne se lisent pas.
    let (status, answer) = api.agent("read_tree", json!({ "parc": "web3c", "path": "group_vars/web3c.yml" })).await;
    assert_eq!((status, code(&answer)), (StatusCode::FORBIDDEN, "path_refused"));
    let (_, d) = api.agent("describe_playbook", json!({ "parc": "web3c", "playbook": "deploy-demo.yml" })).await;
    assert_eq!((d["commit"].clone(), d["tags"].clone()), (json!(c1), json!(["one"])), "{d}");

    // ── Un run part d'un commit précis, consigné au registre ──────────────
    let (status, started) = api.agent("run_ansible_playbook", launch(json!({ "check": true }))).await;
    assert_eq!(status, StatusCode::OK, "{started}");
    assert_eq!(started["commit"], json!(c1), "la tête synchronisée par défaut");
    let done = api.wait_run(started["run_id"].as_str().unwrap()).await;
    assert_eq!((done["state"].clone(), done["commit"].clone()), (json!("success"), json!(c1)));
    let last = api.stub_log().lines().last().unwrap().to_string();
    let tree_dir = format!("ansible-trees/{}/playbooks/deploy-demo.yml", &c1[..16]);
    assert!(last.contains(&tree_dir), "le playbook vient de l'arbre du commit : {last}");
    assert!(last.contains("ansible-data/inventories/web3c_inventory.yml"), "les inventaires sont les données du parc : {last}");
    assert!(done["output_tail"].as_str().unwrap().contains(&format!("commit {}", &c1[..16])), "{done}");
    let (status, tree) = api.agent("tree_status", json!({ "parc": "web3c" })).await;
    assert_eq!((status, tree["commits_cached"].clone()), (StatusCode::OK, json!(1)), "{tree}");

    // ── Un correctif arrive : la synchronisation avance la tête ───────────
    write(&origin.join("Ansible/playbooks/roles/demo-install/tasks/main.yml"), "---\n- name: A\n  debug: msg=two\n  tags: [two]\n");
    git(&origin, &["commit", "-q", "-am", "second"]);
    let c2 = git(&origin, &["rev-parse", "HEAD"]);
    let (status, synced) = api.agent("sync_tree", json!({ "parc": "web3c" })).await;
    assert_eq!(status, StatusCode::OK, "{synced}");
    assert_eq!((synced["commit"].clone(), synced["head"].clone(), synced["reference"].clone()), (json!(c2), json!(c2), json!("main")));

    // Le check du commit c1 n'autorise pas le run de la nouvelle tête.
    let (status, answer) = api.agent("run_ansible_playbook", launch(json!({}))).await;
    assert_eq!((status, code(&answer)), (StatusCode::CONFLICT, "check_required"), "{answer}");
    // … mais il autorise le run de c1 demandé explicitement.
    let (status, old) = api.agent("run_ansible_playbook", launch(json!({ "commit": c1 }))).await;
    assert_eq!(status, StatusCode::OK, "{old}");
    assert_eq!(api.wait_run(old["run_id"].as_str().unwrap()).await["commit"], json!(c1));
    // `HEAD` est la tête synchronisée : c2, donc son propre check.
    let (_, answer) = api.agent("run_ansible_playbook", launch(json!({ "commit": "HEAD" }))).await;
    assert_eq!(code(&answer), "check_required");
    let (status, check2) = api.agent("run_ansible_playbook", launch(json!({ "commit": "HEAD", "check": true }))).await;
    assert_eq!(status, StatusCode::OK, "{check2}");
    assert_eq!(api.wait_run(check2["run_id"].as_str().unwrap()).await["commit"], json!(c2));
    let (status, real2) = api.agent("run_ansible_playbook", launch(json!({}))).await;
    assert_eq!(status, StatusCode::OK, "le check de la tête autorise le run par défaut : {real2}");
    assert_eq!(api.wait_run(real2["run_id"].as_str().unwrap()).await["commit"], json!(c2));

    // Lecture et description à un commit précis.
    let (_, old_file) = api.agent("read_tree", json!({ "parc": "web3c", "path": "roles/demo-install/tasks/main.yml", "commit": c1 })).await;
    let (_, new_file) = api.agent("read_tree", json!({ "parc": "web3c", "path": "roles/demo-install/tasks/main.yml" })).await;
    assert!(old_file["content"].as_str().unwrap().contains("one") && new_file["content"].as_str().unwrap().contains("two"));
    assert_eq!((old_file["commit"].clone(), new_file["commit"].clone()), (json!(c1), json!(c2)));
    let (_, d) = api.agent("describe_playbook", json!({ "parc": "web3c", "playbook": "deploy-demo.yml", "commit": c1 })).await;
    assert_eq!(d["tags"], json!(["one"]));

    // ── Refus : références, commits, grammaire ────────────────────────────
    for reference in ["dev", "origin/main", "refs/heads/main", "infra/papanglabs/x", "infra/web3c/a/b", "--upload-pack=id"] {
        let (status, answer) = api.agent("sync_tree", json!({ "parc": "web3c", "ref": reference })).await;
        assert_eq!((status, code(&answer)), (StatusCode::FORBIDDEN, "ref_refused"), "{reference} → {answer}");
    }
    git(&origin, &["checkout", "-q", "-b", "side", &c1]);
    write(&origin.join("Ansible/playbooks/deploy-side.yml"), "---\n");
    git(&origin, &["add", "-A"]);
    git(&origin, &["commit", "-q", "-m", "side"]);
    let side = git(&origin, &["rev-parse", "HEAD"]);
    git(&origin, &["checkout", "-q", "main"]);
    for (body, expected) in [
        (json!({ "parc": "web3c", "commit": side }), (StatusCode::NOT_FOUND, "unknown_commit")),
        (json!({ "parc": "web3c", "commit": "0".repeat(40) }), (StatusCode::NOT_FOUND, "unknown_commit")),
        (json!({ "parc": "web3c", "commit": "main" }), (StatusCode::BAD_REQUEST, "invalid_argument")),
        (json!({ "parc": "web3c", "commit": &c1[..10] }), (StatusCode::BAD_REQUEST, "invalid_argument")),
        (json!({ "parc": "web3c", "ref": "infra/web3c/ghost" }), (StatusCode::NOT_FOUND, "unknown_commit")),
    ] {
        let (status, answer) = api.agent("sync_tree", body.clone()).await;
        assert_eq!((status, code(&answer)), expected, "{body} → {answer}");
    }
    for commit in [side.clone(), "0".repeat(40)] {
        let (status, answer) = api.agent("run_ansible_playbook", launch(json!({ "check": true, "commit": commit }))).await;
        assert_eq!((status, code(&answer)), (StatusCode::NOT_FOUND, "unknown_commit"), "{answer}");
        let (status, answer) = api.agent("read_tree", json!({ "parc": "web3c", "path": "", "commit": commit })).await;
        assert_eq!((status, code(&answer)), (StatusCode::NOT_FOUND, "unknown_commit"), "{answer}");
    }

    // ── Une branche de correctif du hub : récupérée, contrôlée, jamais suivie ─
    git(&origin, &["checkout", "-q", "-b", "infra/web3c/fix1", &c2]);
    write(&origin.join("Ansible/playbooks/roles/demo-install/tasks/main.yml"), "---\n- name: A\n  debug: msg=three\n  tags: [three]\n");
    git(&origin, &["commit", "-q", "-am", "fix"]);
    let fix = git(&origin, &["rev-parse", "HEAD"]);
    git(&origin, &["checkout", "-q", "main"]);
    let (status, synced) = api.agent("sync_tree", json!({ "parc": "web3c", "ref": "infra/web3c/fix1" })).await;
    assert_eq!(status, StatusCode::OK, "{synced}");
    assert_eq!((synced["commit"].clone(), synced["head"].clone()), (json!(fix), json!(c2)), "la tête suivie n'a pas bougé");
    let (status, check) = api.agent("syntax_check", json!({ "parc": "web3c", "playbook": "deploy-demo.yml", "commit": fix })).await;
    assert_eq!(status, StatusCode::OK, "{check}");
    assert_eq!((check["ok"].clone(), check["commit"].clone()), (json!(true), json!(fix)));
    assert!(api.stub_log().contains("--syntax-check"));
    let (_, d) = api.agent("describe_playbook", json!({ "parc": "web3c", "playbook": "deploy-demo.yml", "commit": fix })).await;
    assert_eq!(d["tags"], json!(["three"]));
    let (status, checked) = api.agent("run_ansible_playbook", launch(json!({ "check": true, "commit": fix }))).await;
    assert_eq!(status, StatusCode::OK, "{checked}");
    assert_eq!(api.wait_run(checked["run_id"].as_str().unwrap()).await["commit"], json!(fix));
    let (_, tree) = api.agent("tree_status", json!({ "parc": "web3c" })).await;
    assert!(tree["commits_cached"].as_u64().unwrap() <= 4, "cache borné (keep=3, plus la tête) : {tree}");
    let (_, tree) = api.agent("tree_status", json!({ "parc": "web3c" })).await;
    assert_eq!(tree["head"], json!(c2));
}

#[test]
fn a_half_configured_git_tree_refuses_to_start() {
    let root = fresh_root();
    let run = |envs: &[(&str, &str)]| {
        let out = Command::new(env!("CARGO_BIN_EXE_fleetforge-web"))
            .env_clear()
            .env("HOME", &root)
            .env("FLEETFORGE_LOG_DIR", root.join("logs"))
            .env("FLEETFORGE_WEB_PORT", free_port().to_string())
            .env("FLEETFORGE_WEB_USER", OPERATOR.0)
            .env("FLEETFORGE_WEB_PASSWORD", OPERATOR.1)
            .envs(envs.iter().copied())
            .output()
            .unwrap();
        assert!(!out.status.success());
        String::from_utf8_lossy(&out.stderr).to_string()
    };
    assert!(run(&[("FLEETFORGE_ANSIBLE_SOURCE", "git")]).contains("FLEETFORGE_ANSIBLE_GIT_DIR"));
    assert!(run(&[("FLEETFORGE_ANSIBLE_SOURCE", "svn")]).contains("inconnu"));
    let base = [
        ("FLEETFORGE_ANSIBLE_SOURCE", "git"),
        ("FLEETFORGE_ANSIBLE_GIT_DIR", "/nowhere/clone"),
        ("FLEETFORGE_ANSIBLE_DATA_DIR", "/nowhere/data"),
        ("FLEETFORGE_ANSIBLE_TREES_DIR", "/nowhere/trees"),
    ];
    let mut bad_branch = base.to_vec();
    bad_branch.push(("FLEETFORGE_ANSIBLE_BRANCH", "a..b"));
    assert!(run(&bad_branch).contains("nom de branche invalide"));
    let mut bad_keep = base.to_vec();
    bad_keep.push(("FLEETFORGE_ANSIBLE_CACHE_KEEP", "0"));
    assert!(run(&bad_keep).contains("FLEETFORGE_ANSIBLE_CACHE_KEEP"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_flawed_bound_refuses_to_start() {
    let hash = hash_with_binary("x");
    let entry = |extra: Value| {
        let mut e = json!({ "user": "a", "password_hash": hash, "parcs": ["web3c"], "mode": "run" });
        e.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        json!([e])
    };
    refuses_accounts(entry(json!({ "deny_playbooks": ["../x"] })), 0o600, "motif de playbook invalide");
    refuses_accounts(entry(json!({ "deny_playbooks": [""] })), 0o600, "motif de playbook invalide");
    refuses_accounts(entry(json!({ "max_hosts": 0 })), 0o600, "max_hosts");
    refuses_accounts(entry(json!({ "max_hosts": 5000 })), 0o600, "max_hosts");
    refuses_accounts(entry(json!({ "max_hosts": -1 })), 0o600, "comptes illisibles");
}
