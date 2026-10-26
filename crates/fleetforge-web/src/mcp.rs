/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Serveur MCP (Model Context Protocol) sur `/mcp`.
//!
//! Les outils SONT les commandes de l'API d'automatisation, de même nom : un
//! appel d'outil passe par `automation::serve`, exactement comme
//! `POST /api/{commande}`. Validation, `--check` exigé, `run_busy` et
//! caviardage ne sont donc pas réécrits ici, et ne peuvent pas diverger.
//!
//! Toujours sous les règles de l'automatisation ([`Role::Automation`]), quel
//! que soit le compte : un client MCP est un programme, souvent un modèle, et
//! le compte opérateur ne lui ouvre pas la forme permissive du frontal. Le
//! périmètre du compte ([`Scope`]) borne les outils : `tools/list` ne montre
//! que ceux de son mode, et chaque appel est tenu à ses parcs.
//!
//! Transport Streamable HTTP, SANS session (chaque requête est servie seule)
//! et en réponses JSON : rien à tenir en mémoire d'une requête à l'autre, ce
//! qui convient à un serveur derrière un proxy en tourniquet. Le SDK `rmcp`
//! négocie la version du protocole, `initialize` compris.
//!
//! Un refus est une ERREUR D'OUTIL (`isError: true`) dont le texte est le
//! corps d'erreur de l'API REST, `{ "error", "code" }` : le client lit le
//! même code par les deux voies. Seul un nom d'outil inconnu reste une erreur
//! de protocole (-32602), comme le prévoit la spécification.

use axum::http::request::Parts;
use axum::Json;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    JsonObject, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
    ToolAnnotations,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use serde_json::{json, Value};
use std::sync::{Arc, LazyLock};

use crate::api::Params;
use crate::automation;
use crate::config::{Role, Scope};
use crate::state::AppState;

/// Consigne remise au client à l'initialisation.
const INSTRUCTIONS: &str = "\
FleetForge automation API: an Ansible control node for one or more parcs (fleets). \
A parc is designated by its NAME (e.g. web3c), a host by its inventory name. \
Read tools have no side effect. run_ansible_playbook is gated: a real run (check: false) \
is refused with code check_required unless the SAME launch (parc, playbook, limit, \
extra_vars) completed with check: true less than one hour ago, and a parc runs one \
playbook at a time (code run_busy). Outputs are redacted. A refusal is a tool error \
whose text is a JSON object {\"error\": <message>, \"code\": <stable code>}.";

/// Service à monter sur `/mcp`.
///
/// `authenticated` : le serveur exige des identifiants (toute écoute hors
/// boucle locale). Le contrôle de l'en-tête `Host` du SDK — une parade au
/// rebond DNS contre un serveur local SANS authentification — est alors
/// levé : derrière le proxy, `Host` vaut le nom public du service, et un
/// navigateur détourné n'a de toute façon pas les identifiants à présenter.
/// Sans authentification (boucle locale), il reste à son défaut : `localhost`,
/// `127.0.0.1`, `::1`.
pub fn service(state: AppState, authenticated: bool) -> StreamableHttpService<Mcp, NeverSessionManager> {
    let mut config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true);
    if authenticated {
        config = config.disable_allowed_hosts();
    }
    StreamableHttpService::new(
        move || Ok(Mcp { state: state.clone() }),
        Arc::new(NeverSessionManager::default()),
        config,
    )
}

#[derive(Clone)]
pub struct Mcp {
    state: AppState,
}

impl ServerHandler for Mcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("fleetforge", env!("CARGO_PKG_VERSION")).with_title("FleetForge"))
            .with_instructions(INSTRUCTIONS)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let scope = scope_of(&context);
        Ok(ListToolsResult::with_all_items(
            TOOLS.iter().filter(|t| scope.may(&t.name)).cloned().collect(),
        ))
    }

    /// Définition d'un outil, pour la vérification des en-têtes `Mcp-Param-*`
    /// que fait le SDK (protocole 2026-07-28).
    fn get_tool(&self, name: &str) -> Option<Tool> {
        TOOLS.iter().find(|t| t.name == name).cloned()
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let name = request.name.as_ref();
        if !TOOLS.iter().any(|t| t.name == name) {
            return Err(McpError::invalid_params(format!("unknown tool: {name}"), None));
        }
        // Un outil hors du mode du compte est refusé par `serve` même, en
        // erreur d'outil `forbidden` : il existe, ce compte ne l'a pas.
        let scope = scope_of(&context);
        let arguments = Value::Object(request.arguments.unwrap_or_default());
        let params = Params::new(defaults(name, arguments));
        let outcome = automation::serve(&self.state, Role::Automation, &scope, name, &params).await;
        Ok(match outcome {
            Ok(Json(value)) => CallToolResult::success(vec![ContentBlock::text(value.to_string())]),
            Err(e) => CallToolResult::error(vec![ContentBlock::text(
                json!({ "error": e.message(), "code": e.code() }).to_string(),
            )]),
        }
        .into())
    }
}

/// Valeurs par défaut propres au transport.
///
/// `run_ansible_playbook` est DÉTACHÉ par défaut : sans cela la réponse
/// attendrait la fin du playbook — des minutes, au-delà du délai d'attente de
/// la plupart des clients MCP. Le run se suit par `run_status`.
fn defaults(tool: &str, mut arguments: Value) -> Value {
    if tool == "run_ansible_playbook" && arguments.get("detach").is_none_or(Value::is_null) {
        arguments["detach"] = json!(true);
    }
    arguments
}

/// Périmètre du compte de l'appel, déposé par `auth::middleware` dans la
/// requête HTTP que le SDK transmet au gestionnaire. Absent : rien.
fn scope_of(context: &RequestContext<RoleServer>) -> Arc<Scope> {
    context
        .extensions
        .get::<Parts>()
        .and_then(|parts| parts.extensions.get::<Arc<Scope>>())
        .cloned()
        .unwrap_or_else(|| Arc::new(Scope::nothing()))
}

fn schema(value: Value) -> Arc<JsonObject> {
    match value {
        Value::Object(map) => Arc::new(map),
        _ => unreachable!("un schéma d'entrée est un objet"),
    }
}

fn parc_property() -> Value {
    json!({ "type": "string", "description": "Parc (fleet) name, e.g. web3c. Never a file path." })
}

fn read_only(title: &str) -> ToolAnnotations {
    ToolAnnotations::with_title(title).read_only(true).destructive(false).idempotent(true)
}

/// Les outils, dans l'ordre de `auth::AUTOMATION_COMMANDS`.
static TOOLS: LazyLock<Vec<Tool>> = LazyLock::new(|| {
    vec![
        Tool::new(
            "list_hosts",
            "List the inventory hosts of a parc: name, ip (ansible_host, empty when undeclared), \
             SSH port (null = 22), inventory groups, role families (ansible_roles), provider, and \
             monitored (false for a host deliberately left unmonitored: ignore its alerts).",
            schema(json!({
                "type": "object",
                "properties": { "parc": parc_property() },
                "required": ["parc"],
                "additionalProperties": false
            })),
        )
        .with_annotations(read_only("List hosts")),
        Tool::new(
            "list_playbooks",
            "List the playbooks of the Ansible tree: path (to pass to run_ansible_playbook), family \
             (deploy, update, remove, purge, security, monitoring, backup, setup, migrate, other), \
             service, label and description.",
            schema(json!({ "type": "object", "properties": {}, "additionalProperties": false })),
        )
        .with_annotations(read_only("List playbooks")),
        Tool::new(
            "alertmanager_alerts",
            "Active alerts of the parc's Alertmanager, neither silenced nor inhibited, as its API v2 \
             returns them (GET /api/v2/alerts).",
            schema(json!({
                "type": "object",
                "properties": { "parc": parc_property() },
                "required": ["parc"],
                "additionalProperties": false
            })),
        )
        .with_annotations(read_only("Alertmanager alerts")),
        Tool::new(
            "query_prometheus",
            "Instant PromQL query (read-only, /api/v1/query) on the parc's own Prometheus. Only an \
             instant vector is returned: range selectors (x[5m]) and scalars are refused. At most \
             1000 series (truncated: true beyond). Answer: {parc, result: [{metric, timestamp, \
             value}], truncated}.",
            schema(json!({
                "type": "object",
                "properties": {
                    "parc": parc_property(),
                    "query": { "type": "string", "description": "PromQL expression, at most 4096 characters." },
                    "time": {
                        "type": ["string", "number"],
                        "description": "Evaluation time: Unix timestamp or RFC 3339. Default: now."
                    }
                },
                "required": ["parc", "query"],
                "additionalProperties": false
            })),
        )
        .with_annotations(read_only("Query Prometheus")),
        Tool::new(
            "ssh_diagnose",
            "Read-only diagnostic on a host through its ro-gate gateway (forced command, closed verbs, \
             redacted output). Verbs: logs journal [DURATION] [all] | logs unit NAME [DURATION] [all] | \
             logs docker NAME [DURATION] [all], status UNIT, containers, stats, firewall, system, ports, \
             http PORT [PATH]. Without args, verb may carry the whole request (\"logs docker searxng \
             1h\"). Without parc the host is searched in every parc of the account, refused when \
             ambiguous.",
            schema(json!({
                "type": "object",
                "properties": {
                    "host": { "type": "string", "description": "Inventory host name." },
                    "verb": { "type": "string", "description": "ro-gate verb, or the whole request." },
                    "args": { "type": "array", "items": { "type": "string" }, "description": "Verb arguments." },
                    "parc": parc_property()
                },
                "required": ["host", "verb"],
                "additionalProperties": false
            })),
        )
        .with_annotations(read_only("Diagnose a host")),
        Tool::new(
            "run_ansible_playbook",
            "Run a playbook of the Ansible tree on a parc. A real run (check: false) is refused with \
             code check_required unless the SAME launch (parc, playbook, limit, extra_vars) completed \
             with check: true less than one hour ago. One run per parc at a time (code run_busy). \
             limit names hosts or groups of the parc, no pattern; extra_vars values are strings, \
             with no ansible_* variable and no Jinja template. Detached by default: answers {run_id, \
             state: running, check, diff}; follow the run with run_status.",
            schema(json!({
                "type": "object",
                "properties": {
                    "parc": parc_property(),
                    "playbook": { "type": "string", "description": "Playbook path as list_playbooks gives it, e.g. deploy-x.yml." },
                    "limit": { "type": "array", "items": { "type": "string" }, "description": "Hosts or groups of the parc (--limit)." },
                    "extra_vars": {
                        "type": "object",
                        "additionalProperties": { "type": "string" },
                        "description": "Extra variables (-e), string values."
                    },
                    "check": { "type": "boolean", "description": "Dry run (--check). Default false." },
                    "diff": { "type": "boolean", "description": "Show file differences (--diff). Default false." },
                    "detach": { "type": "boolean", "description": "Answer as soon as the run is registered. Default true." },
                    "run_id": { "type": "string", "description": "Run identifier to use. Generated when absent." },
                    "label": { "type": "string", "description": "Label shown in the run registry." }
                },
                "required": ["parc", "playbook"],
                "additionalProperties": false
            })),
        )
        .with_annotations(
            ToolAnnotations::with_title("Run a playbook").read_only(false).destructive(true).idempotent(false),
        ),
        Tool::new(
            "run_status",
            "State of a run (running, success, failed), exit code, start and end times, check and diff \
             flags, and the redacted last lines of its output.",
            schema(json!({
                "type": "object",
                "properties": {
                    "run_id": { "type": "string" },
                    "tail_lines": { "type": "integer", "minimum": 1, "maximum": 500, "description": "Output lines to return. Default 50." }
                },
                "required": ["run_id"],
                "additionalProperties": false
            })),
        )
        .with_annotations(read_only("Run status")),
    ]
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_is_an_automation_command_and_back() {
        let tools: Vec<&str> = TOOLS.iter().map(|t| t.name.as_ref()).collect();
        assert_eq!(tools, crate::auth::AUTOMATION_COMMANDS);
    }

    #[test]
    fn every_tool_declares_an_object_schema() {
        for tool in TOOLS.iter() {
            assert_eq!(tool.input_schema.get("type"), Some(&json!("object")), "{}", tool.name);
            assert!(tool.description.as_deref().is_some_and(|d| !d.is_empty()), "{}", tool.name);
        }
    }

    #[test]
    fn a_playbook_run_is_detached_unless_asked_otherwise() {
        assert_eq!(defaults("run_ansible_playbook", json!({}))["detach"], json!(true));
        assert_eq!(defaults("run_ansible_playbook", json!({ "detach": null }))["detach"], json!(true));
        assert_eq!(defaults("run_ansible_playbook", json!({ "detach": false }))["detach"], json!(false));
        assert!(defaults("list_hosts", json!({})).get("detach").is_none());
    }
}
