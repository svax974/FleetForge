/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const OPENCLAW_BIN = "/usr/local/bin/openclaw";
const MASK = "••••••••";
const STATE_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "state");

function alertFingerprint(alert) {
	const scope = alert.labels.instance || alert.labels.domain || alert.labels.job || "";
	return `${alert.labels.alertname}|${scope}|${alert.labels.severity || ""}`;
}

function readAlertsState(instance) {
	try {
		const raw = fs.readFileSync(path.join(STATE_DIR, `${instance}.json`), "utf8");
		const parsed = JSON.parse(raw);
		return Array.isArray(parsed) ? parsed : [];
	} catch {
		return [];
	}
}

function writeAlertsState(instance, fingerprints) {
	try {
		fs.mkdirSync(STATE_DIR, { recursive: true });
		fs.writeFileSync(path.join(STATE_DIR, `${instance}.json`), JSON.stringify(fingerprints));
	} catch {
		// best-effort; a failed write just means the next run re-diffs from empty
	}
}

function readBody(req) {
	return new Promise((resolve, reject) => {
		let data = "";
		req.on("data", (chunk) => {
			data += chunk;
			if (data.length > 1_000_000) req.destroy(new Error("body too large"));
		});
		req.on("end", () => resolve(data));
		req.on("error", reject);
	});
}

function sendJson(res, status, obj) {
	const body = JSON.stringify(obj);
	res.statusCode = status;
	res.setHeader("Content-Type", "application/json; charset=utf-8");
	res.setHeader("Cache-Control", "no-store");
	res.end(body);
}

function bearerToken(req) {
	const header = req.headers.authorization || "";
	const match = /^Bearer\s+(.+)$/i.exec(header);
	return match ? match[1].trim() : null;
}

function patchConfig(patch) {
	return new Promise((resolve, reject) => {
		const proc = spawn(OPENCLAW_BIN, ["config", "patch", "--stdin"], { stdio: ["pipe", "pipe", "pipe"] });
		let stdout = "";
		let stderr = "";
		proc.stdout.on("data", (chunk) => { stdout += chunk; });
		proc.stderr.on("data", (chunk) => { stderr += chunk; });
		proc.on("error", reject);
		proc.on("close", (code) => {
			if (code === 0) resolve(stdout);
			else reject(new Error(stderr.trim() || stdout.trim() || `openclaw config patch exited with code ${code}`));
		});
		proc.stdin.write(JSON.stringify(patch));
		proc.stdin.end();
	});
}

function renderAdminPage() {
	return `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Prometheus Monitor - Admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 760px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
  h1 { font-size: 1.3rem; } h2 { font-size: 1.05rem; margin-top: 2rem; }
  .instance { border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
  label { display: block; font-size: 0.85rem; color: #444; margin-top: 0.5rem; }
  input { width: 100%; box-sizing: border-box; padding: 0.4rem; margin-top: 0.15rem; border: 1px solid #ccc; border-radius: 4px; }
  button { cursor: pointer; padding: 0.5rem 1rem; border-radius: 6px; border: 1px solid #ccc; background: #f5f5f5; margin-top: 0.5rem; }
  button.primary { background: #2563eb; color: white; border-color: #2563eb; }
  button.danger { background: #fff; color: #b91c1c; border-color: #b91c1c; }
  #status { margin-top: 1rem; font-size: 0.9rem; }
  #needsToken { color: #b91c1c; }
</style>
</head>
<body>
<h1>Prometheus Monitor</h1>
<p id="needsToken" hidden>Ouvre cette page avec le token dans l'URL, ex: <code>#token=...</code></p>
<div id="app" hidden>
  <h2>Instances Prometheus</h2>
  <div id="instances"></div>
  <button id="addInstance" type="button">+ Ajouter une instance</button>

  <h2>Notification (doute / besoin de decision)</h2>
  <label>Canal<input id="notifyChannel" placeholder="telegram"></label>
  <label>Compte<input id="notifyAccount" placeholder="default"></label>
  <label>Destination (chatId)<input id="notifyTo" placeholder="123456789"></label>

  <h2>Rapport email</h2>
  <label>Adresse destinataire des recaps<input id="reportEmail" placeholder="ops@example.com"></label>

  <p><button id="save" class="primary" type="button">Enregistrer</button></p>
  <div id="status"></div>
</div>
<script>
const token = new URLSearchParams(location.hash.slice(1)).get("token");
if (!token) { document.getElementById("needsToken").hidden = false; }
else {
  document.getElementById("app").hidden = false;
  const instancesEl = document.getElementById("instances");
  function instanceRow(name, inst) {
    const div = document.createElement("div");
    div.className = "instance";
    div.innerHTML = \`
      <label>Nom<input class="f-name" value="\${name || ""}" placeholder="web3c"></label>
      <label>URL<input class="f-url" value="\${inst?.url || ""}" placeholder="http://prometheus.example:9090/"></label>
      <label>Utilisateur<input class="f-user" value="\${inst?.username || ""}" placeholder="w3prom"></label>
      <label>Mot de passe (laisser vide = inchange)<input class="f-pass" type="password" placeholder="\${inst?.hasPassword ? "${MASK}" : ""}"></label>
      <button type="button" class="danger f-remove">Supprimer cette instance</button>
    \`;
    div.querySelector(".f-remove").onclick = () => div.remove();
    instancesEl.appendChild(div);
  }
  document.getElementById("addInstance").onclick = () => instanceRow("", {});

  async function api(method, body) {
    const res = await fetch(location.pathname.replace(/\\/admin$/, "/api/config"), {
      method,
      headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
    return data;
  }

  api("GET").then((cfg) => {
    for (const [name, inst] of Object.entries(cfg.instances || {})) instanceRow(name, inst);
    if (Object.keys(cfg.instances || {}).length === 0) instanceRow("", {});
    document.getElementById("notifyChannel").value = cfg.notify?.channel || "telegram";
    document.getElementById("notifyAccount").value = cfg.notify?.accountId || "";
    document.getElementById("notifyTo").value = cfg.notify?.to || "";
    document.getElementById("reportEmail").value = cfg.reportEmail || "";
  }).catch((e) => { document.getElementById("status").textContent = "Erreur de chargement: " + e.message; });

  document.getElementById("save").onclick = async () => {
    const instances = {};
    for (const row of instancesEl.querySelectorAll(".instance")) {
      const name = row.querySelector(".f-name").value.trim();
      if (!name) continue;
      const pass = row.querySelector(".f-pass").value;
      instances[name] = {
        url: row.querySelector(".f-url").value.trim(),
        username: row.querySelector(".f-user").value.trim(),
        ...(pass ? { password: pass } : {})
      };
    }
    const body = {
      instances,
      notify: {
        channel: document.getElementById("notifyChannel").value.trim() || "telegram",
        accountId: document.getElementById("notifyAccount").value.trim(),
        to: document.getElementById("notifyTo").value.trim()
      },
      reportEmail: document.getElementById("reportEmail").value.trim()
    };
    const statusEl = document.getElementById("status");
    statusEl.textContent = "Enregistrement...";
    try {
      await api("POST", body);
      statusEl.textContent = "Enregistre. Redemarre le gateway pour appliquer (openclaw daemon restart).";
    } catch (e) {
      statusEl.textContent = "Erreur: " + e.message;
    }
  };
}
</script>
</body>
</html>`;
}

export default {
	id: "prometheus-monitor",
	name: "Prometheus Monitor",
	description: "Query configured Prometheus instances (alerts, PromQL, targets) with server-side Basic Auth.",
	register(api) {
		// OpenClaw >= 2026.10 exige {content:[...]} ; les retours bruts sont enveloppés.
		const rawRegisterTool = api.registerTool.bind(api);
		api.registerTool = (tool) => rawRegisterTool({
			...tool,
			async execute(...args) {
				const r = await tool.execute(...args);
				if (Array.isArray(r?.content)) return r;
				return { content: [{ type: "text", text: JSON.stringify(r) }], details: r };
			}
		});
		function cfg() {
			return api.pluginConfig ?? {};
		}

		function instanceConfig(name) {
			const inst = cfg().instances?.[name];
			if (!inst) {
				const known = Object.keys(cfg().instances ?? {}).join(", ") || "none";
				throw new Error(`Unknown Prometheus instance "${name}". Configured instances: ${known}`);
			}
			return inst;
		}

		async function promFetch(instanceName, path, searchParams) {
			const inst = instanceConfig(instanceName);
			const base = inst.url.endsWith("/") ? inst.url : `${inst.url}/`;
			const url = new URL(path, base);
			if (searchParams) {
				for (const [key, value] of Object.entries(searchParams)) {
					if (value != null) url.searchParams.set(key, String(value));
				}
			}
			const headers = {};
			if (inst.username) {
				headers.Authorization = `Basic ${Buffer.from(`${inst.username}:${inst.password ?? ""}`).toString("base64")}`;
			}
			let res;
			try {
				res = await fetch(url, { headers });
			} catch (error) {
				return { ok: false, status: 0, error: `network error: ${error?.message ?? error}` };
			}
			const text = await res.text();
			let json = null;
			try {
				json = JSON.parse(text);
			} catch {
				// non-JSON body, fall through
			}
			if (!res.ok) {
				return { ok: false, status: res.status, error: json?.error ?? text.slice(0, 500) };
			}
			return { ok: true, status: res.status, data: json?.data ?? json };
		}

		api.registerTool({
			name: "prometheus_instances",
			description: "List the configured Prometheus instance names (parks).",
			parameters: { type: "object", properties: {}, additionalProperties: false },
			async execute() {
				return { instances: Object.keys(cfg().instances ?? {}) };
			}
		});

		api.registerTool({
			name: "prometheus_alerts",
			description: "List active alerts for a configured Prometheus instance (park).",
			parameters: {
				type: "object",
				properties: { instance: { type: "string", description: "Configured instance name, e.g. web3c" } },
				required: ["instance"],
				additionalProperties: false
			},
			async execute(_id, params) {
				return promFetch(params.instance, "api/v1/alerts");
			}
		});

		api.registerTool({
			name: "prometheus_alerts_diff",
			description: "List active alerts for a configured Prometheus instance, plus what changed (added/resolved) since the last call for that instance. Use this instead of prometheus_alerts for periodic/scheduled checks so you can skip notifying when nothing changed.",
			parameters: {
				type: "object",
				properties: { instance: { type: "string", description: "Configured instance name, e.g. web3c" } },
				required: ["instance"],
				additionalProperties: false
			},
			async execute(_id, params) {
				const result = await promFetch(params.instance, "api/v1/alerts");
				if (!result.ok) return result;
				const alerts = result.data?.alerts ?? [];
				const currentFingerprints = alerts.map(alertFingerprint);
				const previousFingerprints = readAlertsState(params.instance);
				const previousSet = new Set(previousFingerprints);
				const currentSet = new Set(currentFingerprints);
				const added = [...currentSet].filter((f) => !previousSet.has(f));
				const resolved = [...previousSet].filter((f) => !currentSet.has(f));
				writeAlertsState(params.instance, currentFingerprints);
				return {
					ok: true,
					changed: added.length > 0 || resolved.length > 0,
					current: alerts,
					added,
					resolved
				};
			}
		});

		api.registerTool({
			name: "prometheus_query",
			description: "Run a PromQL instant query, or a range query when start/end are given, against a configured Prometheus instance.",
			parameters: {
				type: "object",
				properties: {
					instance: { type: "string", description: "Configured instance name, e.g. web3c" },
					query: { type: "string", description: "PromQL expression" },
					start: { type: "string", description: "RFC3339 timestamp or unix seconds; enables a range query" },
					end: { type: "string", description: "RFC3339 timestamp or unix seconds; enables a range query" },
					step: { type: "string", description: "Range query step, e.g. 30s or 1m (default 60s)" }
				},
				required: ["instance", "query"],
				additionalProperties: false
			},
			async execute(_id, params) {
				const { instance, query, start, end, step } = params;
				if (start && end) {
					return promFetch(instance, "api/v1/query_range", { query, start, end, step: step ?? "60s" });
				}
				return promFetch(instance, "api/v1/query", { query });
			}
		});

		api.registerTool({
			name: "prometheus_targets",
			description: "List scrape targets and their health for a configured Prometheus instance.",
			parameters: {
				type: "object",
				properties: {
					instance: { type: "string", description: "Configured instance name, e.g. web3c" },
					state: { type: "string", enum: ["active", "dropped", "any"], description: "Filter by target state (default active)" }
				},
				required: ["instance"],
				additionalProperties: false
			},
			async execute(_id, params) {
				return promFetch(params.instance, "api/v1/targets", params.state ? { state: params.state } : undefined);
			}
		});

		api.registerTool({
			name: "prometheus_settings",
			description: "Return the configured notification channel/target and report email for infra alerts (no secrets).",
			parameters: { type: "object", properties: {}, additionalProperties: false },
			async execute() {
				return { notify: cfg().notify ?? {}, reportEmail: cfg().reportEmail ?? "" };
			}
		});

		api.registerHttpRoute({
			path: "/plugins/prometheus-monitor/admin",
			auth: "plugin",
			match: "exact",
			async handler(_req, res) {
				res.statusCode = 200;
				res.setHeader("Content-Type", "text/html; charset=utf-8");
				res.setHeader("Cache-Control", "no-store");
				res.end(renderAdminPage());
				return true;
			}
		});

		api.registerHttpRoute({
			path: "/plugins/prometheus-monitor/api/config",
			auth: "plugin",
			match: "exact",
			async handler(req, res) {
				const adminToken = cfg().adminToken;
				if (!adminToken || bearerToken(req) !== adminToken) {
					sendJson(res, 401, { error: "unauthorized" });
					return true;
				}
				const method = (req.method ?? "GET").toUpperCase();
				if (method === "GET") {
					const instances = {};
					for (const [name, inst] of Object.entries(cfg().instances ?? {})) {
						instances[name] = { url: inst.url ?? "", username: inst.username ?? "", hasPassword: Boolean(inst.password) };
					}
					sendJson(res, 200, { instances, notify: cfg().notify ?? {}, reportEmail: cfg().reportEmail ?? "" });
					return true;
				}
				if (method === "POST") {
					let body;
					try {
						body = JSON.parse(await readBody(req));
					} catch {
						sendJson(res, 400, { error: "invalid JSON body" });
						return true;
					}
					const existing = cfg().instances ?? {};
					const instances = {};
					for (const [name, inst] of Object.entries(body.instances ?? {})) {
						if (!inst || typeof inst !== "object" || !inst.url) continue;
						instances[name] = {
							url: String(inst.url),
							username: String(inst.username ?? ""),
							password: inst.password ? String(inst.password) : (existing[name]?.password ?? "")
						};
					}
					const patch = {
						plugins: { entries: { "prometheus-monitor": { config: {
							instances,
							notify: {
								channel: String(body.notify?.channel ?? "telegram"),
								accountId: String(body.notify?.accountId ?? ""),
								to: String(body.notify?.to ?? "")
							},
							reportEmail: String(body.reportEmail ?? "")
						} } } }
					};
					try {
						await patchConfig(patch);
						sendJson(res, 200, { ok: true });
					} catch (error) {
						sendJson(res, 500, { error: error?.message ?? String(error) });
					}
					return true;
				}
				res.setHeader("Allow", "GET, POST");
				sendJson(res, 405, { error: "method not allowed" });
				return true;
			}
		});
	}
};
