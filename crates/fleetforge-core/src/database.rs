use crate::models::*;
use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::PathBuf;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new() -> Result<Self> {
        let db_path = Self::get_db_path()?;
        let conn = Connection::open(db_path)?;
        
        let db = Database { conn };
        db.init_tables()?;
        Ok(db)
    }

    fn get_db_path() -> Result<PathBuf> {
        let mut path = crate::paths::data_dir();
        std::fs::create_dir_all(&path)?;
        path.push("database.db");
        Ok(path)
    }

    fn init_tables(&self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                username TEXT NOT NULL,
                auth_type TEXT NOT NULL,
                password TEXT,
                private_key_path TEXT,
                sudo_password TEXT,
                description TEXT,
                is_local INTEGER NOT NULL DEFAULT 0
            )",
            [],
        )?;
        
        // Migration: ajouter sudo_password si la colonne n'existe pas
        let _ = self.conn.execute(
            "ALTER TABLE servers ADD COLUMN sudo_password TEXT",
            [],
        );

        // Désactiver temporairement les contraintes de clés étrangères
        self.conn.execute("PRAGMA foreign_keys = OFF", [])?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS models (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ollama_name TEXT NOT NULL,
                description TEXT,
                size_gb REAL,
                parameters TEXT,
                context_window INTEGER,
                is_predefined INTEGER DEFAULT 0,
                category TEXT,
                requires_auth INTEGER DEFAULT 0,
                icon TEXT,
                created_at TEXT,
                updated_at TEXT
            )",
            [],
        )?;
        
        // Migrations pour les anciennes colonnes
        let _ = self.conn.execute("ALTER TABLE models ADD COLUMN ollama_name TEXT", []);
        let _ = self.conn.execute("ALTER TABLE models ADD COLUMN size_gb REAL", []);
        let _ = self.conn.execute("ALTER TABLE models ADD COLUMN context_window INTEGER", []);
        let _ = self.conn.execute("ALTER TABLE models ADD COLUMN is_predefined INTEGER DEFAULT 0", []);
        let _ = self.conn.execute("ALTER TABLE models ADD COLUMN category TEXT", []);
        let _ = self.conn.execute("ALTER TABLE models ADD COLUMN requires_auth INTEGER DEFAULT 0", []);
        let _ = self.conn.execute("ALTER TABLE models ADD COLUMN icon TEXT", []);
        let _ = self.conn.execute("ALTER TABLE models ADD COLUMN created_at TEXT", []);
        let _ = self.conn.execute("ALTER TABLE models ADD COLUMN updated_at TEXT", []);

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS deployments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_id INTEGER,
                server_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                deployed_at TEXT,
                port INTEGER,
                endpoint_url TEXT,
                model_name TEXT,
                server_name TEXT,
                FOREIGN KEY (server_id) REFERENCES servers(id)
            )",
            [],
        )?;
        
        // Migration: ajouter model_name et server_name si les colonnes n'existent pas
        let _ = self.conn.execute(
            "ALTER TABLE deployments ADD COLUMN model_name TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE deployments ADD COLUMN server_name TEXT",
            [],
        );

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS ansible_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                inventory TEXT NOT NULL,
                roles TEXT NOT NULL,
                hosts TEXT NOT NULL,
                status TEXT NOT NULL,
                output TEXT NOT NULL DEFAULT '',
                started_at TEXT NOT NULL,
                finished_at TEXT
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS server_services (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id       INTEGER NOT NULL,
                server_name     TEXT NOT NULL,
                service_name    TEXT NOT NULL,
                action          TEXT NOT NULL,
                source          TEXT NOT NULL,
                role_name       TEXT,
                ansible_run_id  INTEGER,
                status          TEXT NOT NULL,
                executed_at     TEXT NOT NULL,
                notes           TEXT,
                FOREIGN KEY (server_id) REFERENCES servers(id)
            )",
            [],
        )?;

        Ok(())
    }
    
    /// Initialise les modèles prédéfinis dans la base de données
    pub fn seed_predefined_models(&self) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        
        // Liste des modèles prédéfinis
        let predefined = vec![
            ("Phi-3 Mini 4K Instruct", "phi3", "Modèle compact de Microsoft, excellent pour les tâches de raisonnement et de code avec une fenêtre de contexte de 4K tokens.", 2.3, "3.8B", 4096, "Small", 0, "🔷"),
            ("LLaMA 3 8B Instruct", "llama3", "Modèle polyvalent de Meta, excellent équilibre entre performance et taille pour la plupart des tâches.", 4.7, "8B", 8192, "Medium", 0, "🦙"),
            ("Mistral 7B Instruct v0.2", "mistral", "Modèle performant de Mistral AI, excellent pour le raisonnement et les tâches générales.", 4.1, "7B", 8192, "Medium", 0, "🌪️"),
            ("Gemma 2B Instruct", "gemma:2b", "Modèle ultra-léger de Google, idéal pour les déploiements avec ressources limitées.", 1.4, "2B", 8192, "Small", 0, "💎"),
            ("CodeLlama 7B", "codellama", "Modèle spécialisé pour la génération et la complétion de code.", 3.8, "7B", 16384, "Medium", 0, "💻"),
            ("Neural Chat 7B", "neural-chat", "Modèle conversationnel optimisé pour les dialogues naturels.", 4.1, "7B", 8192, "Medium", 0, "💬"),
            ("Qwen 2.5 Coder 7B", "qwen2.5-coder:7b", "Modèle orienté code de 7B paramètres offrant une complétion précise et du debugging.", 4.3, "7B", 16384, "Medium", 0, "🐉"),
            ("DeepSeek Coder 6.7B", "deepseek-coder:6.7b", "Modèle de 6.7B paramètres très performant pour l'analyse et la génération de code.", 3.9, "6.7B", 16384, "Medium", 0, "🧠"),
            ("Phi-3.5 Mini 3.8B", "phi3.5:mini", "Nouvelle itération Phi 3.5 (3.8B) adaptée aux agents légers et au raisonnement rapide.", 2.5, "3.8B", 8192, "Small", 0, "✨"),
        ];
        
        for (name, ollama_name, desc, size, params, context, category, auth, icon) in predefined {
            let existing_id: Option<i64> = self
                .conn
                .query_row(
                    "SELECT id FROM models WHERE ollama_name = ?1 AND is_predefined = 1",
                    [ollama_name],
                    |row| row.get(0),
                )
                .optional()?;

            if let Some(id) = existing_id {
                let updated_at = chrono::Utc::now().to_rfc3339();
                self.conn.execute(
                    "UPDATE models SET name = ?1, description = ?2, size_gb = ?3, parameters = ?4, 
                                      context_window = ?5, category = ?6, requires_auth = ?7, icon = ?8, 
                                      is_predefined = 1, updated_at = ?9
                     WHERE id = ?10",
                    params![
                        name,
                        desc,
                        size,
                        params,
                        context,
                        category,
                        auth,
                        icon,
                        &updated_at,
                        id
                    ],
                )?;
            } else {
                self.conn.execute(
                    "INSERT INTO models (name, ollama_name, description, size_gb, parameters, 
                                        context_window, is_predefined, category, requires_auth, icon, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8, ?9, ?10)",
                    params![
                        name,
                        ollama_name,
                        desc,
                        size,
                        params,
                        context,
                        category,
                        auth,
                        icon,
                        &now
                    ],
                )?;
            }
        }
        
        Ok(())
    }

    // Gestion des modèles
    pub fn get_models(&self) -> Result<Vec<Model>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, ollama_name, description, size_gb, parameters, context_window, 
                    is_predefined, category, requires_auth, icon, created_at, updated_at
             FROM models"
        )?;

        let models = stmt.query_map([], |row| {
            Ok(Model {
                id: Some(row.get(0)?),
                name: row.get(1)?,
                ollama_name: row.get(2)?,
                description: row.get(3)?,
                size_gb: row.get(4)?,
                parameters: row.get(5)?,
                context_window: row.get(6)?,
                is_predefined: row.get::<_, i64>(7)? == 1,
                category: row.get(8)?,
                requires_auth: row.get::<_, i64>(9)? == 1,
                icon: row.get(10)?,
                created_at: row.get(11)?,
                updated_at: row.get(12)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

        Ok(models)
    }

    pub fn get_model_by_id(&self, id: i64) -> Result<Model> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, ollama_name, description, size_gb, parameters, context_window, 
                    is_predefined, category, requires_auth, icon, created_at, updated_at
             FROM models WHERE id = ?"
        )?;

        let model = stmt.query_row([id], |row| {
            Ok(Model {
                id: Some(row.get(0)?),
                name: row.get(1)?,
                ollama_name: row.get(2)?,
                description: row.get(3)?,
                size_gb: row.get(4)?,
                parameters: row.get(5)?,
                context_window: row.get(6)?,
                is_predefined: row.get::<_, i64>(7)? == 1,
                category: row.get(8)?,
                requires_auth: row.get::<_, i64>(9)? == 1,
                icon: row.get(10)?,
                created_at: row.get(11)?,
                updated_at: row.get(12)?,
            })
        })?;

        Ok(model)
    }

    pub fn add_model(&self, model: Model) -> Result<Model> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO models (name, ollama_name, description, size_gb, parameters, context_window,
                               is_predefined, category, requires_auth, icon, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                model.name,
                model.ollama_name,
                model.description,
                model.size_gb,
                model.parameters,
                model.context_window,
                if model.is_predefined { 1 } else { 0 },
                model.category,
                if model.requires_auth { 1 } else { 0 },
                model.icon,
                &now
            ],
        )?;

        let id = self.conn.last_insert_rowid();
        Ok(Model {
            id: Some(id),
            created_at: Some(now),
            ..model
        })
    }

    pub fn update_model(&self, model: Model) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE models SET name = ?1, ollama_name = ?2, description = ?3, size_gb = ?4,
                              parameters = ?5, context_window = ?6, category = ?7, 
                              requires_auth = ?8, icon = ?9, updated_at = ?10
             WHERE id = ?11",
            params![
                model.name,
                model.ollama_name,
                model.description,
                model.size_gb,
                model.parameters,
                model.context_window,
                model.category,
                if model.requires_auth { 1 } else { 0 },
                model.icon,
                &now,
                model.id
            ],
        )?;
        Ok(())
    }

    pub fn delete_model(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM models WHERE id = ?1", params![id])?;
        Ok(())
    }

    // Ansible runs
    pub fn add_ansible_run(&self, run: AnsibleRun) -> Result<AnsibleRun> {
        self.conn.execute(
            "INSERT INTO ansible_runs (inventory, roles, hosts, status, output, started_at, finished_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                run.inventory,
                serde_json::to_string(&run.roles)?,
                serde_json::to_string(&run.hosts)?,
                run.status,
                run.output,
                run.started_at,
                run.finished_at
            ],
        )?;
        let id = self.conn.last_insert_rowid();
        Ok(AnsibleRun { id: Some(id), ..run })
    }

    pub fn update_ansible_run(&self, run: &AnsibleRun) -> Result<()> {
        self.conn.execute(
            "UPDATE ansible_runs SET status = ?1, output = ?2, finished_at = ?3 WHERE id = ?4",
            params![run.status, run.output, run.finished_at, run.id],
        )?;
        Ok(())
    }

    pub fn get_ansible_runs(&self) -> Result<Vec<AnsibleRun>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, inventory, roles, hosts, status, output, started_at, finished_at
             FROM ansible_runs ORDER BY id DESC LIMIT 50"
        )?;
        let runs = stmt.query_map([], |row| {
            let roles_str: String = row.get(2)?;
            let hosts_str: String = row.get(3)?;
            Ok(AnsibleRun {
                id: Some(row.get(0)?),
                inventory: row.get(1)?,
                roles: serde_json::from_str(&roles_str).unwrap_or_default(),
                hosts: serde_json::from_str(&hosts_str).unwrap_or_default(),
                status: row.get(4)?,
                output: row.get(5)?,
                started_at: row.get(6)?,
                finished_at: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
        Ok(runs)
    }

    pub fn get_ansible_run_by_id(&self, id: i64) -> Result<AnsibleRun> {
        let mut stmt = self.conn.prepare(
            "SELECT id, inventory, roles, hosts, status, output, started_at, finished_at
             FROM ansible_runs WHERE id = ?"
        )?;
        let run = stmt.query_row([id], |row| {
            let roles_str: String = row.get(2)?;
            let hosts_str: String = row.get(3)?;
            Ok(AnsibleRun {
                id: Some(row.get(0)?),
                inventory: row.get(1)?,
                roles: serde_json::from_str(&roles_str).unwrap_or_default(),
                hosts: serde_json::from_str(&hosts_str).unwrap_or_default(),
                status: row.get(4)?,
                output: row.get(5)?,
                started_at: row.get(6)?,
                finished_at: row.get(7)?,
            })
        })?;
        Ok(run)
    }

    // App settings
    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let result: Option<String> = self.conn
            .query_row("SELECT value FROM app_settings WHERE key = ?1", [key], |row| row.get(0))
            .optional()?;
        Ok(result)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO app_settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2",
            params![key, value],
        )?;
        Ok(())
    }

    // Server services — audit log
    pub fn add_server_service(&self, svc: ServerService) -> Result<ServerService> {
        self.conn.execute(
            "INSERT INTO server_services (server_id, server_name, service_name, action, source,
                                          role_name, ansible_run_id, status, executed_at, notes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                svc.server_id,
                svc.server_name,
                svc.service_name,
                svc.action,
                svc.source,
                svc.role_name,
                svc.ansible_run_id,
                svc.status,
                svc.executed_at,
                svc.notes
            ],
        )?;
        let id = self.conn.last_insert_rowid();
        Ok(ServerService { id: Some(id), ..svc })
    }

    pub fn get_server_services(
        &self,
        server_id: Option<i64>,
        service_name: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<ServerService>> {
        let mut query = String::from(
            "SELECT id, server_id, server_name, service_name, action, source,
                    role_name, ansible_run_id, status, executed_at, notes
             FROM server_services WHERE 1=1"
        );
        if server_id.is_some() { query.push_str(" AND server_id = ?1"); }
        if service_name.is_some() { query.push_str(" AND service_name LIKE ?2"); }
        if status.is_some() { query.push_str(" AND status = ?3"); }
        query.push_str(" ORDER BY id DESC LIMIT 500");

        let mut stmt = self.conn.prepare(&query)?;
        let mapper = |row: &rusqlite::Row| -> rusqlite::Result<ServerService> {
            Ok(ServerService {
                id: Some(row.get(0)?),
                server_id: row.get(1)?,
                server_name: row.get(2)?,
                service_name: row.get(3)?,
                action: row.get(4)?,
                source: row.get(5)?,
                role_name: row.get(6)?,
                ansible_run_id: row.get(7)?,
                status: row.get(8)?,
                executed_at: row.get(9)?,
                notes: row.get(10)?,
            })
        };

        let services = match (server_id, service_name, status) {
            (Some(sid), Some(sname), Some(st)) => stmt.query_map(params![sid, format!("%{}%", sname), st], mapper)?,
            (Some(sid), Some(sname), None)     => stmt.query_map(params![sid, format!("%{}%", sname)], mapper)?,
            (Some(sid), None, Some(st))        => stmt.query_map(params![sid, st], mapper)?,
            (Some(sid), None, None)            => stmt.query_map(params![sid], mapper)?,
            (None, Some(sname), Some(st))      => stmt.query_map(params![sname, st], mapper)?,
            (None, Some(sname), None)          => stmt.query_map(params![sname], mapper)?,
            (None, None, Some(st))             => stmt.query_map(params![st], mapper)?,
            (None, None, None)                 => stmt.query_map([], mapper)?,
        };
        services.collect::<Result<Vec<_>, _>>().map_err(|e| anyhow::anyhow!(e))
    }

    pub fn get_server_current_services(&self, server_id: Option<i64>) -> Result<Vec<ServerServiceState>> {
        let base = "SELECT s.server_id, s.server_name, s.service_name, s.action, s.source,
                           s.role_name, s.ansible_run_id, s.executed_at
                    FROM server_services s
                    INNER JOIN (
                        SELECT server_id, service_name, MAX(id) as max_id
                        FROM server_services
                        GROUP BY server_id, service_name
                    ) latest ON s.id = latest.max_id
                    WHERE s.action NOT IN ('remove', 'purge') AND s.status = 'success'";

        let rows = if let Some(sid) = server_id {
            let query = format!("{} AND s.server_id = ?1", base);
            let mut stmt = self.conn.prepare(&query)?;
            let result = stmt.query_map(params![sid], |row| {
                Ok(ServerServiceState {
                    server_id: row.get(0)?,
                    server_name: row.get(1)?,
                    service_name: row.get(2)?,
                    last_action: row.get(3)?,
                    last_source: row.get(4)?,
                    last_role_name: row.get(5)?,
                    last_ansible_run_id: row.get(6)?,
                    installed_at: row.get(7)?,
                })
            })?.collect::<Result<Vec<_>, _>>()?;
            result
        } else {
            let mut stmt = self.conn.prepare(base)?;
            let result = stmt.query_map([], |row| {
                Ok(ServerServiceState {
                    server_id: row.get(0)?,
                    server_name: row.get(1)?,
                    service_name: row.get(2)?,
                    last_action: row.get(3)?,
                    last_source: row.get(4)?,
                    last_role_name: row.get(5)?,
                    last_ansible_run_id: row.get(6)?,
                    installed_at: row.get(7)?,
                })
            })?.collect::<Result<Vec<_>, _>>()?;
            result
        };
        Ok(rows)
    }
}
