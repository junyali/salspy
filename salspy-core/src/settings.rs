use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs::{read_to_string, create_dir_all, write};

const KEYRING_SERVICE: &str = "salspy";
const KEYRING_USER: &str = "postgres_password";
const CONFIG_FILE: &str = "settings.toml";
const DEFAULT_DB_NAME: &str = "audit.db";

#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(default)]
pub struct Settings {
    pub backend: String,
    pub db_folder: String,
    pub db_name: String,
    pub safe_writes: bool,
    pub batch_size: usize,
    pub postgres_host: String,
    pub postgres_port: String,
    pub postgres_user: String,
    pub postgres_dbname: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            backend: "sqlite".to_string(),
            db_folder: String::new(),
            db_name: "audit.db".to_string(),
            safe_writes: true,
            batch_size: 10_000,
            postgres_host: "localhost".to_string(),
            postgres_port: "5432".to_string(),
            postgres_user: "postgres".to_string(),
            postgres_dbname: "audit".to_string(),
        }
    }
}

impl Settings {
    fn config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("salgui").join(CONFIG_FILE))
    }

    pub fn load() -> Self {
        let Some(path) = Self::config_path() else {
            return Settings::default();
        };
        match read_to_string(&path) {
            Ok(text) => toml::from_str(&text).unwrap_or_default(),
            Err(_) => Settings::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Self::config_path().ok_or_else(|| "Could not resolve config directory".to_string())?;
        if let Some(parent) = path.parent() {
            create_dir_all(parent).map_err(|e| format!("Creating config dir: {e}"))?;
        }
        let text = toml::to_string_pretty(self).map_err(|e| format!("Serialising settings: {e}"))?;
        write(&path, text).map_err(|e| format!("Writing settings: {e}"))
    }

    pub fn load_password() -> String {
        match keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER) {
            Ok(entry) => entry.get_password().unwrap_or_default(),
            Err(_) => String::new(),
        }
    }

    pub fn save_password(password: &str) -> Result<(), String> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER).map_err(|e| format!("Keyring entry: {e}"))?;
        if password.is_empty() {
            let _ = entry.delete_credential();
            Ok(())
        } else {
            entry.set_password(password).map_err(|e| format!("Keyring save {e}"))
        }
    }
}

fn compose_db_path(folder: &str, name: &str) -> String {
    let name = if name.trim().is_empty() { DEFAULT_DB_NAME } else { name.trim() };
    if folder.trim().is_empty() {
        name.to_string()
    } else {
        Path::new(folder).join(name).to_string_lossy().to_string()
    }
}

fn compose_postgres_connection(host: &str, port: &str, user: &str, password: &str, dbname: &str) -> String {
    let host = if host.trim().is_empty() { "localhost" } else { host.trim() };
    let port = if port.trim().is_empty() { "5432" } else { port.trim() };
    let user = if user.trim().is_empty() { "postgres" } else { user.trim() };
    let dbname = if dbname.trim().is_empty() { "audit" } else { dbname.trim() };
    let mut s = format!("host={host} port={port} user={user} dbname={dbname}");
    if !password.trim().is_empty() {
        s.push_str(&format!(" password={}", password.trim()));
    }
    s
}
