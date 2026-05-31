use rusqlite::{Connection};
use anyhow::Result;

pub struct Database {
    conn: Connection
}

#[derive(Debug, Clone)]
pub struct ObservationRow {
    pub user_id: String,
    pub user_name: Option<String>,
    pub user_email: Option<String>,
    pub ip: String,
    pub user_agent: Option<String>,
    pub ja3: Option<String>,
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
    pub hits: i64,
}

impl Database {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        
        conn.pragma_update(None, "journal_mode", &"wal")?;
        conn.pragma_update(None, "synchronous", &"NORMAL")?;
        conn.pragma_update(None, "foreign_keys", &"ON")?;
        
        conn.execute_batch(include_str!("schema.sql"))?;
        Ok(Database { conn})
    }
}
