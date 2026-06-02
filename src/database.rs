use crate::model::Observation;
use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension, params_from_iter};
use std::iter::once;

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
    pub fn open(path: &str, safe_writes: bool) -> Result<Self> {
        let conn = Connection::open(path)?;

        conn.pragma_update(None, "journal_mode", &"wal")?;
        let sync = if safe_writes { "NORMAL" } else { "OFF" };
        conn.pragma_update(None, "synchronous", &sync)?;
        conn.pragma_update(None, "foreign_keys", &"ON")?;

        conn.execute_batch(include_str!("../schema.sql"))?;
        Ok(Database { conn})
    }

    pub fn clear(&mut self) -> Result<()> {
        self.conn.execute_batch(
            "
            DELETE FROM observations;
            DELETE FROM seen_events;
            ",
        )?;
        Ok(())
    }

    pub fn import(&mut self, obs: &[Observation]) -> Result<usize> {
        let tx = self.conn.transaction()?;
        let mut affected = 0usize;
        {
            let mut stmt = tx.prepare(
                r#"
                INSERT INTO observations (
                    user_id, user_name, user_email, ip, user_agent, ja3, action, first_seen, last_seen, hits
                )
                VALUES (
                    ?1, ?2, ?3, ?4, COALESCE(?5, ''), ?6, ?7, ?8, ?8, 1
                )
                ON CONFLICT(
                    user_id, ip, user_agent, action
                )
                DO UPDATE SET
                hits = hits + 1,
                first_seen = MIN(first_seen, excluded.first_seen),
                last_seen = MAX(last_seen, excluded.last_seen),
                user_name = COALESCE(excluded.user_name, user_name),
                user_email = COALESCE(excluded.user_email, user_email),
                ja3 = COALESCE(excluded.ja3, ja3)
                "#,
            )?;
            for o in obs {
                let seen: bool = tx.query_row(
                    "SELECT 1 FROM seen_events WHERE event_id = ?1",
                    params![o.event_id],
                    |_| Ok(()),
                ).optional()?.is_some();
                if seen {
                    continue;
                }
                tx.execute("INSERT INTO seen_events(event_id) VALUES (?1)", params![o.event_id])?;
                stmt.execute(params![
                    o.user_id,
                    o.user_name,
                    o.user_email,
                    o.ip,
                    o.user_agent,
                    o.ja3,
                    o.action,
                    o.seen_at,
                ])?;
                affected += 1;
            }
        }
        tx.commit()?;
        Ok(affected)
    }

    pub fn search_ip(&self, pattern: &str, actions: &[String]) -> Result<Vec<ObservationRow>> {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            return Ok(Vec::new());
        }

        let escaped = escape_like(pattern);
        let like = format!("{escaped}%");

        let mut sql = String::from(
        r#"
        SELECT user_id, MAX(user_name), MAX(user_email), ip, user_agent, MAX(ja3), MIN(first_seen), MAX(last_seen), SUM(hits)
        FROM observations
        WHERE ip like ?1 ESCAPE '\'
        "#,
        );
        if !actions.is_empty() {
            let placeholders = vec!["?"; actions.len()].join(",");
            sql.push_str(&format!(" AND action IN ({placeholders})"));
        }
        sql.push_str(" GROUP BY user_id, ip, user_agent ORDER BY ip, user_id");

        let mut stmt = self.conn.prepare(&sql)?;
        let params_iter = once(like).chain(actions.iter().cloned());
        let rows = stmt
            .query_map(params_from_iter(params_iter), Self::map_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn match_ips(&self, ips: &[String], actions: &[String]) -> Result<Vec<ObservationRow>> {
        if ips.is_empty() {
            return Ok(Vec::new());
        }

        let tx = self.conn.unchecked_transaction()?;
        tx.execute_batch(
            "
            CREATE TEMP TABLE IF NOT EXISTS _needle_ips (ip TEXT PRIMARY KEY);
            DELETE FROM _needle_ips;
            ",
        )?;
        {
            let mut ins = tx.prepare("INSERT OR IGNORE INTO _needle_ips(ip) VALUES (?1)")?;
            for ip in ips {
                ins.execute(params![ip])?;
            }
        }
        let mut sql = String::from(
            r#"
            SELECT o.user_id, MAX(o.user_name), MAX(o.user_email), o.ip, o.user_agent, MAX(o.ja3), MIN(o.first_seen), MAX(o.last_seen), SUM(o.hits)
            FROM observations o
            JOIN _needle_ips n ON o.ip = n.ip
            "#,
        );
        if !actions.is_empty() {
            let placeholders = vec!["?"; actions.len()].join(",");
            sql.push_str(&format!(" WHERE o.action IN ({placeholders})"));
        }
        sql.push_str(" GROUP BY o.user_id, o.ip, o.user_agent ORDER BY o.ip, o.user_id");
        let mut stmt = tx.prepare(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(actions.iter().cloned()), Self::map_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        tx.commit()?;
        Ok(rows)
    }

    pub fn count(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM observations", [], |r| r.get(0))?)
    }

    fn map_row(r: &rusqlite::Row) -> rusqlite::Result<ObservationRow> {
        Ok(ObservationRow {
            user_id: r.get(0)?,
            user_name: r.get(1)?,
            user_email: r.get(2)?,
            ip: r.get(3)?,
            user_agent: r.get(4)?,
            ja3: r.get(5)?,
            first_seen: r.get(6)?,
            last_seen: r.get(7)?,
            hits: r.get(8)?,
        })
    }

    pub fn distinct_actions(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT DISTINCT action FROM observations ORDER BY action",)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for character in s.chars() {
        match character {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(character);
            }
            _ => out.push(character),
        }
    }
    out
}
