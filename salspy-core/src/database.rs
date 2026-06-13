use crate::model::Observation;
use anyhow::{Context, Result};
use rusqlite::{params, Connection, params_from_iter};
use postgres::{Client as PgClient, NoTls, types::ToSql};
use std::iter::once;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::{HashSet, HashMap};

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

const SQLITE_SCHEMA: &str = include_str!("../../schemas/schema_sqlite.sql");
const PG_SCHEMA: &str = include_str!("../../schemas/schema_postgres.sql");

#[derive(Clone)]
pub enum DbSpec {
    Sqlite { path: String, safe_writes: bool },
    Postgres { host: String, port: u16, user: String, password: String, dbname: String },
}

pub enum Database {
    Sqlite(Connection),
    Postgres(PgClient),
}

impl Database {
    pub fn open(spec: &DbSpec) -> Result<Self> {
        match spec {
            DbSpec::Sqlite { path, safe_writes } => {
                let conn = Connection::open(path).with_context(|| format!("opening SQLite db at {path}"))?;
                conn.pragma_update(None, "journal_mode", &"wal")?;
                let sync = if *safe_writes { "NORMAL" } else { "OFF" };
                conn.pragma_update(None, "synchronous", &sync)?;
                conn.pragma_update(None, "foreign_keys", &"ON")?;
                conn.execute_batch(SQLITE_SCHEMA)?;
                Ok(Database::Sqlite(conn))
            }
            DbSpec::Postgres { host, port, user, password, dbname } => {
                let mut cfg = postgres::Config::new();
                cfg.host(host).port(*port).user(user).dbname(dbname);
                if !password.is_empty() {
                    cfg.password(password);
                }
                let mut client = cfg.connect(NoTls).with_context(|| format!("connecting to PostgreSQL db {user}@{host}:{port}/{dbname}"))?;
                client.batch_execute(PG_SCHEMA)?;
                Ok(Database::Postgres(client))
            }
        }
    }

    pub fn clear(&mut self) -> Result<()> {
        match self {
            Database::Sqlite(conn) => {
                conn.execute_batch("DELETE FROM observations; DELETE FROM seen_events;")?;
            }
            Database::Postgres(client) => {
                client.batch_execute("DELETE FROM observations; DELETE FROM seen_events;")?;
            }
        }
        Ok(())
    }

    pub fn import(&mut self, obs: &[Observation], cancel: &Arc<AtomicBool>) -> Result<usize> {
        match self {
            Database::Sqlite(conn) => import_sqlite(conn, obs),
            Database::Postgres(client) => import_postgres(client, obs, cancel),
        }
    }

    pub fn search_ip(&mut self, pattern: &str, actions: &[String]) -> Result<Vec<ObservationRow>> {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            return Ok(Vec::new());
        }
        match self {
            Database::Sqlite(conn) => search_ip_sqlite(conn, pattern, actions),
            Database::Postgres(client) => search_ip_postgres(client, pattern, actions),
        }
    }

    pub fn match_ips(&mut self, ips: &[String], actions: &[String]) -> Result<Vec<ObservationRow>> {
        if ips.is_empty() {
            return Ok(Vec::new());
        }
        match self {
            Database::Sqlite(conn) => match_ips_sqlite(conn, ips, actions),
            Database::Postgres(client) => match_ips_postgres(client, ips, actions),
        }
    }

    pub fn distinct_actions(&mut self) -> Result<Vec<String>> {
        match self {
            Database::Sqlite(conn) => {
                let mut stmt = conn.prepare("SELECT DISTINCT action FROM observations ORDER BY action")?;
                let rows = stmt.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            }
            Database::Postgres(client) => {
                let rows = client.query("SELECT DISTINCT action FROM observations ORDER BY action", &[])?;
                Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
            }
        }
    }

    pub fn count(&mut self) -> Result<i64> {
        match self {
            Database::Sqlite(conn) => {
                Ok(conn.query_row("SELECT COUNT(*) FROM observations", [], |r| r.get(0))?)
            }
            Database::Postgres(client) => {
                let row = client.query_one("SELECT COUNT(*) FROM observations", &[])?;
                Ok(row.get::<_, i64>(0))
            }
        }
    }
}

fn import_sqlite(conn: &mut Connection, obs: &[Observation]) -> Result<usize> {
    let tx = conn.transaction()?;
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
        let mut seen_stmt = tx.prepare("INSERT OR IGNORE INTO seen_events(event_id) VALUES (?1)")?;
        for o in obs {
            let inserted = seen_stmt.execute(params![o.event_id])?;
            if inserted == 0 {
                continue;
            }
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

fn search_ip_sqlite(conn: &Connection, pattern: &str, actions: &[String]) -> Result<Vec<ObservationRow>> {
    let like = format!("{}%", escape_like(pattern));
    let mut sql = String::from(
        r#"
        SELECT user_id, MAX(user_name), MAX(user_email), ip, user_agent, MAX(ja3), MIN(first_seen), MAX(last_seen), SUM(hits)
        FROM observations
        WHERE ip LIKE ?1 ESCAPE '\'
        "#,
    );
    if !actions.is_empty() {
        let placeholders = vec!["?"; actions.len()].join(",");
        sql.push_str(&format!(" AND action IN ({placeholders})"));
    }
    sql.push_str(" GROUP BY user_id, ip, user_agent ORDER BY ip, user_id");

    let mut stmt = conn.prepare(&sql)?;
    let params_iter = once(like).chain(actions.iter().cloned());
    let rows = stmt
        .query_map(params_from_iter(params_iter), map_row_sqlite)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn match_ips_sqlite(conn: &mut Connection, ips: &[String], actions: &[String]) -> Result<Vec<ObservationRow>> {
    let tx = conn.transaction()?;
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
        .query_map(params_from_iter(actions.iter().cloned()), map_row_sqlite)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    tx.commit()?;
    Ok(rows)
}

fn map_row_sqlite(r: &rusqlite::Row) -> rusqlite::Result<ObservationRow> {
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

fn import_postgres(client: &mut PgClient, obs: &[Observation], cancel: &Arc<AtomicBool>) -> Result<usize> {
    let mut tx = client.transaction()?;
    let event_ids: Vec<&str> = obs.iter().map(|o| o.event_id.as_str()).collect();
    let new_ids: HashSet<String> = tx
        .query(
            "INSERT INTO seen_events(event_id) \
            SELECT * FROM unnest($1::text[]) \
            ON CONFLICT (event_id) DO NOTHING \
            RETURNING event_id",
            &[&event_ids],
        )?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect();

    if cancel.load(Ordering::Relaxed) {
        tx.rollback()?;
        return Ok(0);
    }

    let fresh: Vec<&Observation> = obs
        .iter()
        .filter(|o| new_ids.contains(&o.event_id))
        .collect();

    if fresh.is_empty() {
        tx.commit()?;
        return Ok(0);
    }

    struct Agg {
        user_name: Option<String>,
        user_email: Option<String>,
        ja3: Option<String>,
        first_seen: Option<i64>,
        last_seen: Option<i64>,
        hits: i64,
    }

    let mut map: HashMap<(String, String, String, String), Agg> = HashMap::new();
    for o in &fresh {
        let ua = o.user_agent.clone().unwrap_or_default();
        let key = (o.user_id.clone(), o.ip.clone(), ua, o.action.clone());
        let e = map.entry(key).or_insert(Agg {
            user_name: None,
            user_email: None,
            ja3: None,
            first_seen: None,
            last_seen: None,
            hits: 0,
        });
        e.hits += 1;
        if e.user_name.is_none() { e.user_name = o.user_name.clone(); }
        if e.user_email.is_none() { e.user_email = o.user_email.clone(); }
        if e.ja3.is_none() { e.ja3 = o.ja3.clone(); }
        match (e.first_seen, o.seen_at) {
            (None, s) => e.first_seen = s,
            (Some(cur), Some(s)) if s < cur => e.first_seen = Some(s),
            _ => {}
        }
        match (e.last_seen, o.seen_at) {
            (None, s) => e.last_seen = s,
            (Some(cur), Some(s)) if s > cur => e.last_seen = Some(s),
            _ => {}
        }
    }

    let mut user_id: Vec<&str> = Vec::with_capacity(map.len());
    let mut ip: Vec<&str> = Vec::with_capacity(map.len());
    let mut user_agent: Vec<&str> = Vec::with_capacity(map.len());
    let mut action: Vec<&str> = Vec::with_capacity(map.len());
    let mut user_name: Vec<Option<&str>> = Vec::with_capacity(map.len());
    let mut user_email: Vec<Option<&str>> = Vec::with_capacity(map.len());
    let mut ja3: Vec<Option<&str>> = Vec::with_capacity(map.len());
    let mut first_seen: Vec<Option<i64>> = Vec::with_capacity(map.len());
    let mut last_seen: Vec<Option<i64>> = Vec::with_capacity(map.len());
    let mut hits: Vec<i64> = Vec::with_capacity(map.len());

    for (key, agg) in &map {
        user_id.push(key.0.as_str());
        ip.push(key.1.as_str());
        user_agent.push(key.2.as_str());
        action.push(key.3.as_str());
        user_name.push(agg.user_name.as_deref());
        user_email.push(agg.user_email.as_deref());
        ja3.push(agg.ja3.as_deref());
        first_seen.push(agg.first_seen);
        last_seen.push(agg.last_seen);
        hits.push(agg.hits);
    }

    let affected = map.len();

    tx.execute(
        r#"
            INSERT INTO observations (
                user_id, user_name, user_email, ip, user_agent, ja3, action, first_seen, last_seen, hits
            )
            SELECT user_id, user_name, user_email, ip, user_agent, ja3, action, first_seen, last_seen, hits
            FROM unnest (
                $1::text[],
                $2::text[],
                $3::text[],
                $4::text[],
                $5::text[],
                $6::text[],
                $7::text[],
                $8::bigint[],
                $9::bigint[],
                $10::bigint[]
            ) AS t(user_id, user_name, user_email, ip, user_agent, ja3, action, first_seen, last_seen, hits)
            ON CONFLICT(
                user_id, ip, user_agent, action
            )
            DO UPDATE SET
            hits = observations.hits + excluded.hits,
            first_seen = LEAST(observations.first_seen, excluded.first_seen),
            last_seen = GREATEST(observations.last_seen, excluded.last_seen),
            user_name = COALESCE(excluded.user_name, observations.user_name),
            user_email = COALESCE(excluded.user_email, observations.user_email),
            ja3 = COALESCE(excluded.ja3, observations.ja3)
            "#,
        &[
            &user_id,
            &user_name,
            &user_email,
            &ip,
            &user_agent,
            &ja3,
            &action,
            &first_seen,
            &last_seen,
            &hits,
        ],
    )?;
    tx.commit()?;
    Ok(affected)
}

fn search_ip_postgres(client: &mut PgClient, pattern: &str, actions: &[String]) -> Result<Vec<ObservationRow>> {
    let like = format!("{}%", escape_like(pattern));
    let mut sql = String::from(
        r#"
        SELECT user_id, MAX(user_name), MAX(user_email), ip, user_agent, MAX(ja3), MIN(first_seen), MAX(last_seen), SUM(hits)::bigint
        FROM observations
        WHERE ip LIKE $1 ESCAPE '\'
        "#,
    );
    let mut params: Vec<&(dyn ToSql + Sync)> = vec![&like];
    if !actions.is_empty() {
        let ph: Vec<String> = (0..actions.len()).map(|i| format!("${}", i + 2)).collect();
        sql.push_str(&format!(" AND action IN ({})", ph.join(",")));
        for a in actions {
            params.push(a);
        }
    }
    sql.push_str(" GROUP BY user_id, ip, user_agent ORDER BY ip, user_id");

    let rows = client.query(sql.as_str(), &params)?;
    Ok(rows.iter().map(map_row_postgres).collect())
}

fn match_ips_postgres(client: &mut PgClient, ips: &[String], actions: &[String]) -> Result<Vec<ObservationRow>> {
    let mut tx = client.transaction()?;
    tx.batch_execute(
        "
            CREATE TEMP TABLE IF NOT EXISTS _needle_ips (ip TEXT PRIMARY KEY) ON COMMIT DROP;
            DELETE FROM _needle_ips;
            ",
    )?;
    {
        let stmt = tx.prepare("INSERT INTO _needle_ips(ip) VALUES ($1) ON CONFLICT DO NOTHING")?;
        for ip in ips {
            tx.execute(&stmt, &[ip])?;
        }
    }
    let mut sql = String::from(
        r#"
            SELECT o.user_id, MAX(o.user_name), MAX(o.user_email), o.ip, o.user_agent, MAX(o.ja3), MIN(o.first_seen), MAX(o.last_seen), SUM(o.hits)::bigint
            FROM observations o
            JOIN _needle_ips n ON o.ip = n.ip
            "#,
    );
    let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
    if !actions.is_empty() {
        let ph: Vec<String> = (0..actions.len()).map(|i| format!("${}", i + 1)).collect();
        sql.push_str(&format!(" WHERE o.action IN ({})", ph.join(",")));
        for a in actions {
            params.push(a);
        }
    }
    sql.push_str(" GROUP BY o.user_id, o.ip, o.user_agent ORDER BY o.ip, o.user_id");

    let rows = tx.query(sql.as_str(), &params)?;
    let out: Vec<ObservationRow> = rows.iter().map(map_row_postgres).collect();
    tx.commit()?;
    Ok(out)
}

fn map_row_postgres(r: &postgres::Row) -> ObservationRow {
    ObservationRow {
        user_id: r.get(0),
        user_name: r.get(1),
        user_email: r.get(2),
        ip: r.get(3),
        user_agent: r.get(4),
        ja3: r.get(5),
        first_seen: r.get(6),
        last_seen: r.get(7),
        hits: r.get(8),
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
