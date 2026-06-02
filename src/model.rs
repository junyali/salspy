use serde::Deserialize;
use std::net::IpAddr;

#[derive(Debug, Deserialize)]
pub struct AuditEntry {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub date_create: Option<i64>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub actor: Option<Actor>,
    #[serde(default)]
    pub context: Option<Context>,
    #[serde(default)]
    pub details: Option<Details>,
}

#[derive(Debug, Deserialize)]
pub struct Actor {
    #[serde(default)]
    pub user: Option<User>
}

#[derive(Debug, Deserialize)]
pub struct User {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub team: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Context {
    #[serde(default)]
    pub ua: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub session_id: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct Details {
    #[serde(default)]
    pub previous_ip_address: Option<String>,
    #[serde(default)]
    pub previous_ua: Option<String>,
    #[serde(default)]
    pub client_ja3_fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Observation {
    pub event_id: String,
    pub user_id: String,
    pub user_name: Option<String>,
    pub user_email: Option<String>,
    pub ip: String,
    pub user_agent: Option<String>,
    pub ja3: Option<String>,
    pub action: String,
    pub seen_at: Option<i64>,
}

pub fn canonical_ip(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    trimmed.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

pub fn entry_to_observations(entry: &AuditEntry) -> Vec<Observation> {
    let mut out = Vec::new();
    let user = entry.actor.as_ref().and_then(|a| a.user.as_ref());
    let event_id = match entry.id.clone() {
        Some(id) => id,
        None => return out,
    };
    let user_id = match user.and_then(|u| u.id.clone()) {
        Some(id) => id,
        None => return out,
    };
    let user_name = user.and_then(|u| u.name.clone());
    let user_email = user.and_then(|u| u.email.clone());
    let ja3 = entry.details.as_ref().and_then(|d| d.client_ja3_fingerprint.clone());
    let action = match entry.action.as_deref() {
        Some(a) if !a.trim().is_empty() => a.to_string(), _ => "(none)".to_string(),
    };
    let ctx = entry.context.as_ref();
    if let Some(ip_raw) = ctx.and_then(|c| c.ip_address.as_ref()) {
        if let Some(ip) = canonical_ip(ip_raw) {
            out.push(Observation {
                event_id: event_id.clone(),
                user_id: user_id.clone(),
                user_name: user_name.clone(),
                user_email: user_email.clone(),
                ip,
                user_agent: ctx.and_then(|c| c.ua.clone()),
                ja3: ja3.clone(),
                action: action.clone(),
                seen_at: entry.date_create
            });
        }
    }
    if let Some(details) = entry.details.as_ref() {
        if let Some(prev_ip_raw) = details.previous_ip_address.as_ref() {
            if let Some(ip) = canonical_ip(prev_ip_raw) {
                out.push(Observation {
                    event_id: format!("{event_id}:prev"),
                    user_id: user_id.clone(),
                    user_name: user_name.clone(),
                    user_email: user_email.clone(),
                    ip,
                    user_agent: details.previous_ua.clone(),
                    ja3,
                    action,
                    seen_at: entry.date_create,
                });
            }
        }
    }
    out
}

pub fn parse_line(line: &str) -> anyhow::Result<Option<AuditEntry>> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(None);
    }
    let entry: AuditEntry = serde_json::from_str(line)?;
    Ok(Some(entry))
}
