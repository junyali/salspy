use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AuditEntry {
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
    pub user_id: String,
    pub user_name: Option<String>,
    pub user_email: Option<String>,
    pub ip: String,
    pub user_agent: Option<String>,
    pub ja3: Option<String>,
    pub seen_at: Option<i64>,
}
