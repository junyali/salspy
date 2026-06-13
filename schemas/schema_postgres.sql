CREATE TABLE IF NOT EXISTS observations(
    user_id    TEXT   NOT NULL,
    user_name  TEXT,
    user_email TEXT,
    ip         TEXT   NOT NULL,
    user_agent TEXT   NOT NULL DEFAULT '',
    ja3        TEXT,
    action     TEXT   NOT NULL DEFAULT '',
    first_seen BIGINT,
    last_seen  BIGINT,
    hits       BIGINT NOT NULL DEFAULT 1,
    UNIQUE(user_id, ip, user_agent, action)
);
CREATE TABLE IF NOT EXISTS seen_events(
    event_id TEXT PRIMARY KEY
);
CREATE INDEX IF NOT EXISTS idx_obs_ip       ON observations(ip);
CREATE INDEX IF NOT EXISTS idx_obs_user     ON observations(user_id);
CREATE INDEX IF NOT EXISTS idx_obs_action   ON observations(action);
