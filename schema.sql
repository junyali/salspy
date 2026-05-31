CREATE TABLE IF NOT EXISTS observations (
    user_id    TEXT NOT NULL,
    user_name  TEXT,
    user_email TEXT,
    ip         TEXT NOT NULL,
    user_agent TEXT NOT NULL DEFAULT '',
    ja3        TEXT,
    first_seen INTEGER,
    last_seen  INTEGER,
    hits       INTEGER NOT NULL DEFAULT 1,
    UNIQUE(user_id, ip, user_agent)
);
CREATE INDEX IF NOT EXISTS idx_obs_ip   ON observations(ip);
CREATE INDEX IF NOT EXISTS idx_obs_user ON observations(user_id);

