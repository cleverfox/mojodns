-- mojodns application tables (users / ACLs / history / API tokens).
-- DNS data itself lives in PowerDNS and is managed through its REST API;
-- zones are referenced here by canonical name (lowercase, trailing dot).

CREATE TABLE app_users (
  id            BIGSERIAL PRIMARY KEY,
  login         VARCHAR(255) NOT NULL UNIQUE,
  email         VARCHAR(255),
  -- formats: "bcrypt$<hash>" or "legacysha1$<salt>$<hexdigest>"
  password_hash VARCHAR(255) NOT NULL,
  role          VARCHAR(16)  NOT NULL DEFAULT 'owner'
                CHECK (role IN ('admin', 'owner')),
  state         VARCHAR(16)  NOT NULL DEFAULT 'active',
  -- per-minute cap on outbound-probe actions; NULL = use the global default
  check_rate_limit INTEGER,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- zone ownership + delegated edit access (replaces domains.user_id and
-- the old user_access table)
CREATE TABLE zone_access (
  id         BIGSERIAL PRIMARY KEY,
  zone       VARCHAR(255) NOT NULL,
  user_id    BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  is_owner   BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (zone, user_id)
);
CREATE INDEX zone_access_zone_idx ON zone_access(zone);
CREATE INDEX zone_access_user_idx ON zone_access(user_id);

CREATE TABLE app_history (
  id          BIGSERIAL PRIMARY KEY,
  user_id     BIGINT REFERENCES app_users(id) ON DELETE SET NULL,
  target_type VARCHAR(16) NOT NULL,        -- 'zone' | 'user'
  target      VARCHAR(255),                -- zone name or user login
  message     TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX app_history_target_idx ON app_history(target_type, target);
CREATE INDEX app_history_created_idx ON app_history(created_at);

-- last NS-delegation verification result per zone
CREATE TABLE zone_checks (
  id          BIGSERIAL PRIMARY KEY,
  zone        VARCHAR(255) NOT NULL UNIQUE,
  status      VARCHAR(16) NOT NULL,     -- ok | partial | mismatch | error
  resolved_ns TEXT,
  detail      VARCHAR(255),
  checked_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- last TLS certificate seen for a record's host:ip during an HTTPS check
CREATE TABLE cert_observations (
  id             BIGSERIAL PRIMARY KEY,
  zone           VARCHAR(255) NOT NULL,
  host           VARCHAR(255) NOT NULL,
  ip             VARCHAR(64)  NOT NULL,
  port           INTEGER NOT NULL DEFAULT 443,
  subject        VARCHAR(255),
  issuer         VARCHAR(255),
  not_after      TIMESTAMPTZ,
  days_left      INTEGER,
  hostname_match BOOLEAN,
  self_signed    BOOLEAN,
  trusted        BOOLEAN,
  error          VARCHAR(255),
  checked_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_cert_host_ip_port UNIQUE (host, ip, port)
);
CREATE INDEX cert_obs_zone_idx ON cert_observations(zone);
CREATE INDEX cert_obs_expiry_idx ON cert_observations(not_after);

CREATE TABLE api_tokens (
  id         BIGSERIAL PRIMARY KEY,
  user_id    BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  token      VARCHAR(64) NOT NULL UNIQUE,
  note       VARCHAR(255),
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
