-- =============================================================================
-- Flyway Migration V1: Create core schema
--
-- Flyway runs this automatically on app startup if it hasn't run before.
-- File naming convention: V{version}__{description}.sql
-- Never edit a migration that has already run — create a new V2__ file.
-- =============================================================================

-- ── Users table ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username              VARCHAR(50) NOT NULL UNIQUE,
    password_hash         VARCHAR(255) NOT NULL,
    role                  VARCHAR(20) NOT NULL CHECK (role IN ('ADMIN','SOC_ANALYST','VIEWER')),
    totp_secret           VARCHAR(255),
    mfa_enabled           BOOLEAN NOT NULL DEFAULT FALSE,
    account_locked        BOOLEAN NOT NULL DEFAULT FALSE,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login            TIMESTAMPTZ
);

-- ── Entity Profiles ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS entity_profiles (
    id                   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_id            VARCHAR(100) NOT NULL UNIQUE,
    entity_type          VARCHAR(30) NOT NULL CHECK (entity_type IN ('USER','DEVICE','SERVICE_ACCOUNT','APPLICATION')),
    department           VARCHAR(100),
    risk_level           VARCHAR(20) NOT NULL DEFAULT 'LOW' CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    total_alerts         INTEGER NOT NULL DEFAULT 0,
    last_seen            TIMESTAMPTZ,
    baseline_established BOOLEAN NOT NULL DEFAULT FALSE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_entity_profiles_entity_id ON entity_profiles(entity_id);
CREATE INDEX idx_entity_profiles_risk_level ON entity_profiles(risk_level);

-- ── Behavioral Baselines ──────────────────────────────────────────────────────
-- One row per (entity, feature) pair.
-- The detection engine updates mu/sigma_sq using Welford's online algorithm.
CREATE TABLE IF NOT EXISTS behavioral_baselines (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_id     VARCHAR(100) NOT NULL,
    feature_name  VARCHAR(100) NOT NULL,
    mu            DOUBLE PRECISION NOT NULL DEFAULT 0,
    sigma_sq      DOUBLE PRECISION NOT NULL DEFAULT 0,
    sample_count  BIGINT NOT NULL DEFAULT 0,
    last_updated  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(entity_id, feature_name)
);

CREATE INDEX idx_baselines_entity_feature ON behavioral_baselines(entity_id, feature_name);

-- ── Alerts ────────────────────────────────────────────────────────────────────
-- The central output of the detection engine.
-- shap_drivers is JSONB for flexible "why was this flagged?" explanations.
CREATE TABLE IF NOT EXISTS alerts (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_id               VARCHAR(100) NOT NULL,
    risk_score              INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    isolation_forest_score  DOUBLE PRECISION,
    autoencoder_error       DOUBLE PRECISION,
    peer_deviation          DOUBLE PRECISION,
    mitre_technique_id      VARCHAR(20),
    mitre_technique_name    VARCHAR(200),
    mitre_tactic            VARCHAR(100),
    shap_drivers            JSONB,          -- [{feature, contribution, description, ...}]
    raw_event_id            VARCHAR(100),   -- MongoDB ObjectId reference
    status                  VARCHAR(30) NOT NULL DEFAULT 'OPEN'
                                CHECK (status IN ('OPEN','INVESTIGATING','RESOLVED','FALSE_POSITIVE','AUTO_MITIGATED')),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at             TIMESTAMPTZ,
    resolved_by             VARCHAR(50)
);

CREATE INDEX idx_alerts_entity_id  ON alerts(entity_id);
CREATE INDEX idx_alerts_risk_score ON alerts(risk_score DESC);
CREATE INDEX idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX idx_alerts_status     ON alerts(status);
-- GIN index allows fast queries INTO the JSONB shap_drivers field
CREATE INDEX idx_alerts_shap_gin   ON alerts USING GIN(shap_drivers);

-- ── MITRE ATT&CK Techniques ───────────────────────────────────────────────────
-- Reference table loaded from the STIX JSON dataset in Week 2.
CREATE TABLE IF NOT EXISTS mitre_techniques (
    technique_id   VARCHAR(20) PRIMARY KEY,   -- e.g. "T1078"
    name           VARCHAR(200) NOT NULL,      -- e.g. "Valid Accounts"
    tactic         VARCHAR(100) NOT NULL,      -- e.g. "Defense Evasion"
    description    TEXT,
    url            VARCHAR(500)               -- Link to attack.mitre.org
);

-- ── Response Audit Log ────────────────────────────────────────────────────────
-- Immutable record of every automated and manual response action.
-- Critical for compliance (GDPR Article 33) and forensic analysis.
CREATE TABLE IF NOT EXISTS response_audit (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id       UUID REFERENCES alerts(id),
    action_type    VARCHAR(50) NOT NULL,   -- AUTO_DISABLE, EMAIL_SENT, OPERATOR_OVERRIDE …
    entity_id      VARCHAR(100),
    performed_by   VARCHAR(100),           -- 'SYSTEM' or operator username
    reason         TEXT,
    metadata       JSONB,
    performed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_response_audit_alert_id ON response_audit(alert_id);

-- ── Default admin user (BCrypt hash of 'ChangeMe123!' — change immediately) ──
INSERT INTO users (username, password_hash, role)
VALUES ('admin', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LetR7X5aK5vxZGe3G', 'ADMIN')
ON CONFLICT DO NOTHING;
