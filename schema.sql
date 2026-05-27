DROP TABLE IF EXISTS ne_policies CASCADE;
DROP TABLE IF EXISTS ne_lan CASCADE;
DROP TABLE IF EXISTS ne_wan CASCADE;
DROP TABLE IF EXISTS ne_profiles CASCADE;
DROP TABLE IF EXISTS pqc CASCADE;

DROP TYPE IF EXISTS encryption_action_enum CASCADE;
DROP TYPE IF EXISTS encryption_protocol_enum CASCADE;
DROP TYPE IF EXISTS encryption_method_enum CASCADE;

CREATE TYPE encryption_action_enum AS ENUM ('L2', 'L3', 'L4', 'bypass');

CREATE TYPE encryption_protocol_enum AS ENUM ('tcp', 'udp', 'icmp', 'ospf');

CREATE TYPE encryption_method_enum AS ENUM (
    'aes-gcm-128',
    'aes-gcm-256',
    'aes-ctr-128',
    'aes-ctr-256',
    'pqc-gcm'
);

CREATE TABLE pqc (
    id              SERIAL PRIMARY KEY,
    encryption_key  TEXT     NULL
);

CREATE TABLE ne_profiles (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(100)    NOT NULL,
    description     VARCHAR(80)     NULL,
    weight_enable   BOOLEAN         NOT NULL DEFAULT FALSE,
    latency_enable  BOOLEAN         NOT NULL DEFAULT FALSE,
    loss_enable     BOOLEAN         NOT NULL DEFAULT FALSE,
    latency_duration INT            NULL CHECK (latency_duration >= 0),
    loss_duration   INT             NULL CHECK (loss_duration >= 0),
    created_at      TIMESTAMP       NOT NULL DEFAULT NOW(),
    created_by      VARCHAR(100)    NULL,
    updated_at      TIMESTAMP       NULL,
    updated_by      VARCHAR(100)    NULL,


    CONSTRAINT uq_encryption_profile_name UNIQUE (name)
);

CREATE INDEX idx_encryption_profile_name ON ne_profiles (name);

CREATE TABLE ne_policies (
    id              INT             PRIMARY KEY,
    profile_id      INT             NOT NULL REFERENCES ne_profiles(id) ON DELETE CASCADE,
    priority        INT             NOT NULL,
    action          encryption_action_enum   NOT NULL,
    proto           encryption_protocol_enum NULL,
    src_ip          TEXT[]          NULL,
    invert_src_ip   BOOLEAN         NOT NULL DEFAULT FALSE,
    dst_ip          TEXT[]          NULL,
    invert_dst_ip   BOOLEAN         NOT NULL DEFAULT FALSE,
    src_port        TEXT[]          NULL,
    dst_port        TEXT[]          NULL,
    method          encryption_method_enum   NULL,
    encryption_key  VARCHAR(512)    NULL,
    nonce           INT             NULL CHECK (nonce IN (4, 8, 12, 16)),
    created_at      TIMESTAMP       NOT NULL DEFAULT NOW(),
    created_by      VARCHAR(100)    NULL,
    updated_at      TIMESTAMP       NULL,
    updated_by      VARCHAR(100)    NULL,

    CONSTRAINT uq_encryption_profile_priority UNIQUE (profile_id, priority)
);

CREATE INDEX idx_encryption_profile_id  ON ne_policies (profile_id);
CREATE INDEX idx_encryption_priority    ON ne_policies (priority);
CREATE INDEX idx_encryption_action      ON ne_policies (action);

CREATE TABLE ne_lan (
    id          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    interface   VARCHAR(100)    NULL,
    profile_id  INT             NOT NULL REFERENCES ne_profiles(id) ON DELETE CASCADE,
    created_at  TIMESTAMP       NOT NULL DEFAULT NOW(),
    created_by  VARCHAR(100)    NULL,
    updated_at  TIMESTAMP       NULL,
    updated_by  VARCHAR(100)    NULL
);

CREATE TABLE ne_wan (
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    interface       VARCHAR(100)    NULL,
    profile_id      INT             NOT NULL REFERENCES ne_profiles(id) ON DELETE CASCADE,
    dst_ip          VARCHAR(45)     NULL,
    weight          INT             NOT NULL DEFAULT 50 CHECK (weight BETWEEN 0 AND 100),
    latency_ip      VARCHAR(45)     NULL,
    latency         INT             NULL CHECK (latency >= 0),
    latency_enable  BOOLEAN         NOT NULL DEFAULT FALSE,
    loss_ip         VARCHAR(45)     NULL,
    loss_percentage INT             NOT NULL DEFAULT 0 CHECK (loss_percentage BETWEEN 0 AND 100),
    loss_enable     BOOLEAN         NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMP       NOT NULL DEFAULT NOW(),
    created_by      VARCHAR(100)    NULL,
    updated_at      TIMESTAMP       NULL,
    updated_by      VARCHAR(100)    NULL
);

CREATE TABLE IF NOT EXISTS pqc_identities (
    profile_id INT PRIMARY KEY REFERENCES xdp_profiles(id) ON DELETE CASCADE,
    peer_pub TEXT NOT NULL,
    peer_fingerprint VARCHAR(16),
    is_initiator BOOLEAN NOT NULL DEFAULT TRUE
);



