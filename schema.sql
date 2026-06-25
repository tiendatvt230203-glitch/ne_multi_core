-- ============================================================
-- NE MODEL SCHEMA - SQL Script
-- Tables: ne_profiles, ne_wan, ne_lan, ne_policies,
--         bridges, bridge_interfaces, pqc_keys,
--         pqc_exchange_tunnels, policy_pqc_ref,
--         profile_tunnel_ref, profile_bridge_ref
-- ============================================================

-- ============================================================
-- DROP TABLES (thứ tự đảo ngược để tránh vi phạm FK)
-- ============================================================
DROP TABLE IF EXISTS policy_pqc_ref CASCADE;
DROP TABLE IF EXISTS profile_tunnel_ref CASCADE;
DROP TABLE IF EXISTS profile_bridge_ref CASCADE;
DROP TABLE IF EXISTS bridge_interfaces CASCADE;
DROP TABLE IF EXISTS ne_policies CASCADE;
DROP TABLE IF EXISTS ne_wan CASCADE;
DROP TABLE IF EXISTS ne_lan CASCADE;
DROP TABLE IF EXISTS pqc_exchange_tunnels CASCADE;
DROP TABLE IF EXISTS pqc_keys CASCADE;
DROP TABLE IF EXISTS bridges CASCADE;
DROP TABLE IF EXISTS ne_profiles CASCADE;


-- ============================================================
-- CREATE TABLES
-- ============================================================

-- ------------------------------------------------------------
-- 1. ne_profiles
-- ------------------------------------------------------------
CREATE TABLE ne_profiles (
    id               SERIAL PRIMARY KEY,
    name             VARCHAR(255)     NOT NULL,
    description      VARCHAR(80),
    weight_enable    BOOLEAN          NOT NULL DEFAULT FALSE,
    loss_enable      BOOLEAN          NOT NULL DEFAULT FALSE,
    latency_enable   BOOLEAN          NOT NULL DEFAULT FALSE,
    latency_duration INT              DEFAULT NULL,
    loss_duration    INT              DEFAULT NULL,
    bridge_enable    BOOLEAN          NOT NULL DEFAULT FALSE,
    tunnel_enable    BOOLEAN          NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMP        NOT NULL DEFAULT NOW(),
    created_by       VARCHAR(255)     NOT NULL,
    updated_at       TIMESTAMP        NOT NULL DEFAULT NOW(),
    updated_by       VARCHAR(255)     NOT NULL
);

-- ------------------------------------------------------------
-- 2. ne_wan
-- ------------------------------------------------------------
CREATE TABLE ne_wan (
    id              UUID             PRIMARY KEY DEFAULT gen_random_uuid(),
    interface       VARCHAR(255)     NOT NULL,
    profile_id      INT              NOT NULL REFERENCES ne_profiles(id) ON DELETE CASCADE,
    dst_ip          INET             NOT NULL,
    weight          INT              CHECK (weight <= 100),
    latency_ip      INET,
    latency         INT,
    latency_enable  BOOLEAN          NOT NULL DEFAULT FALSE,
    loss_ip         INET,
    loss_percentage INT              CHECK (loss_percentage <= 100),
    loss_enable     BOOLEAN          NOT NULL DEFAULT FALSE
);

-- ------------------------------------------------------------
-- 3. ne_lan
-- ------------------------------------------------------------
CREATE TABLE ne_lan (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    interface   VARCHAR(255) NOT NULL,
    profile_id  INT          NOT NULL REFERENCES ne_profiles(id) ON DELETE CASCADE
);

-- ------------------------------------------------------------
-- 4. bridges
-- ------------------------------------------------------------
CREATE TABLE bridges (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    ifname      VARCHAR(255) NOT NULL,
    description TEXT,
    created_at  TIMESTAMP    NOT NULL DEFAULT NOW(),
    created_by  VARCHAR(255) NOT NULL,
    updated_at  TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_by  VARCHAR(255) NOT NULL
);

-- ------------------------------------------------------------
-- 5. bridge_interfaces
-- ------------------------------------------------------------
CREATE TABLE bridge_interfaces (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    bridge_id   UUID         NOT NULL REFERENCES bridges(id) ON DELETE CASCADE,
    ifname      VARCHAR(255) NOT NULL,
    tag         VARCHAR(10)  NOT NULL CHECK (tag IN ('WAN', 'LAN'))
);

-- ------------------------------------------------------------
-- 6. pqc_keys
-- ------------------------------------------------------------
CREATE TABLE pqc_keys (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id      VARCHAR(255) NOT NULL UNIQUE,
    status      VARCHAR(20)  NOT NULL CHECK (status IN ('await', 'exchange', 'establish', 'failed')),
    log         VARCHAR(500),
    local       TEXT         NOT NULL,
    remote      TEXT         NOT NULL,
    created_at  TIMESTAMP    NOT NULL DEFAULT NOW(),
    created_by  VARCHAR(255) NOT NULL,
    updated_at  TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_by  VARCHAR(255) NOT NULL
);

-- ------------------------------------------------------------
-- 7. pqc_exchange_tunnels
-- ------------------------------------------------------------
CREATE TABLE pqc_exchange_tunnels (
    id                      UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tunnel_name             VARCHAR(255) NOT NULL,
    mode                    VARCHAR(10)  NOT NULL CHECK (mode IN ('server', 'client')),
    client_tunnel_ip        INET,
    client_peer_public_ip   INET,
    client_peer_listen_port INT          CHECK (client_peer_listen_port BETWEEN 1 AND 65535),
    server_public_ip        INET,
    private_key             TEXT,
    public_key              TEXT,
    peer_public_key         TEXT,
    peer_tunnel_ip          INET,
    created_at              TIMESTAMP    NOT NULL DEFAULT NOW(),
    created_by              VARCHAR(255) NOT NULL,
    updated_at              TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_by              VARCHAR(255) NOT NULL
);

-- ------------------------------------------------------------
-- 8. ne_policies
-- ------------------------------------------------------------
CREATE TABLE ne_policies (
    id             SERIAL       PRIMARY KEY,
    profile_id     INT          REFERENCES ne_profiles(id) ON DELETE SET NULL,
    priority       INT          NOT NULL,
    action         VARCHAR(10)  NOT NULL CHECK (action IN ('L2', 'L3', 'L4', 'bypass')),
    protocol       VARCHAR(10)  CHECK (protocol IN ('tcp', 'udp', 'icmp', 'ospf') OR protocol IS NULL),
    src_ip         TEXT[],
    dst_ip         TEXT[],
    src_port       TEXT[],
    dst_port       TEXT[],
    invert_src_ip  BOOLEAN      NOT NULL DEFAULT FALSE,
    invert_dst_ip  BOOLEAN      NOT NULL DEFAULT FALSE,
    method         VARCHAR(30)  CHECK (method IN ('aes-gcm-128','aes-gcm-256','aes-ctr-128','aes-ctr-256','pqc-gcm') OR method IS NULL),
    encryption_key TEXT
);

-- ------------------------------------------------------------
-- 9. policy_pqc_ref  (join: ne_policies <-> pqc_keys)
-- ------------------------------------------------------------
CREATE TABLE policy_pqc_ref (
    policy_id  INT          NOT NULL REFERENCES ne_policies(id) ON DELETE CASCADE,
    key_id     VARCHAR(255) NOT NULL REFERENCES pqc_keys(key_id) ON DELETE CASCADE,
    PRIMARY KEY (policy_id, key_id)
);

-- ------------------------------------------------------------
-- 10. profile_tunnel_ref  (join: ne_profiles <-> pqc_exchange_tunnels)
-- ------------------------------------------------------------
CREATE TABLE profile_tunnel_ref (
    profile_id  INT  NOT NULL REFERENCES ne_profiles(id) ON DELETE CASCADE,
    tunnel_id   UUID NOT NULL REFERENCES pqc_exchange_tunnels(id) ON DELETE CASCADE,
    PRIMARY KEY (profile_id, tunnel_id)
);

-- ------------------------------------------------------------
-- 11. profile_bridge_ref  (join: ne_profiles <-> bridges)
-- ------------------------------------------------------------
CREATE TABLE profile_bridge_ref (
    profile_id  INT  NOT NULL REFERENCES ne_profiles(id) ON DELETE CASCADE,
    bridge_id   UUID NOT NULL REFERENCES bridges(id) ON DELETE CASCADE,
    PRIMARY KEY (profile_id, bridge_id)
);


-- ============================================================
-- SAMPLE DATA (INSERT)
-- ============================================================

-- ne_profiles
INSERT INTO ne_profiles (name, description, weight_enable, loss_enable, latency_enable, bridge_enable, tunnel_enable, latency_duration, loss_duration, created_by, updated_by)
VALUES
    ('Profile_Primary',   'Main WAN profile',    TRUE,  FALSE, TRUE, TRUE, TRUE, 300, NULL, 'admin', 'admin'),
    ('Profile_Backup',    'Backup WAN profile',   FALSE, TRUE,  FALSE,  TRUE, TRUE, NULL, 600, 'admin', 'admin'),
    ('Profile_Default',   'Default no-feature',   FALSE, FALSE, FALSE,  TRUE, TRUE, NULL, NULL,'admin', 'admin');

-- bridges
INSERT INTO bridges (id, ifname, description, created_by, updated_by)
VALUES
    ('11111111-1111-1111-1111-111111111111', 'br0', 'Main bridge',   'admin', 'admin'),
    ('22222222-2222-2222-2222-222222222222', 'br1', 'Second bridge', 'admin', 'admin');

-- bridge_interfaces
INSERT INTO bridge_interfaces (id, bridge_id, ifname, tag)
VALUES
    ('aaaa0001-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'eth0', 'WAN'),
    ('aaaa0001-0000-0000-0000-000000000002', '11111111-1111-1111-1111-111111111111', 'eth1', 'LAN'),
    ('aaaa0001-0000-0000-0000-000000000003', '22222222-2222-2222-2222-222222222222', 'eth2', 'WAN');

-- pqc_keys
INSERT INTO pqc_keys (id, key_id, status, local, remote, created_by, updated_by)
VALUES
    ('cccc0001-0000-0000-0000-000000000001', 'KEY-001', 'establish', 'local_key_data_001', 'remote_key_data_001', 'admin', 'admin'),
    ('cccc0001-0000-0000-0000-000000000002', 'KEY-002', 'await',     'local_key_data_002', 'remote_key_data_002', 'admin', 'admin');

-- pqc_exchange_tunnels
INSERT INTO pqc_exchange_tunnels (id, tunnel_name, mode, client_tunnel_ip, client_peer_public_ip, client_peer_listen_port, server_public_ip, private_key, public_key, peer_public_key, peer_tunnel_ip, created_by, updated_by)
VALUES
    ('dddd0001-0000-0000-0000-000000000001', 'Tunnel-Alpha', 'client', '10.0.0.2', '203.0.113.1', 51820, '203.0.113.10', 'priv_key_alpha', 'pub_key_alpha', 'peer_pub_key_alpha', '10.0.0.1', 'admin', 'admin'),
    ('dddd0001-0000-0000-0000-000000000002', 'Tunnel-Beta',  'server', NULL,        NULL,           NULL,  '203.0.113.20', 'priv_key_beta',  'pub_key_beta',  'peer_pub_key_beta',  '10.0.1.1', 'admin', 'admin');

-- ne_wan
INSERT INTO ne_wan (id, interface, profile_id, dst_ip, weight, latency_ip, latency, latency_enable, loss_ip, loss_percentage, loss_enable)
VALUES
    ('bbbb0001-0000-0000-0000-000000000001', 'eth0', 1, '192.168.1.1', 80, '8.8.8.8',  20,   TRUE,  '8.8.4.4', 0,    FALSE),
    ('bbbb0001-0000-0000-0000-000000000002', 'eth1', 1, '192.168.1.2', 20, '1.1.1.1',  50,   FALSE, '1.0.0.1', 5,    TRUE),
    ('bbbb0001-0000-0000-0000-000000000003', 'eth2', 2, '10.10.0.1',   50, NULL,        NULL, FALSE, NULL,      NULL, FALSE);

-- ne_lan
INSERT INTO ne_lan (id, interface, profile_id)
VALUES
    ('eeee0001-0000-0000-0000-000000000001', 'lan0', 1),
    ('eeee0001-0000-0000-0000-000000000002', 'lan1', 2);

-- ne_policies
INSERT INTO ne_policies (profile_id, priority, action, protocol, src_ip, dst_ip, src_port, dst_port, invert_src_ip, invert_dst_ip, method, encryption_key)
VALUES
    (1, 10, 'L3',     'tcp',  ARRAY['192.168.0.0/24'], ARRAY['10.0.0.0/8'],  ARRAY['1024:65535'], ARRAY['443'], FALSE, FALSE, 'aes-gcm-256', 'enc_key_001'),
    (1, 20, 'bypass', NULL,   NULL,                    NULL,                 NULL,                NULL,         FALSE, FALSE, NULL,          NULL),
    (2, 10, 'L4',     'udp',  ARRAY['172.16.0.0/16'],  ARRAY['8.8.8.8/32'], ARRAY['any'],        ARRAY['53'],  FALSE, FALSE, 'pqc-gcm',     'enc_key_002');

-- policy_pqc_ref
INSERT INTO policy_pqc_ref (policy_id, key_id)
VALUES
    (1, 'KEY-001'),
    (3, 'KEY-002');

-- profile_tunnel_ref
INSERT INTO profile_tunnel_ref (profile_id, tunnel_id)
VALUES
    (1, 'dddd0001-0000-0000-0000-000000000001'),
    (2, 'dddd0001-0000-0000-0000-000000000002');

-- profile_bridge_ref
INSERT INTO profile_bridge_ref (profile_id, bridge_id)
VALUES
    (1, '11111111-1111-1111-1111-111111111111'),
    (2, '22222222-2222-2222-2222-222222222222');


-- ============================================================
-- READ (SELECT)
-- ============================================================

-- Lấy tất cả profiles
SELECT * FROM ne_profiles;

-- Lấy tất cả WAN kèm tên profile
SELECT w.*, p.name AS profile_name
FROM ne_wan w
JOIN ne_profiles p ON p.id = w.profile_id;

-- Lấy tất cả policies kèm profile
SELECT po.*, p.name AS profile_name
FROM ne_policies po
LEFT JOIN ne_profiles p ON p.id = po.profile_id
ORDER BY po.profile_id, po.priority;

-- Lấy bridges cùng danh sách member interfaces
SELECT b.ifname AS bridge, bi.ifname AS member_if, bi.tag
FROM bridges b
JOIN bridge_interfaces bi ON bi.bridge_id = b.id;

-- Lấy policy kèm pqc_key liên kết
SELECT po.id AS policy_id, po.action, po.method, pk.key_id, pk.status
FROM ne_policies po
JOIN policy_pqc_ref ref ON ref.policy_id = po.id
JOIN pqc_keys pk ON pk.key_id = ref.key_id;

-- Lấy profile kèm tunnel liên kết
SELECT p.name AS profile_name, t.tunnel_name, t.mode
FROM ne_profiles p
JOIN profile_tunnel_ref ptr ON ptr.profile_id = p.id
JOIN pqc_exchange_tunnels t ON t.id = ptr.tunnel_id;


-- Tổng hợp từ profile

SELECT 
    -- Thông tin từ ne_profiles
    p.id AS profile_id,
    p.name AS profile_name,
    p.description AS profile_description,
    p.weight_enable,
    p.loss_enable,
    p.latency_enable,
    p.latency_duration,
    p.loss_duration,
    p.bridge_enable,
    p.tunnel_enable,    
    p.created_at AS profile_created_at,
    p.created_by AS profile_created_by,
    p.updated_at AS profile_updated_at,
    p.updated_by AS profile_updated_by,
    
    -- Thông tin từ ne_wan
    json_agg(DISTINCT jsonb_build_object(
        'id', w.id,
        'interface', w.interface,
        'dst_ip', w.dst_ip,
        'weight', w.weight,
        'latency_ip', w.latency_ip,
        'latency', w.latency,
        'latency_enable', w.latency_enable,
        'loss_ip', w.loss_ip,
        'loss_percentage', w.loss_percentage,
        'loss_enable', w.loss_enable
    )) FILTER (WHERE w.id IS NOT NULL) AS wan_interfaces,
    
    -- Thông tin từ ne_lan
    json_agg(DISTINCT jsonb_build_object(
        'id', l.id,
        'interface', l.interface
    )) FILTER (WHERE l.id IS NOT NULL) AS lan_interfaces,
    
    -- Thông tin từ pqc_keys (thông qua policy_pqc_ref và ne_policies)
    json_agg(DISTINCT jsonb_build_object(
        'key_id', pk.key_id,
        'status', pk.status,
        'local', pk.local,
        'remote', pk.remote,
        'created_at', pk.created_at,
        'created_by', pk.created_by,
        'updated_at', pk.updated_at,
        'updated_by', pk.updated_by
    )) FILTER (WHERE pk.key_id IS NOT NULL) AS pqc_keys,
    
    -- Thông tin từ pqc_exchange_tunnels (thông qua profile_tunnel_ref)
    json_agg(DISTINCT jsonb_build_object(
        'id', t.id,
        'tunnel_name', t.tunnel_name,
        'mode', t.mode,
        'client_tunnel_ip', t.client_tunnel_ip,
        'client_peer_public_ip', t.client_peer_public_ip,
        'client_peer_listen_port', t.client_peer_listen_port,
        'server_public_ip', t.server_public_ip,
        'private_key', t.private_key,
        'public_key', t.public_key,
        'peer_public_key', t.peer_public_key,
        'peer_tunnel_ip', t.peer_tunnel_ip,
        'created_at', t.created_at,
        'created_by', t.created_by,
        'updated_at', t.updated_at,
        'updated_by', t.updated_by
    )) FILTER (WHERE t.id IS NOT NULL) AS exchange_tunnels

FROM 
    ne_profiles p
    LEFT JOIN ne_wan w ON p.id = w.profile_id
    LEFT JOIN ne_lan l ON p.id = l.profile_id
    LEFT JOIN ne_policies pol ON p.id = pol.profile_id
    LEFT JOIN policy_pqc_ref ppr ON pol.id = ppr.policy_id
    LEFT JOIN pqc_keys pk ON ppr.key_id = pk.key_id
    LEFT JOIN profile_tunnel_ref ptr ON p.id = ptr.profile_id
    LEFT JOIN pqc_exchange_tunnels t ON ptr.tunnel_id = t.id
GROUP BY 
    p.id, p.name, p.description, p.weight_enable, p.loss_enable, 
    p.latency_enable, p.latency_duration, p.loss_duration,
    p.created_at, p.created_by, p.updated_at, p.updated_by
ORDER BY 
    p.id;