BEGIN;

DELETE FROM ne_policies WHERE profile_id = 31;
DELETE FROM ne_lan WHERE profile_id = 31;
DELETE FROM ne_wan WHERE profile_id = 31;
DELETE FROM ne_profiles WHERE id = 31;


INSERT INTO ne_profiles (id, name, description, weight_enable, latency_enable, loss_enable, created_by)
VALUES (
    31, 'profile31',
    'Profile Test',
    TRUE, FALSE, FALSE, 'seed'
);

INSERT INTO ne_policies (
    id, profile_id, priority, action, proto,
    src_ip, invert_src_ip, dst_ip, invert_dst_ip,
    src_port, dst_port, method, encryption_key, created_by
) VALUES
(
    -- Port 7004: Layer 2, AES-GCM-128
    1, 31, 1, 'L2', 'tcp/udp',
    ARRAY['192.168.50.2/32']::text[], FALSE,
    ARRAY['192.168.50.3/32']::text[], FALSE,
    NULL, ARRAY['7004']::text[],
    'aes-gcm-128', 'aac816a88e013feb4925f9f2af602b3f', 'seed'
),
(
    -- Port 7005: Layer 2, AES-GCM-256
    2, 31, 2, 'L2', 'tcp/udp',
    ARRAY['192.168.50.2/32']::text[], FALSE,
    ARRAY['192.168.50.3/32']::text[], FALSE,
    NULL, ARRAY['7005']::text[],
    'aes-gcm-256', '13c2082bfb3f7fe8fcb3c81614ecbf1dce2539279ceb0eeec9c4989c2eed57b1', 'seed'
),
(
    -- Port 7006: Layer 2, AES-CTR-128
    3, 31, 3, 'L2', 'tcp/udp',
    ARRAY['192.168.50.2/32']::text[], FALSE,
    ARRAY['192.168.50.3/32']::text[], FALSE,
    NULL, ARRAY['7006']::text[],
    'aes-ctr-128', 'b3d0a102cbb4fd0d2a3c0b2416cae613', 'seed'
),
(
    -- Port 7007: Layer 2, AES-CTR-256
    4, 31, 4, 'L2', 'tcp/udp',
    ARRAY['192.168.50.2/32']::text[], FALSE,
    ARRAY['192.168.50.3/32']::text[], FALSE,
    NULL, ARRAY['7007']::text[],
    'aes-ctr-256', 'f52964727db9e0defd9b5b578bdef0af17a369834b14b1d4362d1973a6ca07bb', 'seed'
),
(
    -- Port 7008: Layer 3, AES-GCM-256
    5, 31, 5, 'L3', 'tcp/udp',
    ARRAY['192.168.50.2/32']::text[], FALSE,
    ARRAY['192.168.50.3/32']::text[], FALSE,
    NULL, ARRAY['7008']::text[],
    'aes-gcm-256', '344d9d66e66abd7f5c2ca3ba3f160b34c757ebcfc75ed2a1bb264c773af75d1e', 'seed'
),
(
    -- Port 7009: Layer 4, AES-GCM-256
    6, 31, 6, 'L4', 'tcp/udp',
    ARRAY['192.168.50.2/32']::text[], FALSE,
    ARRAY['192.168.50.3/32']::text[], FALSE,
    NULL, ARRAY['7009']::text[],
    'aes-gcm-256', '06977c53356f3ebd658fb4000412ed388747123c7c1972bc28ccb59cb03908c4', 'seed'
),
(
    -- Port 7010: Layer 2, PQC-GCM
    7, 31, 7, 'L2', 'tcp/udp',
    ARRAY['192.168.50.2/32']::text[], FALSE,
    ARRAY['192.168.50.3/32']::text[], FALSE,
    NULL, ARRAY['7010']::text[],
    'pqc-gcm', NULL, 'seed'
),
(
    -- Rule cuối: Bypass traffic còn lại
    8, 31, 8, 'bypass', NULL,
    NULL, FALSE,
    NULL, FALSE,
    NULL, NULL,
    NULL, NULL, 'seed'
);


INSERT INTO ne_lan (interface, subnet, profile_id, created_by) VALUES
    ('enp5s0', '192.168.50.0/24', 31, 'seed');


INSERT INTO ne_wan (interface, profile_id, dst_ip, weight, created_by) VALUES
    ('enp7s0', 31, NULL, 50, 'seed'),
    ('enp8s0', 31, NULL, 50, 'seed'),
    ('enp6s0', 31, '192.168.8.2/24', NULL, 'seed');

SELECT setval(pg_get_serial_sequence('ne_profiles', 'id')::regclass,
    COALESCE((SELECT MAX(id) FROM ne_profiles), 1), true);

COMMIT;
