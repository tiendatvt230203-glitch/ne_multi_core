-- Requires: ./sh/ne_init_db.sh (schema.sql BE)
BEGIN;

DELETE FROM policy_pqc_ref WHERE policy_id IN (SELECT id FROM ne_policies WHERE profile_id = 31);
DELETE FROM ne_policies WHERE profile_id = 31;
DELETE FROM ne_lan WHERE profile_id = 31;
DELETE FROM ne_wan WHERE profile_id = 31;
DELETE FROM profile_bridge_ref WHERE profile_id = 31;
DELETE FROM ne_profiles WHERE id = 31;

INSERT INTO ne_profiles (
    id, name, description,
    weight_enable, latency_enable, loss_enable,
    bridge_enable, tunnel_enable,
    created_by, updated_by
) VALUES (
    31, 'profile31', 'Profile test',
    TRUE, FALSE, FALSE,
    FALSE, FALSE,
    'seed', 'seed'
);

INSERT INTO ne_policies (
    id, profile_id, priority, action, protocol,
    src_ip, invert_src_ip, dst_ip, invert_dst_ip,
    src_port, dst_port, method, encryption_key
) VALUES
(
    101, 31, 1, 'L2', 'tcp',
    ARRAY['192.168.50.2/32']::text[], FALSE,
    ARRAY['192.168.50.3/32']::text[], FALSE,
    NULL, ARRAY['7004']::text[],
    'aes-gcm-128', 'aac816a88e013feb4925f9f2af602b3f'
),
(
    102, 31, 2, 'L2', 'tcp',
    ARRAY['192.168.50.2/32']::text[], FALSE,
    ARRAY['192.168.50.3/32']::text[], FALSE,
    NULL, ARRAY['7005']::text[],
    'aes-gcm-256', '13c2082bfb3f7fe8fcb3c81614ecbf1dce2539279ceb0eeec9c4989c2eed57b1'
),
(
    103, 31, 3, 'L2', 'tcp',
    ARRAY['192.168.50.2/32']::text[], FALSE,
    ARRAY['192.168.50.3/32']::text[], FALSE,
    NULL, ARRAY['7006']::text[],
    'aes-ctr-128', 'b3d0a102cbb4fd0d2a3c0b2416cae613'
),
(
    104, 31, 4, 'L2', 'tcp',
    ARRAY['192.168.50.2/32']::text[], FALSE,
    ARRAY['192.168.50.3/32']::text[], FALSE,
    NULL, ARRAY['7007']::text[],
    'aes-ctr-256', 'f52964727db9e0defd9b5b578bdef0af17a369834b14b1d4362d1973a6ca07bb'
),
(
    105, 31, 5, 'L2', 'tcp',
    ARRAY['192.168.50.2/32']::text[], FALSE,
    ARRAY['192.168.50.3/32']::text[], FALSE,
    NULL, ARRAY['7008']::text[],
    'aes-gcm-256', '344d9d66e66abd7f5c2ca3ba3f160b34c757ebcfc75ed2a1bb264c773af75d1e'
),
(
    106, 31, 6, 'L2', 'tcp',
    ARRAY['192.168.50.2/32']::text[], FALSE,
    ARRAY['192.168.50.3/32']::text[], FALSE,
    NULL, ARRAY['7009']::text[],
    'aes-gcm-256', '06977c53356f3ebd658fb4000412ed388747123c7c1972bc28ccb59cb03908c4'
),
(
    107, 31, 7, 'L2', 'tcp',
    ARRAY['192.168.60.2/32']::text[], FALSE,
    ARRAY['192.168.60.3/32']::text[], FALSE,
    NULL, ARRAY['7010']::text[],
    'aes-gcm-256', '8bf23b1f8bd5719dcdaccd99e643d257397898e401ae27fd8218c7b724370933'
),
(
    108, 31, 8, 'L3', 'tcp',
    ARRAY['192.168.50.2/32']::text[], FALSE,
    ARRAY['192.168.50.3/32']::text[], FALSE,
    NULL, ARRAY['7011']::text[],
    'aes-gcm-256', '8bf23b1f8bd5719dcdaccd99e643d257397898e401ae27fd8218c7b724370933'
),
(
    109, 31, 9, 'bypass', NULL,
    NULL, FALSE,
    NULL, FALSE,
    NULL, NULL,
    NULL, NULL
);

INSERT INTO ne_lan (interface, profile_id) VALUES
    ('enp6s0', 31),
    ('enp5s0', 31);

INSERT INTO ne_wan (interface, profile_id, dst_ip, weight) VALUES
    ('enp7s0', 31, NULL, 50),
    ('enp8s0', 31, NULL, 50);

SELECT setval(pg_get_serial_sequence('ne_profiles', 'id')::regclass,
    COALESCE((SELECT MAX(id) FROM ne_profiles), 1), true);
SELECT setval(pg_get_serial_sequence('ne_policies', 'id')::regclass,
    COALESCE((SELECT MAX(id) FROM ne_policies), 1), true);
COMMIT;
