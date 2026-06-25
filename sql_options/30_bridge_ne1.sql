-- Requires: ./sh/ne_init_db.sh (schema.sql BE)
BEGIN;

DELETE FROM policy_pqc_ref WHERE policy_id IN (SELECT id FROM ne_policies WHERE profile_id = 30);
DELETE FROM ne_policies WHERE profile_id = 30;
DELETE FROM ne_lan WHERE profile_id = 30;
DELETE FROM ne_wan WHERE profile_id = 30;
DELETE FROM profile_bridge_ref WHERE profile_id = 30;
DELETE FROM ne_profiles WHERE id = 30;

INSERT INTO ne_profiles (
    id, name, description,
    weight_enable, latency_enable, loss_enable,
    bridge_enable, tunnel_enable,
    created_by, updated_by
) VALUES (
    30, 'profile_30', 'Bridge / dataplane test',
    TRUE, FALSE, FALSE,
    TRUE, FALSE,
    'seed', 'seed'
);

INSERT INTO ne_policies (
    id, profile_id, priority, action, protocol,
    src_ip, invert_src_ip, dst_ip, invert_dst_ip,
    src_port, dst_port, method, encryption_key
) VALUES (
    100, 30, 1, 'L2', 'tcp',
    ARRAY['192.168.70.2/32']::text[], FALSE,
    ARRAY['192.168.70.3/32']::text[], FALSE,
    NULL, ARRAY['7020']::text[],
    'aes-gcm-128', 'aac816a88e013feb4925f9f2af602b3f'
);

INSERT INTO ne_lan (interface, profile_id) VALUES
    ('eno3', 30);

INSERT INTO ne_wan (interface, profile_id, dst_ip, weight) VALUES
    ('eno4', 30, NULL, 100);

SELECT setval(pg_get_serial_sequence('ne_profiles', 'id')::regclass,
    COALESCE((SELECT MAX(id) FROM ne_profiles), 1), true);
SELECT setval(pg_get_serial_sequence('ne_policies', 'id')::regclass,
    COALESCE((SELECT MAX(id) FROM ne_policies), 1), true);
COMMIT;
