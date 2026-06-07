BEGIN;

DELETE FROM ne_policies WHERE profile_id = 123;
DELETE FROM ne_lan WHERE profile_id = 123;
DELETE FROM ne_wan WHERE profile_id = 123;
DELETE FROM ne_profiles WHERE id = 123;

INSERT INTO ne_profiles (id, name, description, weight_enable, latency_enable, loss_enable, created_by)
VALUES (
    123, 'profile123',
    '',
    TRUE, FALSE, FALSE, 'seed'
);

INSERT INTO ne_policies (
    id, profile_id, priority, action, proto,
    src_ip, invert_src_ip, dst_ip, invert_dst_ip,
    src_port, dst_port, method, nonce, encryption_key, created_by
) VALUES
(
    10, 123, 1, 'L2', NULL,
    ARRAY['192.168.50.2/32']::text[], FALSE,
    ARRAY['192.168.50.3/32']::text[], FALSE,
    NULL, ARRAY['7002']::text[],
    'aes-gcm-128', 12, '87e3855f04321a1a7c661a283570b5bd', 'seed'
);

INSERT INTO ne_lan (interface, subnet, profile_id, created_by) VALUES
    ('enp5s0', '192.168.50.0/24', 123, 'seed');


INSERT INTO ne_wan (interface, profile_id, dst_ip, weight, created_by) VALUES
    ('enp7s0', 123, NULL, 50, 'seed'),
    ('enp8s0', 123, NULL, 50, 'seed'),
    ('enp6s0', 123, '192.168.8.1/24', NULL, 'seed');

SELECT setval(pg_get_serial_sequence('ne_profiles', 'id')::regclass,
    COALESCE((SELECT MAX(id) FROM ne_profiles), 1), true);

COMMIT;