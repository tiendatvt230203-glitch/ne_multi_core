BEGIN;

DELETE FROM ne_policies WHERE profile_id = 30;
DELETE FROM ne_lan WHERE profile_id = 30;
DELETE FROM ne_wan WHERE profile_id = 30;
DELETE FROM ne_profiles WHERE id = 30;

-- Thêm profile mới
INSERT INTO ne_profiles (id, name, description, weight_enable, latency_enable, loss_enable, created_by)
VALUES (
    30, 'profile30',
    '',
    TRUE, FALSE, FALSE, 'seed'
);

INSERT INTO ne_policies (
    id, profile_id, priority, action, proto,
    src_ip, invert_src_ip, dst_ip, invert_dst_ip,
    src_port, dst_port, method, nonce, encryption_key, created_by
) VALUES
(
    10, 30, 1, 'L2', NULL,
    ARRAY['192.168.9.2/32']::text[], FALSE,
    ARRAY['192.168.180.2/32']::text[], FALSE,
    NULL, ARRAY['7002']::text[],
    'aes-gcm-128', 12, '87e3855f04321a1a7c661a283570b5bd', 'seed'
),
(
    20, 30, 2, 'L3', NULL,
    ARRAY['192.168.9.2/32']::text[], FALSE,
    ARRAY['192.168.180.2/32']::text[], FALSE,
    NULL, ARRAY['7003']::text[],

    'aes-gcm-128', 12, '1234fc1037ab91a5702b4874b2d293a1', 'seed'
),
(
    30, 30, 3, 'L4', NULL,
    ARRAY['192.168.9.2/32']::text[], FALSE,
    ARRAY['192.168.180.2/32']::text[], FALSE,
    NULL, ARRAY['7004']::text[],
    'aes-gcm-128', 12, 'aac816a88e013feb4925f9f2af602b3f', 'seed'
),
(
    40, 30, 4, 'L2', NULL,
    ARRAY['192.168.9.2/32']::text[], FALSE,
    ARRAY['192.168.180.2/32']::text[], FALSE,
    NULL, ARRAY['7004']::text[],
    'pqc-gcm', 12, NULL, 'seed'
);
-- (
--     40, 30, 4, 'bypass', NULL,
--     NULL, FALSE,
--     NULL, FALSE,
--     NULL, NULL,
--     NULL, NULL, NULL, 'seed'
-- );


INSERT INTO ne_lan (interface, profile_id, created_by) VALUES
    ('enp5s0', 30, 'seed');


INSERT INTO ne_wan (interface, profile_id, dst_ip, weight, created_by) VALUES
    ('enp7s0', 30, NULL, 75, 'seed'),
    ('enp8s0', 30, NULL, 25, 'seed');


SELECT setval(pg_get_serial_sequence('ne_profiles', 'id')::regclass,
    COALESCE((SELECT MAX(id) FROM ne_profiles), 1), true);

COMMIT;
