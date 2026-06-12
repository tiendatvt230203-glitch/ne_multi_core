BEGIN;

DELETE FROM ne_policies WHERE profile_id = 30;
DELETE FROM ne_lan WHERE profile_id = 30;
DELETE FROM ne_wan WHERE profile_id = 30;
DELETE FROM ne_profiles WHERE id = 30;
INSERT INTO ne_profiles (id, name, description, weight_enable, latency_enable, loss_enable, created_by)
VALUES (
    30, 'profile_30',
    'Profile test',
    TRUE, FALSE, FALSE, 'seed'
);


INSERT INTO ne_policies (
    id, profile_id, priority, action, proto,
    src_ip, invert_src_ip, dst_ip, invert_dst_ip,
    src_port, dst_port, method, encryption_key, created_by
) VALUES
(
    100, 30, 1, 'L2', 'tcp/udp',
    ARRAY['192.168.50.2/32']::text[], FALSE,
    ARRAY['192.168.50.3/32']::text[], FALSE,
    NULL, ARRAY['7020']::text[],
    'aes-gcm-128', 'aac816a88e013feb4925f9f2af602b3s', 'seed'
);


INSERT INTO ne_lan (interface,subnet,  profile_id, created_by) VALUES
    ('enp5s0', '192.168.50.0/24', 30, 'seed'),
    ('enp6s0', '192.168.60.0/24', 30, 'seed');

INSERT INTO ne_wan (interface, profile_id, dst_ip, weight, created_by) VALUES
    ('eno1', 30, NULL, 50, 'seed'),
    ('eno2', 30, NULL, 50, 'seed');

SELECT setval(pg_get_serial_sequence('ne_profiles', 'id')::regclass,
    COALESCE((SELECT MAX(id) FROM ne_profiles), 1), true);
COMMIT;