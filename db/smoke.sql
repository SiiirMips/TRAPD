INSERT INTO trapd.events VALUES (now64(3), 'org_demo', 'sensor_01', 'auth_failed', '192.0.2.10', 54321, 22, 'TCP', 'high', '{"msg":"ssh bruteforce", "attempts": 5}');
SELECT ts, event_type, src_ip, severity FROM trapd.events ORDER BY ts DESC LIMIT 5;
