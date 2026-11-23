-- =============================================================================
-- File: schema/02-seed-security-logs.sql
-- Target DBMS: PostgreSQL 16+
-- Purpose: Deterministic baseline telemetry (~17,000+ rows across 14 days)
--          plus 3 injected security incidents for threat hunting & index tuning.
-- =============================================================================

BEGIN;

TRUNCATE TABLE ssh_auth_logs, firewall_flow_logs, asset_inventory
    RESTART IDENTITY CASCADE;

-- -----------------------------------------------------------------------------
-- 1. Seed Enterprise Asset Inventory (Aligned with VLAN 10/20/30/40 Architecture)
-- -----------------------------------------------------------------------------
INSERT INTO asset_inventory (ip_address, hostname, vlan_id, device_role, is_critical, created_at)
VALUES
    -- VLAN 10: Infrastructure & Management
    ('192.168.10.1',   'fw-core-gw01',       10, 'router_firewall',   TRUE,  '2026-11-01 08:00:00+07'),
    ('192.168.10.5',   'omada-sdn-ctrl01',   10, 'sdn_controller',    TRUE,  '2026-11-01 08:05:00+07'),
    ('192.168.10.10',  'pve-hypervisor01',   10, 'hypervisor',        TRUE,  '2026-11-01 08:10:00+07'),
    ('192.168.10.50',  'admin-thinkpad-p52', 10, 'admin_workstation', FALSE, '2026-11-01 08:15:00+07'),

    -- VLAN 20: Core Production Servers
    ('192.168.20.10',  'win-ad-dc01',        20, 'server',            TRUE,  '2026-11-01 08:20:00+07'),
    ('192.168.20.20',  'ubuntu-api-srv01',   20, 'server',            TRUE,  '2026-11-01 08:25:00+07'),
    ('192.168.20.30',  'grafana-mon-srv01',  20, 'server',            FALSE, '2026-11-01 08:30:00+07'),

    -- VLAN 30: Corporate Staff Wi-Fi
    ('192.168.30.2',   'eap650-ap-fl1',      30, 'access_point',      FALSE, '2026-11-01 08:35:00+07'),
    ('192.168.30.101', 'staff-laptop-hr01',  30, 'staff_endpoint',    FALSE, '2026-11-01 08:40:00+07'),
    ('192.168.30.102', 'staff-laptop-fin02', 30, 'staff_endpoint',    FALSE, '2026-11-01 08:45:00+07'),
    ('192.168.30.115', 'staff-laptop-dev03', 30, 'staff_endpoint',    FALSE, '2026-11-01 08:50:00+07'),

    -- VLAN 40: Isolated IoT & CCTV Network
    ('192.168.40.21',  'cctv-gate-mc200',    40, 'iot_cctv',          FALSE, '2026-11-01 08:55:00+07'),
    ('192.168.40.22',  'cctv-lobby-cam02',   40, 'iot_cctv',          FALSE, '2026-11-01 09:00:00+07'),
    ('192.168.40.23',  'cctv-parking-cam03', 40, 'iot_cctv',          FALSE, '2026-11-01 09:05:00+07');

-- -----------------------------------------------------------------------------
-- 2. Baseline Firewall Telemetry (14 Days = 336 Hours, ~16,800 Deterministic Rows)
--    Models routine outbound HTTPS/DNS, internal API/AD traffic, and CCTV NTP.
-- -----------------------------------------------------------------------------

-- 2A. Outbound HTTPS egress baseline for servers & staff (4 hosts x 336 hrs x 8 flows = 10,752 rows)
INSERT INTO firewall_flow_logs (src_ip, dst_ip, dst_port, protocol, action, bytes_sent, logged_at)
SELECT
    host_ip::INET AS src_ip,
    ('198.51.100.' || (10 + ((hr_idx + flow_idx) % 30)))::INET AS dst_ip,
    443 AS dst_port,
    'TCP' AS protocol,
    'ACCEPT' AS action,
    -- Deterministic normal hourly volume (~2.2 MB - 3.6 MB per flow => ~18 MB - 28 MB/hr per host)
    (2200000 + ((hr_idx * 137 + flow_idx * 509) % 1400000))::BIGINT AS bytes_sent,
    TIMESTAMPTZ '2026-11-08 00:00:00+07'
        + (hr_idx || ' hours')::INTERVAL
        + ((flow_idx * 7) || ' minutes')::INTERVAL AS logged_at
FROM generate_series(0, 335) AS hr_idx
CROSS JOIN generate_series(1, 8) AS flow_idx
CROSS JOIN (
    VALUES
        ('192.168.20.20'),
        ('192.168.30.101'),
        ('192.168.30.102'),
        ('192.168.30.115')
) AS hosts(host_ip);

-- 2B. Internal Staff-to-Server & Admin Management flows (336 hrs x 12 flows = 4,032 rows)
INSERT INTO firewall_flow_logs (src_ip, dst_ip, dst_port, protocol, action, bytes_sent, logged_at)
SELECT
    CASE (flow_idx % 4)
        WHEN 0 THEN '192.168.10.50'::INET
        WHEN 1 THEN '192.168.30.101'::INET
        WHEN 2 THEN '192.168.30.102'::INET
        ELSE        '192.168.30.115'::INET
    END AS src_ip,
    CASE (flow_idx % 3)
        WHEN 0 THEN '192.168.20.10'::INET
        WHEN 1 THEN '192.168.20.20'::INET
        ELSE        '192.168.20.30'::INET
    END AS dst_ip,
    CASE (flow_idx % 3)
        WHEN 0 THEN 389
        WHEN 1 THEN 443
        ELSE        3000
    END AS dst_port,
    'TCP' AS protocol,
    'ACCEPT' AS action,
    (45000 + ((hr_idx * 97 + flow_idx * 311) % 180000))::BIGINT AS bytes_sent,
    TIMESTAMPTZ '2026-11-08 00:03:00+07'
        + (hr_idx || ' hours')::INTERVAL
        + ((flow_idx * 4) || ' minutes')::INTERVAL AS logged_at
FROM generate_series(0, 335) AS hr_idx
CROSS JOIN generate_series(1, 12) AS flow_idx;

-- 2C. Baseline VLAN 40 CCTV NTP sync & routine blocked broadcast noise (336 hrs x 6 flows = 2,016 rows)
INSERT INTO firewall_flow_logs (src_ip, dst_ip, dst_port, protocol, action, bytes_sent, logged_at)
SELECT
    CASE (cam_idx)
        WHEN 1 THEN '192.168.40.21'::INET
        WHEN 2 THEN '192.168.40.22'::INET
        ELSE        '192.168.40.23'::INET
    END AS src_ip,
    CASE WHEN is_ntp = 1 THEN '192.168.10.1'::INET ELSE '192.168.40.255'::INET END AS dst_ip,
    CASE WHEN is_ntp = 1 THEN 123 ELSE 1900 END AS dst_port,
    'UDP' AS protocol,
    CASE WHEN is_ntp = 1 THEN 'ACCEPT' ELSE 'DROP' END AS action,
    CASE WHEN is_ntp = 1 THEN 96 ELSE 128 END AS bytes_sent,
    TIMESTAMPTZ '2026-11-08 00:10:00+07'
        + (hr_idx || ' hours')::INTERVAL
        + ((cam_idx * 5 + is_ntp) || ' minutes')::INTERVAL AS logged_at
FROM generate_series(0, 335) AS hr_idx
CROSS JOIN generate_series(1, 3) AS cam_idx
CROSS JOIN generate_series(0, 1) AS is_ntp;

-- -----------------------------------------------------------------------------
-- 3. Baseline SSH Authentication Telemetry (~700 Routine Events)
-- -----------------------------------------------------------------------------

-- 3A. Routine sysadmin SSH logins from ThinkPad P52 (VLAN 10)
INSERT INTO ssh_auth_logs (target_ip, source_ip, username, auth_status, attempted_at)
SELECT
    CASE (d % 3)
        WHEN 0 THEN '192.168.10.10'::INET
        WHEN 1 THEN '192.168.20.20'::INET
        ELSE        '192.168.20.30'::INET
    END AS target_ip,
    '192.168.10.50'::INET AS source_ip,
    'benjarong' AS username,
    -- Occasional single password typo (1 FAILED) that never crosses >= 5 brute-force threshold
    CASE WHEN (d % 17 = 0 AND s = 1) THEN 'FAILED' ELSE 'ACCEPTED' END AS auth_status,
    TIMESTAMPTZ '2026-11-08 09:00:00+07'
        + (d || ' hours')::INTERVAL
        + ((s * 2) || ' minutes')::INTERVAL AS attempted_at
FROM generate_series(0, 335, 2) AS d
CROSS JOIN generate_series(1, 2) AS s;

-- 3B. Unsuccessful external scanner noise (8 failures, NEVER followed by ACCEPTED)
INSERT INTO ssh_auth_logs (target_ip, source_ip, username, auth_status, attempted_at)
SELECT
    '192.168.20.20'::INET,
    '203.0.113.88'::INET,
    CASE WHEN attempt_no % 2 = 0 THEN 'root' ELSE 'admin' END,
    CASE WHEN attempt_no % 3 = 0 THEN 'INVALID_USER' ELSE 'FAILED' END,
    TIMESTAMPTZ '2026-11-18 23:40:00+07' + ((attempt_no * 18) || ' seconds')::INTERVAL
FROM generate_series(1, 8) AS attempt_no;

-- =============================================================================
-- 4. INJECTED SECURITY INCIDENTS (Ground Truth for Analytical Queries)
-- =============================================================================

-- INCIDENT 1: SSH Brute-Force Compromise
-- Source 192.168.30.115 triggers 6 failed attempts within ~2.5 mins against
-- ubuntu-api-srv01 (192.168.20.20), immediately followed by ACCEPTED login.
INSERT INTO ssh_auth_logs (target_ip, source_ip, username, auth_status, attempted_at)
VALUES
    ('192.168.20.20', '192.168.30.115', 'deploy', 'INVALID_USER', '2026-11-20 02:14:05+07'),
    ('192.168.20.20', '192.168.30.115', 'deploy', 'FAILED',       '2026-11-20 02:14:28+07'),
    ('192.168.20.20', '192.168.30.115', 'deploy', 'FAILED',       '2026-11-20 02:14:55+07'),
    ('192.168.20.20', '192.168.30.115', 'deploy', 'FAILED',       '2026-11-20 02:15:19+07'),
    ('192.168.20.20', '192.168.30.115', 'deploy', 'FAILED',       '2026-11-20 02:15:44+07'),
    ('192.168.20.20', '192.168.30.115', 'deploy', 'FAILED',       '2026-11-20 02:16:12+07'),
    ('192.168.20.20', '192.168.30.115', 'deploy', 'ACCEPTED',     '2026-11-20 02:16:38+07');

-- INCIDENT 2: VLAN 40 Compromised IoT Camera Lateral Port Scan
-- Camera 192.168.40.21 probes 18 distinct TCP service ports across VLAN 10 & VLAN 20
-- (54 SYN packets blocked by nftables segmentation policy).
INSERT INTO firewall_flow_logs (src_ip, dst_ip, dst_port, protocol, action, bytes_sent, logged_at)
SELECT
    '192.168.40.21'::INET AS src_ip,
    target_srv::INET AS dst_ip,
    scanned_port AS dst_port,
    'TCP' AS protocol,
    'DROP' AS action,
    60 AS bytes_sent,
    TIMESTAMPTZ '2026-11-20 03:10:00+07'
        + ((port_ord * 3 + srv_ord) || ' seconds')::INTERVAL AS logged_at
FROM unnest(
    ARRAY[21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 9200]
) WITH ORDINALITY AS p(scanned_port, port_ord)
CROSS JOIN unnest(
    ARRAY['192.168.10.10', '192.168.20.10', '192.168.20.20']
) WITH ORDINALITY AS s(target_srv, srv_ord);

-- INCIDENT 3: Outbound Data Exfiltration Anomaly (Post-SSH Compromise)
-- Between 02:22 and 02:49 on 2026-11-20, ubuntu-api-srv01 (192.168.20.20)
-- exfiltrates 1.85 GB (10 chunks x 185 MB) over TCP/443 to external host 198.51.100.240.
INSERT INTO firewall_flow_logs (src_ip, dst_ip, dst_port, protocol, action, bytes_sent, logged_at)
SELECT
    '192.168.20.20'::INET AS src_ip,
    '198.51.100.240'::INET AS dst_ip,
    443 AS dst_port,
    'TCP' AS protocol,
    'ACCEPT' AS action,
    185000000::BIGINT AS bytes_sent,
    TIMESTAMPTZ '2026-11-20 02:20:00+07' + ((chunk_id * 3) || ' minutes')::INTERVAL AS logged_at
FROM generate_series(1, 10) AS chunk_id;

COMMIT;

-- Refresh planner statistics immediately so B-tree indexes engage accurately
ANALYZE asset_inventory, firewall_flow_logs, ssh_auth_logs;
