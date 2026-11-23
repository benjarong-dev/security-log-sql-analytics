-- =============================================================================
-- File: queries/01-threat-detection-queries.sql
-- Target DBMS: PostgreSQL 16+
-- Purpose: Production threat-hunting queries detecting SSH brute-force
--          compromises, VLAN 40 lateral port scans, and outbound exfiltration.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- QUERY 1: SSH Brute-Force Compromise Detection (Rolling 5-Minute Window)
-- Objective: Identify source IPs recording >= 5 failed SSH attempts within a
--            rolling 5-minute window that are immediately followed by an
--            ACCEPTED login on the same target host within 5 minutes.
-- Why it matters: Filters out noisy internet scanners (failures only) and
--                 isolates confirmed credential compromises.
-- -----------------------------------------------------------------------------
WITH auth_windowed AS (
    SELECT
        s.auth_id,
        s.source_ip,
        s.target_ip,
        s.username,
        s.auth_status,
        s.attempted_at,
        COUNT(*) FILTER (WHERE s.auth_status IN ('FAILED', 'INVALID_USER')) OVER (
            PARTITION BY s.source_ip, s.target_ip
            ORDER BY s.attempted_at
            RANGE BETWEEN INTERVAL '5 minutes' PRECEDING AND CURRENT ROW
        ) AS rolling_5m_failures,
        MIN(s.attempted_at) FILTER (WHERE s.auth_status IN ('FAILED', 'INVALID_USER')) OVER (
            PARTITION BY s.source_ip, s.target_ip
            ORDER BY s.attempted_at
            RANGE BETWEEN INTERVAL '5 minutes' PRECEDING AND CURRENT ROW
        ) AS first_failure_in_window,
        LEAD(s.auth_status) OVER (
            PARTITION BY s.source_ip, s.target_ip
            ORDER BY s.attempted_at
        ) AS next_auth_status,
        LEAD(s.attempted_at) OVER (
            PARTITION BY s.source_ip, s.target_ip
            ORDER BY s.attempted_at
        ) AS next_attempted_at,
        LEAD(s.username) OVER (
            PARTITION BY s.source_ip, s.target_ip
            ORDER BY s.attempted_at
        ) AS accepted_username
    FROM ssh_auth_logs AS s
    WHERE s.attempted_at >= TIMESTAMPTZ '2026-11-08 00:00:00+07'
      AND s.attempted_at <  TIMESTAMPTZ '2026-11-22 00:00:00+07'
)
SELECT
    w.source_ip                                      AS attacker_ip,
    COALESCE(src.hostname, 'external_unmanaged')     AS attacker_hostname,
    src.vlan_id                                      AS attacker_vlan,
    w.target_ip                                      AS compromised_host_ip,
    dst.hostname                                     AS compromised_hostname,
    dst.is_critical                                  AS is_critical_asset,
    w.accepted_username                              AS compromised_account,
    w.rolling_5m_failures                            AS failed_attempts_before_login,
    w.first_failure_in_window                        AS brute_force_started_at,
    w.next_attempted_at                              AS compromised_login_at,
    (w.next_attempted_at - w.first_failure_in_window) AS time_to_compromise
FROM auth_windowed AS w
INNER JOIN asset_inventory AS dst
    ON dst.ip_address = w.target_ip
LEFT JOIN asset_inventory AS src
    ON src.ip_address = w.source_ip
WHERE w.auth_status IN ('FAILED', 'INVALID_USER')
  AND w.rolling_5m_failures >= 5
  AND w.next_auth_status = 'ACCEPTED'
  AND w.next_attempted_at <= w.attempted_at + INTERVAL '5 minutes'
ORDER BY w.next_attempted_at DESC;


-- -----------------------------------------------------------------------------
-- QUERY 2: VLAN 40 Isolated IoT/CCTV Lateral Movement & Port Scan Audit
-- Objective: Detect endpoints inside the isolated CCTV subnet (192.168.40.0/24)
--            probing multiple internal RFC1918 subnets or >= 10 distinct ports
--            within any 1-hour window.
-- Index used: Partial index idx_fw_logs_dropped_recent (WHERE action = 'DROP').
-- -----------------------------------------------------------------------------
WITH cross_vlan_iot_drops AS (
    SELECT
        f.src_ip,
        f.dst_ip,
        f.dst_port,
        f.logged_at
    FROM firewall_flow_logs AS f
    WHERE f.action = 'DROP'
      AND f.logged_at >= TIMESTAMPTZ '2026-11-08 00:00:00+07'
      AND f.logged_at <  TIMESTAMPTZ '2026-11-22 00:00:00+07'
      AND f.src_ip << INET '192.168.40.0/24'
      AND NOT (f.dst_ip << INET '192.168.40.0/24')
      AND (
          f.dst_ip << INET '10.0.0.0/8'
          OR f.dst_ip << INET '172.16.0.0/12'
          OR f.dst_ip << INET '192.168.0.0/16'
      )
),
hourly_scan_summary AS (
    SELECT
        c.src_ip,
        DATE_TRUNC('hour', c.logged_at)                        AS scan_hour,
        COUNT(*)                                               AS blocked_packet_count,
        COUNT(DISTINCT c.dst_ip)                               AS distinct_targets_probed,
        COUNT(DISTINCT c.dst_port)                             AS distinct_ports_probed,
        ARRAY_AGG(DISTINCT HOST(c.dst_ip) ORDER BY HOST(c.dst_ip)) AS targeted_internal_ips,
        (ARRAY_AGG(DISTINCT c.dst_port ORDER BY c.dst_port))[1:10] AS sample_scanned_ports,
        MIN(c.logged_at)                                       AS scan_started_at,
        MAX(c.logged_at)                                       AS scan_ended_at
    FROM cross_vlan_iot_drops AS c
    GROUP BY c.src_ip, DATE_TRUNC('hour', c.logged_at)
    HAVING COUNT(DISTINCT c.dst_port) >= 10
        OR COUNT(DISTINCT c.dst_ip) >= 3
)
SELECT
    h.scan_hour,
    h.src_ip                AS scanner_ip,
    a.hostname              AS scanner_hostname,
    a.device_role           AS scanner_role,
    h.blocked_packet_count,
    h.distinct_targets_probed,
    h.distinct_ports_probed,
    CASE
        WHEN h.distinct_ports_probed >= 15 AND h.distinct_targets_probed >= 3
            THEN 'CRITICAL_HYBRID_RECON'
        WHEN h.distinct_ports_probed >= 10
            THEN 'HIGH_VERTICAL_PORTSCAN'
        ELSE 'MEDIUM_HORIZONTAL_SWEEP'
    END                     AS alert_severity,
    h.targeted_internal_ips,
    h.sample_scanned_ports,
    (h.scan_ended_at - h.scan_started_at) AS scan_burst_duration
FROM hourly_scan_summary AS h
INNER JOIN asset_inventory AS a
    ON a.ip_address = h.src_ip
ORDER BY h.blocked_packet_count DESC, h.scan_hour DESC;


-- -----------------------------------------------------------------------------
-- QUERY 3: Outbound Data Exfiltration Anomaly Detection (Hourly Z-Score > 2.5)
-- Objective: Calculate per-host historical hourly outbound transfer baselines
--            to external (non-RFC1918) IPs and flag hours exceeding +2.5 SD.
-- -----------------------------------------------------------------------------
WITH hourly_external_egress AS (
    SELECT
        f.src_ip,
        DATE_TRUNC('hour', f.logged_at) AS traffic_hour,
        COUNT(*)                        AS outbound_flow_count,
        SUM(f.bytes_sent)::NUMERIC      AS hourly_bytes_sent,
        (ARRAY_AGG(f.dst_ip ORDER BY f.bytes_sent DESC))[1] AS top_external_dst_ip
    FROM firewall_flow_logs AS f
    WHERE f.action = 'ACCEPT'
      AND f.logged_at >= TIMESTAMPTZ '2026-11-08 00:00:00+07'
      AND f.logged_at <  TIMESTAMPTZ '2026-11-22 00:00:00+07'
      AND NOT (
          f.dst_ip << INET '10.0.0.0/8'
          OR f.dst_ip << INET '172.16.0.0/12'
          OR f.dst_ip << INET '192.168.0.0/16'
      )
    GROUP BY f.src_ip, DATE_TRUNC('hour', f.logged_at)
),
host_egress_zscores AS (
    SELECT
        e.src_ip,
        e.traffic_hour,
        e.outbound_flow_count,
        e.hourly_bytes_sent,
        e.top_external_dst_ip,
        AVG(e.hourly_bytes_sent) OVER (PARTITION BY e.src_ip)         AS baseline_avg_bytes,
        STDDEV_SAMP(e.hourly_bytes_sent) OVER (PARTITION BY e.src_ip) AS baseline_stddev_bytes,
        (
            e.hourly_bytes_sent - AVG(e.hourly_bytes_sent) OVER (PARTITION BY e.src_ip)
        ) / NULLIF(STDDEV_SAMP(e.hourly_bytes_sent) OVER (PARTITION BY e.src_ip), 0) AS z_score
    FROM hourly_external_egress AS e
)
SELECT
    z.traffic_hour                                         AS anomaly_hour,
    z.src_ip                                               AS internal_host_ip,
    a.hostname                                             AS internal_hostname,
    a.vlan_id,
    a.is_critical,
    z.top_external_dst_ip                                  AS primary_destination_ip,
    ROUND((z.hourly_bytes_sent / 1048576.0)::NUMERIC, 2)   AS hourly_egress_mb,
    ROUND((z.baseline_avg_bytes / 1048576.0)::NUMERIC, 2)  AS baseline_avg_mb,
    ROUND(z.z_score::NUMERIC, 2)                           AS anomaly_z_score
FROM host_egress_zscores AS z
INNER JOIN asset_inventory AS a
    ON a.ip_address = z.src_ip
WHERE z.z_score > 2.5
ORDER BY z.z_score DESC;
