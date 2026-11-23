-- =============================================================================
-- File: queries/02-index-performance-tuning.sql
-- Target DBMS: PostgreSQL 16+
-- Purpose: Benchmark query execution plans and shared buffer hits using
--          EXPLAIN (ANALYZE, BUFFERS) across B-tree, Partial, and Covering
--          (INCLUDE) indexes.
-- =============================================================================

-- Ensure visibility map and planner statistics are up to date so PostgreSQL
-- can accurately evaluate Index Only Scans and selectivity estimates.
VACUUM ANALYZE asset_inventory, firewall_flow_logs, ssh_auth_logs;

-- -----------------------------------------------------------------------------
-- BENCHMARK 1A (ANTI-PATTERN): Non-SARGable Timestamp Filtering
-- Problem: Wrapping column logged_at inside timezone/date extraction functions
--          prevents B-tree traversal on idx_fw_logs_logged_at_action, forcing
--          a full Sequential Scan across all ~16,860+ rows.
-- -----------------------------------------------------------------------------
EXPLAIN (ANALYZE, BUFFERS)
SELECT
    f.src_ip,
    COUNT(*)         AS dropped_packets,
    MIN(f.logged_at) AS first_seen,
    MAX(f.logged_at) AS last_seen
FROM firewall_flow_logs AS f
WHERE DATE(f.logged_at AT TIME ZONE 'Asia/Bangkok') = DATE '2026-11-20'
  AND UPPER(f.action) = 'DROP'
GROUP BY f.src_ip
ORDER BY dropped_packets DESC;


-- -----------------------------------------------------------------------------
-- BENCHMARK 1B (OPTIMIZED): SARGable Half-Open Range Predicate
-- Fix: Keep indexed columns (logged_at, action) bare on the left-hand side.
--      PostgreSQL traverses composite B-tree idx_fw_logs_logged_at_action,
--      dramatically reducing shared buffer pages read.
-- -----------------------------------------------------------------------------
EXPLAIN (ANALYZE, BUFFERS)
SELECT
    f.src_ip,
    COUNT(*)         AS dropped_packets,
    MIN(f.logged_at) AS first_seen,
    MAX(f.logged_at) AS last_seen
FROM firewall_flow_logs AS f
WHERE f.logged_at >= TIMESTAMPTZ '2026-11-20 00:00:00+07'
  AND f.logged_at <  TIMESTAMPTZ '2026-11-21 00:00:00+07'
  AND f.action = 'DROP'
GROUP BY f.src_ip
ORDER BY dropped_packets DESC;


-- -----------------------------------------------------------------------------
-- BENCHMARK 2: Partial Index Efficiency for Blocked Lateral Scan Forensics
-- Why it works: Blocked flows ('DROP') represent ~6% of total firewall volume.
--               Partial index idx_fw_logs_dropped_recent indexes ONLY dropped
--               rows, minimizing B-tree depth and buffer cache footprint.
-- -----------------------------------------------------------------------------
EXPLAIN (ANALYZE, BUFFERS)
SELECT
    f.dst_ip,
    f.dst_port,
    f.logged_at
FROM firewall_flow_logs AS f
WHERE f.action = 'DROP'
  AND f.src_ip = INET '192.168.40.21'
  AND f.logged_at >= TIMESTAMPTZ '2026-11-20 03:00:00+07'
  AND f.logged_at <  TIMESTAMPTZ '2026-11-20 04:00:00+07'
ORDER BY f.dst_ip, f.dst_port;


-- -----------------------------------------------------------------------------
-- BENCHMARK 3: Covering Index (INCLUDE) & Sort Elimination on Window Functions
-- Why it works: idx_ssh_window_partition is keyed on (source_ip, target_ip,
--               attempted_at) and includes (auth_status, username) as payload.
--               PostgreSQL reads pre-ordered tuples via Index Only Scan with
--               zero explicit Sort node for the rolling 5-minute window.
-- -----------------------------------------------------------------------------
EXPLAIN (ANALYZE, BUFFERS)
SELECT
    s.source_ip,
    s.target_ip,
    s.username,
    s.auth_status,
    s.attempted_at,
    COUNT(*) FILTER (WHERE s.auth_status IN ('FAILED', 'INVALID_USER')) OVER (
        PARTITION BY s.source_ip, s.target_ip
        ORDER BY s.attempted_at
        RANGE BETWEEN INTERVAL '5 minutes' PRECEDING AND CURRENT ROW
    ) AS rolling_5m_failures
FROM ssh_auth_logs AS s
WHERE s.source_ip = INET '192.168.30.115'
  AND s.target_ip = INET '192.168.20.20'
  AND s.attempted_at >= TIMESTAMPTZ '2026-11-20 02:00:00+07'
  AND s.attempted_at <  TIMESTAMPTZ '2026-11-20 03:00:00+07';


-- -----------------------------------------------------------------------------
-- BENCHMARK 4: Index Footprint & Scan Counter Audit (Catalog Verification)
-- Purpose: Inspect physical index sizes and confirm index scan utilization
--          after executing analytical workloads.
-- -----------------------------------------------------------------------------
SELECT
    schemaname                                      AS schema_name,
    relname                                         AS table_name,
    indexrelname                                    AS index_name,
    idx_scan                                        AS index_scans,
    idx_tup_read                                    AS tuples_read,
    idx_tup_fetch                                   AS heap_tuples_fetched,
    pg_size_pretty(pg_relation_size(indexrelid))    AS index_size
FROM pg_stat_user_indexes
WHERE relname IN ('asset_inventory', 'firewall_flow_logs', 'ssh_auth_logs')
ORDER BY relname, pg_relation_size(indexrelid) DESC;
