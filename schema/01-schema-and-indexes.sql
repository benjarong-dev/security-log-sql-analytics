-- =============================================================================
-- File: schema/01-schema-and-indexes.sql
-- Target DBMS: PostgreSQL 16+
-- Purpose: Normalized schema, domain constraints, and B-tree/partial indexes
--          for enterprise VLAN firewall (nftables) and SSH (sshd) telemetry.
-- =============================================================================

BEGIN;

DROP TABLE IF EXISTS ssh_auth_logs CASCADE;
DROP TABLE IF EXISTS firewall_flow_logs CASCADE;
DROP TABLE IF EXISTS asset_inventory CASCADE;

-- -----------------------------------------------------------------------------
-- 1. Enterprise Asset Inventory (VLAN 10, 20, 30, 40)
--    Uses native PostgreSQL INET type to support subnet containment (<<, >>).
-- -----------------------------------------------------------------------------
CREATE TABLE asset_inventory (
    asset_id      SERIAL PRIMARY KEY,
    ip_address    INET NOT NULL UNIQUE,
    hostname      VARCHAR(64) NOT NULL UNIQUE,
    vlan_id       SMALLINT NOT NULL CHECK (vlan_id IN (10, 20, 30, 40)),
    device_role   VARCHAR(32) NOT NULL CHECK (
        device_role IN (
            'router_firewall',
            'sdn_controller',
            'hypervisor',
            'admin_workstation',
            'server',
            'access_point',
            'staff_endpoint',
            'iot_cctv'
        )
    ),
    is_critical   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 2. Stateful Firewall Flow Telemetry (nftables forward/output chains)
-- -----------------------------------------------------------------------------
CREATE TABLE firewall_flow_logs (
    flow_id       BIGSERIAL PRIMARY KEY,
    src_ip        INET NOT NULL REFERENCES asset_inventory(ip_address) ON UPDATE CASCADE,
    dst_ip        INET NOT NULL,
    dst_port      INTEGER NOT NULL CHECK (dst_port BETWEEN 0 AND 65535),
    protocol      VARCHAR(8) NOT NULL CHECK (protocol IN ('TCP', 'UDP', 'ICMP')),
    action        VARCHAR(8) NOT NULL CHECK (action IN ('ACCEPT', 'DROP', 'REJECT')),
    bytes_sent    BIGINT NOT NULL CHECK (bytes_sent >= 0),
    logged_at     TIMESTAMPTZ NOT NULL
);

-- -----------------------------------------------------------------------------
-- 3. SSH Daemon Authentication Telemetry (sshd)
-- -----------------------------------------------------------------------------
CREATE TABLE ssh_auth_logs (
    auth_id       BIGSERIAL PRIMARY KEY,
    target_ip     INET NOT NULL REFERENCES asset_inventory(ip_address) ON UPDATE CASCADE,
    source_ip     INET NOT NULL,
    username      VARCHAR(64) NOT NULL,
    auth_status   VARCHAR(16) NOT NULL CHECK (
        auth_status IN ('FAILED', 'ACCEPTED', 'INVALID_USER')
    ),
    attempted_at  TIMESTAMPTZ NOT NULL
);

-- -----------------------------------------------------------------------------
-- 4. Indexing Strategy for Analytical & Time-Series Workloads
-- -----------------------------------------------------------------------------

-- Supports SARGable time-range filtering and action aggregation on firewall flows
CREATE INDEX idx_fw_logs_logged_at_action
    ON firewall_flow_logs (logged_at, action);

-- Supports per-host port scan detection and egress volume baselines
CREATE INDEX idx_fw_logs_src_dst_port
    ON firewall_flow_logs (src_ip, dst_port, logged_at);

-- Partial index accelerating security audits focused strictly on blocked traffic
CREATE INDEX idx_fw_logs_dropped_recent
    ON firewall_flow_logs (src_ip, dst_ip, dst_port, logged_at)
    WHERE action = 'DROP';

-- Supports time-bounded authentication audits by status
CREATE INDEX idx_ssh_status_attempted_at
    ON ssh_auth_logs (auth_status, attempted_at);

-- Eliminates sort overhead for rolling-window brute-force detection:
-- OVER (PARTITION BY source_ip, target_ip ORDER BY attempted_at)
CREATE INDEX idx_ssh_window_partition
    ON ssh_auth_logs (source_ip, target_ip, attempted_at)
    INCLUDE (auth_status, username);

COMMIT;
