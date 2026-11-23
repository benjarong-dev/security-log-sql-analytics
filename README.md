# security-log-sql-analytics
PostgreSQL security telemetry analytics: SSH brute-force window detection, VLAN lateral movement hunting, Z-score egress anomaly analysis, and B-tree index tuning.

# Network & Security Telemetry SQL Analytics (PostgreSQL)

Analytical SQL repository focused on threat hunting, segmentation policy auditing, and query performance optimization using **PostgreSQL 16**. The dataset models firewall (`nftables`) and authentication (`sshd`) telemetry collected from a segmented enterprise network (`VLAN 10` Management, `VLAN 20` Core Servers, `VLAN 30` Staff Wi-Fi, and `VLAN 40` Isolated IoT/CCTV).

## Relational Schema Overview

```text
+-------------------------+       +----------------------------------+
|      asset_inventory    |       |       firewall_flow_logs         |
+-------------------------+       +----------------------------------+
| PK asset_id (SERIAL)    |<---+  | PK flow_id (BIGSERIAL)           |
| UQ ip_address (INET)    |    +--| FK src_ip (INET)                 |
|    hostname (VARCHAR)   |       |    dst_ip (INET)                 |
|    vlan_id (SMALLINT)   |       |    dst_port (INTEGER)            |
|    device_role (VARCHAR)|       |    protocol (VARCHAR)            |
|    is_critical (BOOLEAN)|       |    action (VARCHAR: ACCEPT/DROP) |
+-------------------------+       |    bytes_sent (BIGINT)           |
             ^                    |    logged_at (TIMESTAMPTZ)       |
             |                    +----------------------------------+
             |                    Idx: idx_fw_logs_logged_at_action
             |                    Idx: idx_fw_logs_src_dst_port
             |
             |                    +----------------------------------+
             |                    |          ssh_auth_logs           |
             |                    +----------------------------------+
             |                    | PK auth_id (BIGSERIAL)           |
             +--------------------| FK target_ip (INET)              |
                                  |    source_ip (INET)              |
                                  |    username (VARCHAR)            |
                                  |    auth_status (VARCHAR)         |
                                  |    attempted_at (TIMESTAMPTZ)    |
                                  +----------------------------------+
                                  Idx: idx_ssh_status_attempted_at
```

## Repository Structure

- `schema/01-schema-and-indexes.sql` — Normalized PostgreSQL DDL (`INET`, `TIMESTAMPTZ`, `CHECK` constraints) and composite B-tree indexes.
- `schema/02-seed-security-logs.sql` — Reproducible telemetry dataset containing baseline traffic alongside injected security incidents.
- `queries/01-threat-detection-queries.sql` — Production analytical queries covering brute-force compromises, lateral port scanning, and anomalous outbound data transfers.
- `queries/02-index-performance-tuning.sql` — SARGable vs. non-SARGable predicate refactoring verified with `EXPLAIN (ANALYZE, BUFFERS)`.

## Analytical Scenarios & SQL Techniques

| Scenario | Security Objective | Core SQL Features Used |
|---|---|---|
| **1. SSH Brute-Force Compromise** | Detect IPs triggering >= 5 failed logins within a rolling 5-minute window followed by a successful login | `COUNT(*) OVER (PARTITION BY ... ORDER BY ... RANGE BETWEEN INTERVAL '5 minutes' PRECEDING AND CURRENT ROW)`, `LEAD()` |
| **2. VLAN 40 Lateral Movement Scan** | Audit isolated IoT/CCTV endpoints (`192.168.40.0/24`) attempting horizontal/vertical scans against RFC1918 subnets | Multi-CTE pipeline, `COUNT(DISTINCT dst_port)`, `INET` subnet containment (`<<`), `JOIN` enrichment |
| **3. Egress Exfiltration Anomaly** | Flag internal hosts whose hourly outbound byte volume exceeds 2.5 standard deviations above their historical baseline | `DATE_TRUNC()`, Window aggregates (`AVG() OVER`, `STDDEV_SAMP() OVER`), Z-score calculation (`NULLIF`) |
| **4. Time-Series Index Optimization** | Eliminate full table scans on timestamp filters by replacing function-wrapped columns with SARGable range predicates | Composite B-tree indexing, `EXPLAIN (ANALYZE, BUFFERS)` execution plan comparison |

## Local Verification (PostgreSQL CLI)

```bash
# 1. Create local test database
createdb sec_telemetry_lab

# 2. Initialize tables, constraints, and composite indexes
psql -d sec_telemetry_lab -f schema/01-schema-and-indexes.sql

# 3. Load baseline and incident telemetry data
psql -d sec_telemetry_lab -f schema/02-seed-security-logs.sql

# 4. Run threat hunting and performance verification queries
psql -d sec_telemetry_lab -f queries/01-threat-detection-queries.sql
psql -d sec_telemetry_lab -f queries/02-index-performance-tuning.sql
```
