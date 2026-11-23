# Network & Security Telemetry SQL Analytics (PostgreSQL 16)

Analytical SQL repository focused on threat hunting, VLAN segmentation auditing, and B-tree/partial index optimization using **PostgreSQL 16**. The dataset models stateful firewall (`nftables`) and authentication (`sshd`) telemetry collected across a segmented enterprise network (`VLAN 10` Management, `VLAN 20` Core Servers, `VLAN 30` Staff Wi-Fi, and `VLAN 40` Isolated IoT/CCTV).

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
             |                    Idx: idx_fw_logs_logged_at_action (336 kB)
             |                    Idx: idx_fw_logs_src_dst_port (1088 kB)
             |                    Idx: idx_fw_logs_dropped_recent (80 kB, Partial)
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
                                  Idx: idx_ssh_window_partition (56 kB, INCLUDE)
                                  Idx: idx_ssh_status_attempted_at (40 kB)
```

## Repository Structure

- `schema/01-schema-and-indexes.sql` — Normalized PostgreSQL DDL (`INET`, `TIMESTAMPTZ`, `CHECK` constraints) alongside B-tree, partial, and covering (`INCLUDE`) indexes.
- `schema/02-seed-security-logs.sql` — Reproducible 14-day telemetry dataset (~17,200+ rows) containing baseline traffic and 3 injected security incidents.
- `queries/01-threat-detection-queries.sql` — Production threat-hunting queries covering SSH brute-force compromises, lateral port scans, and anomalous data exfiltration.
- `queries/02-index-performance-tuning.sql` — SARGable vs. non-SARGable execution plan benchmarks verified with `EXPLAIN (ANALYZE, BUFFERS)`.

## Threat-Hunting Scenarios & Verified Detections

| Scenario | Security Objective | Core SQL Features | Verified Detection Summary |
|---|---|---|---|
| **1. SSH Brute-Force Compromise** | Detect IPs triggering >= 5 failures within a rolling 5-minute window followed by an `ACCEPTED` login | `COUNT(*) FILTER (...) OVER (... RANGE BETWEEN INTERVAL '5 minutes' PRECEDING AND CURRENT ROW)`, `LEAD()` | Flagged `192.168.30.115` (`staff-laptop-dev03`) compromising `deploy@192.168.20.20` after 6 failures in `00:02:33` while ignoring external scanner noise |
| **2. VLAN 40 Lateral Port Scan** | Audit isolated CCTV endpoints (`192.168.40.0/24`) probing internal RFC1918 subnets | Multi-CTE pipeline, `INET` containment (`<<`), `ARRAY_AGG(DISTINCT ...)` | Flagged `192.168.40.21` (`cctv-gate-mc200`) sending 54 blocked SYN probes across 18 ports on 3 servers in `00:00:53` |
| **3. Egress Exfiltration Anomaly** | Identify internal hosts exceeding +2.5 SD above their historical hourly outbound transfer baseline | `DATE_TRUNC()`, Window `AVG() OVER` & `STDDEV_SAMP() OVER`, `NULLIF` Z-score | Flagged `192.168.20.20` (`ubuntu-api-srv01`) transferring `1,781.40 MB/hr` to `198.51.100.240` vs. `22.23 MB/hr` baseline (`Z = 18.28`) |

## Verified Benchmark Results (PostgreSQL 16.15 on Linux x86_64)

Measured with `EXPLAIN (ANALYZE, BUFFERS)` after `VACUUM ANALYZE` on 16,864 firewall flow records and 351 SSH authentication events:

| Benchmark Case | Execution Plan Selected | Shared Buffers Hit | Execution Time | Key Optimization Outcome |
|---|---|---|---|---|
| **1A. Non-SARGable Date Filter** (`DATE(logged_at AT TIME ZONE ...)`) | `Seq Scan` (`16,738` rows filtered out) | `174` pages | `4.666 ms` | Anti-pattern baseline: function wrapper disables index traversal |
| **1B. SARGable Half-Open Range** (`logged_at >= ... AND logged_at < ...`) | `Index Only Scan` (`idx_fw_logs_dropped_recent`, `Heap Fetches: 0`) | `10` pages | `0.100 ms` | **46.7x faster**, **94.3% reduction** in shared buffer reads |
| **2. Blocked Lateral Scan Forensics** (`WHERE action = 'DROP' AND src_ip = ...`) | `Index Only Scan` (`idx_fw_logs_dropped_recent`, `Heap Fetches: 0`) | `5` pages | `0.059 ms` | Partial index consumes **80 kB** vs. **1,088 kB** full index (**92.6% smaller**) |
| **3. Rolling 5-Min SSH Window** (`OVER (PARTITION BY ... ORDER BY attempted_at)`) | `WindowAgg` -> `Index Only Scan` (`idx_ssh_window_partition`) | `3` pages | `0.050 ms` | Covering `INCLUDE` index eliminates explicit `Sort` node completely |

## Local Verification (PostgreSQL CLI)

```bash
createdb sec_telemetry_lab
psql -v ON_ERROR_STOP=1 -d sec_telemetry_lab -f schema/01-schema-and-indexes.sql
psql -v ON_ERROR_STOP=1 -d sec_telemetry_lab -f schema/02-seed-security-logs.sql

psql -P pager=off -d sec_telemetry_lab -f queries/01-threat-detection-queries.sql
psql -P pager=off -d sec_telemetry_lab -f queries/02-index-performance-tuning.sql
```
