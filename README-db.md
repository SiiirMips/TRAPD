# TRAPD ClickHouse Database Documentation

## Overview

TRAPD uses ClickHouse 24.3 as its primary data store for security events and sensor telemetry. The database is configured with automatic TTL-based data retention (180 days), partitioning, and optimized indexes.

## Prerequisites

- **Docker Desktop** (latest version recommended)
- **Windows PowerShell** (version 5.1 or later)
- **Git** (optional, for version control)

Make sure Docker Desktop is running before proceeding with the setup.

## Quick Start

### 1. Initial Setup

Run the bootstrap script from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\bootstrap-db.ps1
```

This script will:
- ✅ Check that Docker is running
- ✅ Start the ClickHouse container (`trapd-clickhouse`)
- ✅ Wait for the database to be ready (up to 60 seconds)
- ✅ Apply the database schema (`db/schema.sql`)
- ✅ Create indexes (`db/indexes.sql`)
- ✅ Run smoke tests (`db/smoke.sql`)
- ✅ Display connection details and table structure

### 2. Verify Installation

After bootstrap completes, verify the setup:

```powershell
# Check container status
docker ps | Select-String "trapd-clickhouse"

# Test connection
docker exec trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --query "SELECT version()"

# Check table structure
docker exec trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --query "SHOW TABLES FROM trapd"
```

## Connection Details

| Parameter | Value |
|-----------|-------|
| **HTTP Port** | `8123` |
| **Native TCP Port** | `9000` |
| **Database** | `trapd` |
| **Admin User** | `trapd` |
| **Admin Password** | `trapd_pwd` |
| **Container Name** | `trapd-clickhouse` |

### Connection Examples

**Using clickhouse-client (in container):**
```powershell
docker exec -it trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --database trapd
```

**Using HTTP API:**
```powershell
curl "http://localhost:8123/?user=trapd&password=trapd_pwd&query=SELECT+version()"
```

**Using Native TCP (from application):**
```
clickhouse://trapd:trapd_pwd@localhost:9000/trapd
```

## Database Schema

### Table: `trapd.events`

Primary table for storing security events from sensors.

**Columns:**
- `ts` - DateTime64(3, 'UTC') - Event timestamp with millisecond precision
- `org_id` - String - Organization identifier
- `sensor_id` - String - Sensor identifier
- `event_type` - LowCardinality(String) - Event type (e.g., "auth_failed")
- `src_ip` - String - Source IP address
- `src_port` - UInt16 - Source port
- `dst_port` - UInt16 - Destination port
- `proto` - LowCardinality(String) - Protocol (TCP, UDP, etc.)
- `severity` - LowCardinality(String) - Severity level (low, medium, high, critical)
- `payload` - String - JSON payload with additional event data

**Engine Configuration:**
- **Engine:** MergeTree
- **Partitioning:** Monthly by `toYYYYMM(ts)`
- **Ordering:** `(ts, src_ip)`
- **TTL:** Automatic deletion after 180 days from event timestamp
- **Index Granularity:** 8192 rows

**Indexes:**
- `idx_src_ip` - Data-skipping set index on `src_ip` for faster IP-based queries

## Smoke Test

The bootstrap script automatically runs a smoke test that:
1. Inserts a sample "auth_failed" event
2. Queries the most recent 5 events
3. Verifies data retrieval

**Expected output:**
```
ts                      event_type   src_ip       severity
2025-10-17 12:34:56.789 auth_failed  192.0.2.10  high
```

## Data Export & Backup

### Export to Parquet

Export all events to Parquet format:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\db-export.ps1
```

This creates `.\backup\events.parquet` on the host machine.

### Manual Backup

**Backup entire database:**
```powershell
# Create backup directory
docker exec trapd-clickhouse mkdir -p /var/lib/clickhouse/backup

# Export table
docker exec trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --query "BACKUP TABLE trapd.events TO Disk('default', 'backup/events_backup')"

# Copy to host
docker cp trapd-clickhouse:/var/lib/clickhouse/backup ./backup
```

**Restore from backup:**
```powershell
# Copy backup to container
docker cp ./backup trapd-clickhouse:/var/lib/clickhouse/restore

# Restore table
docker exec trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --query "RESTORE TABLE trapd.events FROM Disk('default', 'restore/events_backup')"
```

## User Management

### Create Read-Only User

For monitoring and analytics, create a user with SELECT-only permissions:

```powershell
# Run with readonly user creation
powershell -ExecutionPolicy Bypass -File .\tools\bootstrap-db.ps1 -CreateReadonly
```

Or manually:
```powershell
docker exec trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --multiquery < tools/create-readonly-user.sql
```

**Read-only credentials:**
- User: `trapd_ro`
- Password: `readonly_pwd`
- Permissions: SELECT on `trapd.*`

## Maintenance

### View Container Logs

```powershell
docker logs trapd-clickhouse --tail 100 -f
```

### Check Table Statistics

```powershell
docker exec trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --query "SELECT 
    table, 
    formatReadableSize(total_bytes) as size,
    formatReadableQuantity(total_rows) as rows
FROM system.tables 
WHERE database = 'trapd'"
```

### Check Partition Information

```powershell
docker exec trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --query "SELECT 
    partition,
    formatReadableSize(bytes_on_disk) as size,
    rows,
    min_time,
    max_time
FROM system.parts
WHERE database = 'trapd' AND table = 'events' AND active"
```

### Manual TTL Execution

Force TTL cleanup (normally runs automatically):

```powershell
docker exec trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --query "OPTIMIZE TABLE trapd.events FINAL"
```

## Clean Reset

To completely reset the database and start fresh:

```powershell
# Stop and remove container + volumes
docker compose down -v

# Restart with bootstrap
powershell -ExecutionPolicy Bypass -File .\tools\bootstrap-db.ps1
```

**⚠️ Warning:** This will delete all data permanently!

## Troubleshooting

### Container won't start

```powershell
# Check Docker Desktop status
docker info

# Check container logs
docker logs trapd-clickhouse

# Try manual start
docker compose up
```

### Connection refused

```powershell
# Check if ports are already in use
netstat -ano | findstr "8123"
netstat -ano | findstr "9000"

# Verify container is running
docker ps | Select-String "trapd-clickhouse"
```

### Schema errors

```powershell
# Drop and recreate table
docker exec trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --query "DROP TABLE IF EXISTS trapd.events"

# Re-run bootstrap
powershell -ExecutionPolicy Bypass -File .\tools\bootstrap-db.ps1
```

### Volume issues

```powershell
# List volumes
docker volume ls | Select-String "trapd"

# Inspect volume
docker volume inspect trapd_clickhouse_data

# Remove volumes (⚠️ deletes data)
docker volume rm trapd_clickhouse_data trapd_clickhouse_logs
```

## Performance Tuning

### Query Optimization Tips

1. **Always filter by `ts` first** - leverages partitioning
2. **Use `src_ip` in WHERE clauses** - leverages data-skipping index
3. **Prefer `event_type` over wildcard searches** - benefits from LowCardinality
4. **Limit result sets** - use LIMIT for exploratory queries

### Example Queries

**Recent high-severity events:**
```sql
SELECT ts, event_type, src_ip, severity, payload
FROM trapd.events
WHERE ts >= now() - INTERVAL 1 HOUR
  AND severity = 'high'
ORDER BY ts DESC
LIMIT 100;
```

**Top source IPs by event count:**
```sql
SELECT src_ip, count() as event_count
FROM trapd.events
WHERE ts >= today() - 7
GROUP BY src_ip
ORDER BY event_count DESC
LIMIT 20;
```

**Events by hour:**
```sql
SELECT 
    toStartOfHour(ts) as hour,
    event_type,
    count() as count
FROM trapd.events
WHERE ts >= now() - INTERVAL 24 HOUR
GROUP BY hour, event_type
ORDER BY hour DESC, count DESC;
```

## Configuration Files

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Container orchestration |
| `db/schema.sql` | Table definitions and database structure |
| `db/indexes.sql` | Data-skipping indexes |
| `db/smoke.sql` | Integration test queries |
| `tools/bootstrap-db.ps1` | Automated setup script |
| `tools/db-export.ps1` | Parquet export utility |
| `tools/create-readonly-user.sql` | Read-only user creation |

## Named Volumes

TRAPD uses named Docker volumes for data persistence:

- **`trapd_clickhouse_data`** - Database files (`/var/lib/clickhouse`)
- **`trapd_clickhouse_logs`** - Server logs (`/var/log/clickhouse-server`)

These volumes persist data across container restarts and upgrades.

## Security Considerations

### Production Recommendations

1. **Change default passwords** - Update `trapd_pwd` and `readonly_pwd`
2. **Use environment variables** - Store credentials in `.env` file (not committed)
3. **Enable TLS/SSL** - Configure HTTPS for HTTP interface
4. **Network isolation** - Use Docker networks, don't expose ports publicly
5. **Regular backups** - Schedule automated exports
6. **Monitor access logs** - Review `query_log` table regularly

### Access Control

```sql
-- Create organization-specific users
CREATE USER org_acme IDENTIFIED BY 'secure_password';
GRANT SELECT ON trapd.events TO org_acme WHERE org_id = 'acme';

-- Revoke permissions
REVOKE SELECT ON trapd.* FROM trapd_ro;

-- List all users
SELECT name, auth_type FROM system.users;
```

## Support & Resources

- **ClickHouse Documentation:** https://clickhouse.com/docs
- **Docker Compose Reference:** https://docs.docker.com/compose/
- **TRAPD Repository:** [Your repo URL]

## Version History

- **2025-10-17:** Initial setup with ClickHouse 24.3, DateTime64, TTL support
