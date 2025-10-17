-- TRAPD ClickHouse Schema
-- DateTime64 with TTL cast fix for ClickHouse 24.3+

CREATE DATABASE IF NOT EXISTS trapd;

CREATE TABLE IF NOT EXISTS trapd.events
(
  ts         DateTime64(3, 'UTC'),
  org_id     String,
  sensor_id  String,
  event_type LowCardinality(String),
  src_ip     String,
  src_port   UInt16,
  dst_port   UInt16,
  proto      LowCardinality(String),
  severity   LowCardinality(String),
  payload    String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, src_ip)
TTL toDateTime(ts) + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;
