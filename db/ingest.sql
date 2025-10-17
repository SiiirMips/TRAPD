CREATE TABLE IF NOT EXISTS trapd.ingest_raw
(
  ts_str     String,
  org_id     String,
  sensor_id  String,
  event_type String,
  src_ip     String,
  src_port   UInt16,
  dst_port   UInt16,
  proto      String,
  severity   String,
  payload    String
)
ENGINE = MergeTree()
ORDER BY tuple();

CREATE MATERIALIZED VIEW IF NOT EXISTS trapd.mv_ingest_to_events
TO trapd.events AS
SELECT
  parseDateTime64BestEffortOrNull(ts_str, 3) AS ts,
  org_id,
  sensor_id,
  CAST(event_type AS LowCardinality(String)) AS event_type,
  src_ip,
  src_port,
  dst_port,
  CAST(proto AS LowCardinality(String)) AS proto,
  CAST(severity AS LowCardinality(String)) AS severity,
  payload
FROM trapd.ingest_raw
WHERE ts IS NOT NULL;
