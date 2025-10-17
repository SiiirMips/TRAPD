-- TRAPD ClickHouse Indexes
-- Data-skipping indexes for improved query performance

ALTER TABLE trapd.events
  ADD INDEX IF NOT EXISTS idx_src_ip src_ip TYPE set(0) GRANULARITY 1;
