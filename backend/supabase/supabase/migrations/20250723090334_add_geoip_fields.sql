-- Add GeoIP fields to attacker_logs table
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS country_code CHAR(2);
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS country_name TEXT;
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS region_code TEXT;
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS region_name TEXT;
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS city TEXT;
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS latitude DECIMAL(10, 8);
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS longitude DECIMAL(11, 8);
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS timezone TEXT;
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS isp TEXT;
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS organization TEXT;

-- Index for geographic queries
CREATE INDEX IF NOT EXISTS idx_attacker_logs_country ON attacker_logs (country_code);
CREATE INDEX IF NOT EXISTS idx_attacker_logs_city ON attacker_logs (city);
CREATE INDEX IF NOT EXISTS idx_attacker_logs_coordinates ON attacker_logs (latitude, longitude);

-- View for dashboard queries with geographic aggregation
CREATE OR REPLACE VIEW v_attacks_by_country AS
SELECT 
    country_code,
    country_name,
    COUNT(*) as attack_count,
    COUNT(DISTINCT source_ip) as unique_ips,
    MIN(timestamp) as first_seen,
    MAX(timestamp) as last_seen,
    array_agg(DISTINCT honeypot_type) as honeypot_types
FROM attacker_logs 
WHERE country_code IS NOT NULL
GROUP BY country_code, country_name
ORDER BY attack_count DESC;

-- View for city-level attacks
CREATE OR REPLACE VIEW v_attacks_by_city AS
SELECT 
    country_code,
    country_name,
    city,
    latitude,
    longitude,
    COUNT(*) as attack_count,
    COUNT(DISTINCT source_ip) as unique_ips,
    array_agg(DISTINCT honeypot_type) as honeypot_types
FROM attacker_logs 
WHERE city IS NOT NULL AND latitude IS NOT NULL AND longitude IS NOT NULL
GROUP BY country_code, country_name, city, latitude, longitude
ORDER BY attack_count DESC;
