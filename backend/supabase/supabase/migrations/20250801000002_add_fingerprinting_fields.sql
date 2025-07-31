-- Migration für Enhanced Fingerprinting Support in attacker_logs
-- Erweitert die attacker_logs Tabelle um Fingerprinting-Daten

-- Füge Fingerprinting-spezifische Spalten hinzu
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS scanner_type TEXT;
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS tool_confidence FLOAT;
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS threat_level TEXT;
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS is_real_browser BOOLEAN;
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS browser_engine TEXT;
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS browser_version TEXT;
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS operating_system TEXT;
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS scan_pattern TEXT;
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS burst_requests INTEGER;
ALTER TABLE attacker_logs ADD COLUMN IF NOT EXISTS request_interval_ms BIGINT;

-- Indizes für Fingerprinting-Queries
CREATE INDEX IF NOT EXISTS idx_attacker_logs_scanner_type ON attacker_logs (scanner_type);
CREATE INDEX IF NOT EXISTS idx_attacker_logs_threat_level ON attacker_logs (threat_level);
CREATE INDEX IF NOT EXISTS idx_attacker_logs_is_real_browser ON attacker_logs (is_real_browser);
CREATE INDEX IF NOT EXISTS idx_attacker_logs_scan_pattern ON attacker_logs (scan_pattern);

-- View für Scanner-Statistiken
CREATE OR REPLACE VIEW v_scanner_statistics AS
SELECT 
    scanner_type,
    threat_level,
    COUNT(*) as detection_count,
    COUNT(DISTINCT source_ip) as unique_ips,
    AVG(tool_confidence) as avg_confidence,
    MIN(timestamp) as first_detected,
    MAX(timestamp) as last_detected,
    array_agg(DISTINCT country_code) FILTER (WHERE country_code IS NOT NULL) as countries
FROM attacker_logs 
WHERE scanner_type IS NOT NULL
GROUP BY scanner_type, threat_level
ORDER BY detection_count DESC;

-- View für Threat Level Übersicht
CREATE OR REPLACE VIEW v_threat_overview AS
SELECT 
    threat_level,
    COUNT(*) as total_threats,
    COUNT(DISTINCT source_ip) as unique_threat_ips,
    COUNT(CASE WHEN is_real_browser = false THEN 1 END) as automated_threats,
    COUNT(CASE WHEN is_real_browser = true THEN 1 END) as browser_threats,
    array_agg(DISTINCT scanner_type) FILTER (WHERE scanner_type IS NOT NULL) as detected_scanners
FROM attacker_logs 
WHERE threat_level IS NOT NULL
GROUP BY threat_level
ORDER BY 
    CASE threat_level 
        WHEN 'Critical' THEN 4 
        WHEN 'High' THEN 3 
        WHEN 'Medium' THEN 2 
        WHEN 'Low' THEN 1 
        ELSE 0 
    END DESC;

-- View für Browser vs Scanner Analyse
CREATE OR REPLACE VIEW v_browser_vs_scanner AS
SELECT 
    DATE(timestamp) as date,
    COUNT(CASE WHEN is_real_browser = true THEN 1 END) as real_browsers,
    COUNT(CASE WHEN is_real_browser = false THEN 1 END) as automated_tools,
    COUNT(CASE WHEN scanner_type IS NOT NULL THEN 1 END) as detected_scanners,
    COUNT(*) as total_requests
FROM attacker_logs 
GROUP BY DATE(timestamp)
ORDER BY date DESC;

-- View für Timing Pattern Analyse
CREATE OR REPLACE VIEW v_timing_patterns AS
SELECT 
    scan_pattern,
    threat_level,
    COUNT(*) as pattern_count,
    AVG(burst_requests) as avg_burst_requests,
    AVG(request_interval_ms) as avg_interval_ms,
    MIN(request_interval_ms) as min_interval_ms,
    MAX(request_interval_ms) as max_interval_ms,
    COUNT(DISTINCT source_ip) as unique_ips
FROM attacker_logs 
WHERE scan_pattern IS NOT NULL
GROUP BY scan_pattern, threat_level
ORDER BY pattern_count DESC;

-- Kommentare zu den neuen Spalten
COMMENT ON COLUMN attacker_logs.scanner_type IS 'Erkannter Scanner-Typ (z.B. Nmap, Masscan, Gobuster)';
COMMENT ON COLUMN attacker_logs.tool_confidence IS 'Konfidenz-Score der Scanner-Erkennung (0.0-1.0)';
COMMENT ON COLUMN attacker_logs.threat_level IS 'Bewertetes Bedrohungslevel (Low, Medium, High, Critical)';
COMMENT ON COLUMN attacker_logs.is_real_browser IS 'Ob es sich um einen echten Browser handelt';
COMMENT ON COLUMN attacker_logs.scan_pattern IS 'Erkanntes Scan-Muster (Sequential, Random, Dictionary, Bruteforce, Normal)';
