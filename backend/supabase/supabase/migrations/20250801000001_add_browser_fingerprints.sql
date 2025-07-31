-- Migration für Browser Fingerprinting Tabelle
-- Diese Tabelle speichert detaillierte JavaScript-Fingerprinting-Daten

CREATE TABLE IF NOT EXISTS browser_fingerprints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ DEFAULT now(),
    source_ip INET NOT NULL,
    honeypot_type TEXT DEFAULT 'http_fingerprint',
    
    -- GeoIP Informationen
    country_code TEXT,
    country_name TEXT,
    region_code TEXT,
    region_name TEXT,
    city TEXT,
    latitude FLOAT,
    longitude FLOAT,
    timezone TEXT,
    isp TEXT,
    organization TEXT,
    
    -- JavaScript Fingerprinting Daten
    fingerprint_data JSONB NOT NULL, -- Vollständige JavaScript-Fingerprint-Daten
    
    -- HTTP Headers die mit dem Fingerprint gesendet wurden
    headers JSONB,
    
    -- Zusätzliche Metadaten
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- Indizes für bessere Performance
CREATE INDEX idx_browser_fingerprints_ip_time ON browser_fingerprints (source_ip, timestamp DESC);
CREATE INDEX idx_browser_fingerprints_country ON browser_fingerprints (country_code);
CREATE INDEX idx_browser_fingerprints_timestamp ON browser_fingerprints (timestamp DESC);

-- Index für JSON-Fingerprint-Daten (für Suchen in den Fingerprint-Daten)
CREATE INDEX idx_browser_fingerprints_data ON browser_fingerprints USING GIN (fingerprint_data);

-- Kommentar zur Tabelle
COMMENT ON TABLE browser_fingerprints IS 'Speichert JavaScript-basierte Browser-Fingerprinting-Daten von HTTP-Honeypot-Interaktionen';
