-- Tabelle für Angreifer-Interaktionen (Logs)
CREATE TABLE IF NOT EXISTS attacker_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ DEFAULT now(),
    source_ip INET NOT NULL, -- IP-Adresse des Angreifers
    honeypot_type TEXT NOT NULL, -- Z.B. 'ssh', 'http', 'ftp'
    interaction_data JSONB, -- JSON-Feld für beliebige Interaktionsdetails (z.B. Befehle, HTTP-Requests)
    honeypot_id UUID, -- Optional: ID des spezifischen Honeypot-Instances
    status TEXT DEFAULT 'logged' -- Z.B. 'logged', 'desinformed', 'analyzed'
);

-- Index für schnellen Zugriff basierend auf IP und Zeit
CREATE INDEX idx_attacker_logs_ip_time ON attacker_logs (source_ip, timestamp DESC);

-- Tabelle für generierte Desinformationsinhalte
CREATE TABLE IF NOT EXISTS disinformation_content (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    creation_timestamp TIMESTAMPTZ DEFAULT now(),
    content TEXT NOT NULL, -- Der generierte Desinformations-Text/Inhalt
    content_type TEXT NOT NULL, -- Z.B. 'ssh_banner', 'http_page', 'file_content', 'credential_pair'
    target_context JSONB, -- Kontext, für den die Desinformation generiert wurde (z.B. Angreifer-TTPs, Honeypot-Typ)
    generated_by_ai BOOLEAN DEFAULT TRUE,
    ai_model TEXT -- Optional: Welches KI-Modell verwendet wurde
);

-- Optional: Tabelle für Angreiferprofile (später für persistente Identitäten)
CREATE TABLE IF NOT EXISTS attacker_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    first_seen TIMESTAMPTZ DEFAULT now(),
    last_seen TIMESTAMPTZ DEFAULT now(),
    -- Verknüpfung zu Logs oder anderen Indikatoren, um ein Profil aufzubauen
    correlated_ips INET[], -- Array von IPs, die diesem Profil zugeordnet werden
    known_tactics TEXT[], -- TTPs, die diesem Profil zugeordnet werden
    identified_persona JSONB, -- KI-generierte oder manuell erstellte Persona-Daten
    notes TEXT
);
-- Index für schnellen Zugriff auf Profile nach IP
CREATE INDEX idx_attacker_profiles_ips ON attacker_profiles USING GIN (correlated_ips);