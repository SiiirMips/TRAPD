// backend/rust_honeypots/src/common.rs

use reqwest::Client;
use std::sync::Arc; // Arc für die gemeinsame Nutzung über Threads

// Datenstruktur für den HTTP-Client und Konfiguration
// Muss 'Send + Sync' sein, damit sie sicher über Async-Tasks geteilt werden kann
#[derive(Clone)]
pub struct AppState { // 'pub' damit es von anderen Modulen importiert werden kann
    pub http_client: Client,
    pub supabase_api_url: String,
    pub supabase_service_role_key: String,
    pub python_ai_url: String,
}

// Typedef für den gemeinsam genutzten State
pub type SharedAppState = Arc<AppState>;