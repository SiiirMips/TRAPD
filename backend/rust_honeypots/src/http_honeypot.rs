// backend/rust_honeypots/src/http_honeypot.rs

use axum::{
    extract::{ConnectInfo, State, OriginalUri},
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use std::net::SocketAddr;
use axum::http::{HeaderMap, Method, Version};
use url::Url;

use crate::common::{SharedAppState, lookup_geoip};

// Öffentlicher Router, damit er von main.rs eingebunden werden kann
pub fn create_http_router(app_state: SharedAppState) -> Router {
    Router::new()
        .route("/", get(honeypot_handler))
        .route("/*path", get(honeypot_handler))
        .route("/", post(honeypot_handler_post))
        .route("/*path", post(honeypot_handler_post))
        .with_state(app_state)
}

// Handler für GET-Anfragen (ohne Body-Extraction)
async fn honeypot_handler(
    method: Method,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<SharedAppState>,
    uri: OriginalUri,
    headers: HeaderMap,
    http_version: Version,
) -> impl IntoResponse {
    // Filter für Browser-spezifische Anfragen (Favicon, etc.)
    let request_path = uri.path();
    if should_ignore_request(request_path, &headers) {
        println!("Ignoriere Browser-Anfrage: {}", request_path);
        return Html(generate_simple_404().await);
    }

    let (disinformation_content, _) = log_http_interaction(method, addr, state, uri, headers, http_version, None).await;
    
    // Dynamische HTML-Antwort generieren
    Html(generate_dynamic_html_response(disinformation_content).await)
}

// Handler für POST-Anfragen (mit Body-Extraction)
async fn honeypot_handler_post(
    method: Method,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<SharedAppState>,
    uri: OriginalUri,
    headers: HeaderMap,
    http_version: Version,
    body: String, // Extrahiere den Request Body als String
) -> impl IntoResponse {
    // Filter für Browser-spezifische Anfragen
    let request_path = uri.path();
    if should_ignore_request(request_path, &headers) {
        println!("Ignoriere Browser-POST-Anfrage: {}", request_path);
        return Html(generate_simple_404().await);
    }

    let (disinformation_content, _) = log_http_interaction(method, addr, state, uri, headers, http_version, Some(body)).await;
    
    // Dynamische HTML-Antwort generieren
    Html(generate_dynamic_html_response(disinformation_content).await)
}

// Allgemeine Funktion zum Loggen und Weiterleiten von HTTP-Interaktionen
async fn log_http_interaction(
    method: Method,
    addr: SocketAddr,
    state: SharedAppState,
    uri: OriginalUri,
    headers: HeaderMap,
    http_version_raw: Version,
    request_body: Option<String>,
) -> (String, Value) {
    let client_ip = addr.ip().to_string();
    let client_port = addr.port();
    let full_uri = uri.to_string();
    let request_path = uri.path();
    let http_method = method.as_str();

    // NEU: Zusätzliche Filterung für verdächtige/interessante Anfragen
    let is_suspicious_request = is_attack_request(request_path, &headers, &request_body);
    
    println!("HTTP Honeypot: {} {} von {} (Verdächtig: {})", 
             http_method, request_path, client_ip, is_suspicious_request);

    // Nur verdächtige Anfragen loggen (optional - entkommentieren falls gewünscht)
    // if !is_suspicious_request {
    //     return (String::from("Request ignored - not suspicious"), Value::Null);
    // }

    // GeoIP lookup
    let geo_location = lookup_geoip(addr.ip(), &state.http_client).await;
    println!("GeoIP for {}: {:?}", client_ip, geo_location);

    let http_version_str = format!("{:?}", http_version_raw);

    let user_agent = headers.get("User-Agent")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("N/A");

    let mut query_params = serde_json::Map::new();
    if let Some(query) = uri.query() {
        if let Ok(parsed_url) = Url::parse(&format!("http://dummy.com?{}", query)) {
            for (key, value) in parsed_url.query_pairs() {
                query_params.insert(key.into_owned(), Value::String(value.into_owned()));
            }
        }
    }

    // Body-Parsing-Logik
    let mut parsed_body_data: Option<Value> = None;
    if let Some(body_str) = &request_body {
        if let Some(content_type_header) = headers.get("Content-Type") {
            if let Ok(content_type_str) = content_type_header.to_str() {
                if content_type_str.contains("application/json") {
                    if let Ok(json_val) = serde_json::from_str::<Value>(body_str) {
                        parsed_body_data = Some(json_val);
                    } else {
                        eprintln!("Fehler beim Parsen des JSON-Bodys: {}", body_str);
                    }
                } else if content_type_str.contains("application/x-www-form-urlencoded") {
                    let mut form_map = serde_json::Map::new();
                    for (key, value) in url::form_urlencoded::parse(body_str.as_bytes()) {
                        form_map.insert(key.into_owned(), Value::String(value.into_owned()));
                    }
                    if !form_map.is_empty() {
                        parsed_body_data = Some(Value::Object(form_map));
                    } else {
                        eprintln!("Keine Daten im URL-encoded Bodys geparsed oder Fehler: {}", body_str);
                    }
                }
            }
        }
    }

    println!("Honeypot-Interaktion: IP: {}, Port: {}, Methode: {}, Pfad: {}, Version: {}, User-Agent: {}",
             client_ip, client_port, http_method, request_path, http_version_str, user_agent);
    if let Some(body) = &request_body {
        println!("Request Body: {}", body);
    }
    if let Some(parsed_data) = &parsed_body_data {
        println!("Parsed Body Data: {}", parsed_data);
    }


    // Daten für die Datenbank und die KI
    let mut interaction_data = json!({
        "full_uri": full_uri,
        "request_path": request_path,
        "method": http_method,
        "http_version": http_version_str,
        "user_agent": user_agent,
        "headers": headers.iter().map(|(k, v)| {
            (k.to_string(), Value::String(v.to_str().unwrap_or("").to_string()))
        }).collect::<serde_json::Map<String, Value>>(),
        "query_parameters": query_params,
        "client_port": client_port,
    });

    if let Some(body) = request_body.clone() {
        interaction_data["request_body"] = Value::String(body);
    }
    if let Some(parsed_data) = parsed_body_data {
        interaction_data["parsed_body"] = parsed_data;
    }


    // --- 1. Logge in Supabase (attacker_logs) ---
    let mut supabase_log_payload = json!({
        "source_ip": client_ip,
        "honeypot_type": "http",
        "interaction_data": interaction_data,
        "status": "logged"
    });

    // Add GeoIP data to Supabase payload
    if let Some(country_code) = &geo_location.country_code {
        supabase_log_payload["country_code"] = json!(country_code);
    }
    if let Some(country_name) = &geo_location.country_name {
        supabase_log_payload["country_name"] = json!(country_name);
    }
    if let Some(region_code) = &geo_location.region_code {
        supabase_log_payload["region_code"] = json!(region_code);
    }
    if let Some(region_name) = &geo_location.region_name {
        supabase_log_payload["region_name"] = json!(region_name);
    }
    if let Some(city) = &geo_location.city {
        supabase_log_payload["city"] = json!(city);
    }
    if let Some(latitude) = geo_location.latitude {
        supabase_log_payload["latitude"] = json!(latitude);
    }
    if let Some(longitude) = geo_location.longitude {
        supabase_log_payload["longitude"] = json!(longitude);
    }
    if let Some(timezone) = &geo_location.timezone {
        supabase_log_payload["timezone"] = json!(timezone);
    }
    if let Some(isp) = &geo_location.isp {
        supabase_log_payload["isp"] = json!(isp);
    }
    if let Some(organization) = &geo_location.organization {
        supabase_log_payload["organization"] = json!(organization);
    }

    let supabase_table_url = format!("{}/rest/v1/attacker_logs", state.supabase_api_url);

    match state.http_client
        .post(&supabase_table_url)
        .header("apikey", &state.supabase_service_role_key)
        .header("Authorization", format!("Bearer {}", &state.supabase_service_role_key))
        .header("Content-Type", "application/json")
        .json(&supabase_log_payload)
        .send()
        .await
    {
        Ok(res) => {
            let status_code = res.status();
            if status_code.is_success() {
                println!("Log erfolgreich in Supabase gespeichert. Status: {}", status_code);
            } else {
                eprintln!("Fehler beim Speichern des Logs in Supabase: Status {}", status_code);
                if let Ok(body) = res.text().await {
                    eprintln!("Antwort Body: {}", body);
                }
            }
        },
        Err(e) => {
            eprintln!("Fehler beim Senden des Logs an Supabase: {:?}", e);
        }
    }

    // --- 2. Sende Daten an Python KI-Mockup und erhalte Desinformation ---
    let ki_api_endpoint = format!("{}/analyze/and-disinform/", state.python_ai_url);

    let mut ki_payload = json!({
        "source_ip": client_ip,
        "honeypot_type": "http",
        "interaction_data": interaction_data,
        "status": "logged"
    });

    // Add GeoIP data to AI payload
    ki_payload["geo_location"] = json!(geo_location);

    let mut disinformation_content = String::from("Ein unerwarteter Fehler ist aufgetreten. Die angeforderte Ressource konnte nicht gefunden werden.");
    let mut ki_response_raw = Value::Null;

    match state.http_client
        .post(&ki_api_endpoint)
        .header("Content-Type", "application/json")
        .json(&ki_payload)
        .send()
        .await
    {
        Ok(res) => {
            let status_code = res.status();
            if status_code.is_success() {
                println!("Daten erfolgreich an Python KI-Mockup gesendet. Status: {}", status_code);
                if let Ok(ki_response_body) = res.json::<Value>().await {
                    if let Some(payload) = ki_response_body.get("disinformation_payload") {
                        if let Some(content) = payload.get("content") {
                            if let Some(s) = content.as_str() {
                                disinformation_content = s.to_string();
                            }
                        }
                    }
                    ki_response_raw = ki_response_body;
                    println!("Antwort von KI-Mockup: {:?}", ki_response_raw);
                } else {
                    eprintln!("Fehler beim Parsen der KI-Antwort (kein JSON?): {}", status_code);
                }
            } else {
                eprintln!("Fehler beim Senden an Python KI-Mockup: Status {}", status_code);
                if let Ok(body) = res.text().await {
                    eprintln!("Antwort Body von KI-Mockup: {}", body);
                }
            }
        },
        Err(e) => {
            eprintln!("Fehler beim Senden der Anfrage an Python KI-Mockup: {:?}", e);
        }
    }

    // Rückgabe der Desinformation und der rohen KI-Antwort
    (disinformation_content, ki_response_raw)
}

// NEU: Funktion zur Generierung einer dynamischen HTML-Antwort
async fn generate_dynamic_html_response(disinformation_text: String) -> String {
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Systemmeldung: Interner Fehler</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f0f2f5; color: #333; margin: 0; padding: 20px; display: flex; justify-content: center; align-items: center; min-height: 100vh; }}
        .container {{ background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); max-width: 600px; text-align: center; }}
        h1 {{ color: #d32f2f; font-size: 2.5em; margin-bottom: 20px; }}
        p {{ font-size: 1.1em; line-height: 1.6; color: #555; }}
        .error-code {{ font-family: 'Consolas', monospace; background-color: #eee; padding: 5px 10px; border-radius: 4px; display: inline-block; margin-top: 15px; color: #777; }}
        .disinfo-message {{ background-color: #e8f5e9; color: #388e3c; padding: 15px; border-left: 5px solid #4caf50; margin-top: 25px; border-radius: 4px; text-align: left; }}
        .footer {{ margin-top: 30px; font-size: 0.9em; color: #888; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Zugriff verweigert oder Fehler</h1>
        <p>Leider konnte Ihre Anfrage nicht wie gewünscht bearbeitet werden.</p>
        <div class="disinfo-message">
            <strong>Wichtige Systeminformationen:</strong><br>
            {}
        </div>
        <p class="footer">Bitte kontaktieren Sie den Systemadministrator, falls Sie weitere Unterstützung benötigen.</p>
    </div>
</body>
</html>"#,
        disinformation_text
    );
    html
}

// NEU: Funktion zur Filterung von Browser-spezifischen Anfragen
fn should_ignore_request(path: &str, headers: &HeaderMap) -> bool {
    // Liste der Pfade, die ignoriert werden sollen
    let ignore_paths = [
        "/favicon.ico",
        "/robots.txt",
        "/sitemap.xml",
        "/apple-touch-icon.png",
        "/apple-touch-icon-precomposed.png",
        "/.well-known/security.txt",
        "/browserconfig.xml",
        "/manifest.json"
    ];
    
    // Prüfe, ob der Pfad in der Ignore-Liste steht
    if ignore_paths.contains(&path) {
        return true;
    }
    
    // Ignoriere Preflight OPTIONS-Anfragen für CORS
    if let Some(method) = headers.get("access-control-request-method") {
        if method.to_str().unwrap_or("").to_uppercase() == "OPTIONS" {
            return true;
        }
    }
    
    // Ignoriere Service Worker Anfragen
    if path.starts_with("/sw.js") || path.starts_with("/service-worker") {
        return true;
    }
    
    false
}

// NEU: Einfache 404-Antwort für ignorierte Anfragen
async fn generate_simple_404() -> String {
    r#"<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body><h1>404 Not Found</h1><p>The requested resource was not found.</p></body>
</html>"#.to_string()
}

// NEU: Funktion zur Erkennung von Angriffs-Anfragen
fn is_attack_request(path: &str, headers: &HeaderMap, body: &Option<String>) -> bool {
    let path_lower = path.to_lowercase();
    
    // Verdächtige Pfade (typische Angriffsmuster)
    let suspicious_paths = [
        "admin", "login", "phpmyadmin", "wp-admin", "wp-login",
        "config", ".env", "backup", "database", "sql",
        "shell", "webshell", "cmd", "phpinfo",
        "exploit", "backdoor", "upload"
    ];
    
    // Prüfe auf verdächtige Pfade
    if suspicious_paths.iter().any(|&pattern| path_lower.contains(pattern)) {
        return true;
    }
    
    // Prüfe User-Agent für Scanner/Bots
    if let Some(user_agent) = headers.get("User-Agent") {
        if let Ok(ua_str) = user_agent.to_str() {
            let ua_lower = ua_str.to_lowercase();
            let scanner_patterns = [
                "nmap", "masscan", "gobuster", "dirb", "sqlmap",
                "nikto", "burp", "scanner", "bot", "crawl"
            ];
            if scanner_patterns.iter().any(|&pattern| ua_lower.contains(pattern)) {
                return true;
            }
        }
    }
    
    // Prüfe Body auf verdächtige Inhalte (falls vorhanden)
    if let Some(body_content) = body {
        let body_lower = body_content.to_lowercase();
        if body_lower.contains("select") && body_lower.contains("from") ||
           body_lower.contains("union") && body_lower.contains("select") ||
           body_lower.contains("<script") ||
           body_lower.contains("javascript:") {
            return true;
        }
    }
    
    // Alle anderen Anfragen als "normal" betrachten (aber trotzdem loggen)
    true // Setzen Sie auf false, wenn Sie nur Angriffe loggen möchten
}

