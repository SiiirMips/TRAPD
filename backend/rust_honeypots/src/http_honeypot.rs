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
use regex::Regex;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use once_cell::sync::Lazy;
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose};

use crate::common::{SharedAppState, lookup_geoip};

// Öffentlicher Router, damit er von main.rs eingebunden werden kann
pub fn create_http_router(app_state: SharedAppState) -> Router {
    Router::new()
        .route("/", get(honeypot_handler))
        .route("/*path", get(honeypot_handler))
        .route("/", post(honeypot_handler_post))
        .route("/*path", post(honeypot_handler_post))
        .route("/fingerprint", post(fingerprint_handler))
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

// Handler für JavaScript-Fingerprinting-Daten
async fn fingerprint_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let client_ip = addr.ip().to_string();
    
    println!("🔍 JavaScript Fingerprint received from {}: {}", client_ip, body);
    
    // Parse fingerprint data
    if let Ok(fingerprint_data) = serde_json::from_str::<Value>(&body) {
        let mut enhanced_fingerprint = json!({
            "source_ip": client_ip,
            "honeypot_type": "http_fingerprint",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "fingerprint_data": fingerprint_data,
            "headers": headers.iter().map(|(k, v)| {
                (k.to_string(), Value::String(v.to_str().unwrap_or("").to_string()))
            }).collect::<serde_json::Map<String, Value>>(),
        });

        // Add GeoIP data
        let geo_location = lookup_geoip(addr.ip(), &state.http_client).await;
        if let Some(country_code) = &geo_location.country_code {
            enhanced_fingerprint["country_code"] = json!(country_code);
        }
        if let Some(country_name) = &geo_location.country_name {
            enhanced_fingerprint["country_name"] = json!(country_name);
        }

        // Log to Supabase (mit Fallback falls Tabelle nicht existiert)
        let supabase_table_url = format!("{}/rest/v1/browser_fingerprints", state.supabase_api_url);
        match state.http_client
            .post(&supabase_table_url)
            .header("apikey", &state.supabase_service_role_key)
            .header("Authorization", format!("Bearer {}", &state.supabase_service_role_key))
            .header("Content-Type", "application/json")
            .json(&enhanced_fingerprint)
            .send()
            .await
        {
            Ok(res) => {
                if res.status().is_success() {
                    println!("✅ Browser fingerprint successfully logged to Supabase");
                } else if res.status() == 404 {
                    eprintln!("⚠️  browser_fingerprints table not found. Run Supabase migrations first:");
                    eprintln!("   cd backend/supabase && supabase db push");
                    eprintln!("   Or create the table manually in your Supabase dashboard");
                } else {
                    eprintln!("❌ Failed to log browser fingerprint: {}", res.status());
                    if let Ok(body) = res.text().await {
                        eprintln!("Response: {}", body);
                    }
                }
            },
            Err(e) => {
                eprintln!("❌ Error logging browser fingerprint: {:?}", e);
            }
        }
    }
    
    // Return minimal response
    "OK"
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

    // Advanced Fingerprinting & Scanner Detection
    let fingerprint_result = perform_advanced_fingerprinting(
        &client_ip,
        &headers,
        &request_path,
        &http_method,
        &http_version_str,
        &request_body,
    ).await;

    println!("🔍 Advanced Fingerprinting Result: {:?}", fingerprint_result);

    // Add fingerprinting data to interaction_data
    interaction_data["fingerprinting"] = json!({
        "scanner_type": fingerprint_result.scanner_type,
        "tool_confidence": fingerprint_result.tool_confidence,
        "threat_level": format!("{:?}", fingerprint_result.threat_level),
        "browser_fingerprint": fingerprint_result.browser_fingerprint,
        "http_fingerprint": fingerprint_result.http_fingerprint,
        "timing_patterns": {
            "scan_pattern": format!("{:?}", fingerprint_result.timing_patterns.scan_pattern),
            "burst_requests": fingerprint_result.timing_patterns.burst_requests,
            "request_interval_ms": fingerprint_result.timing_patterns.request_interval_ms
        }
    });


    let mut supabase_log_payload = json!({
        "source_ip": client_ip,
        "honeypot_type": "http",
        "interaction_data": interaction_data,
        "status": "logged",
        // Advanced Fingerprinting Felder
        "scanner_type": fingerprint_result.scanner_type,
        "tool_confidence": fingerprint_result.tool_confidence,
        "threat_level": format!("{:?}", fingerprint_result.threat_level),
        "is_real_browser": fingerprint_result.browser_fingerprint.as_ref().map(|bf| bf.is_real_browser),
        "browser_engine": fingerprint_result.browser_fingerprint.as_ref().and_then(|bf| bf.engine.clone()),
        "browser_version": fingerprint_result.browser_fingerprint.as_ref().and_then(|bf| bf.version.clone()),
        "operating_system": fingerprint_result.browser_fingerprint.as_ref().and_then(|bf| bf.os.clone()),
        "scan_pattern": format!("{:?}", fingerprint_result.timing_patterns.scan_pattern),
        "burst_requests": fingerprint_result.timing_patterns.burst_requests,
        "request_interval_ms": fingerprint_result.timing_patterns.request_interval_ms
    });


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
    let javascript_fingerprinting = generate_javascript_fingerprinting();
    
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
    {}
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
        javascript_fingerprinting,
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

// Enhanced attack request detection using advanced fingerprinting
fn is_attack_request(path: &str, headers: &HeaderMap, body: &Option<String>) -> bool {
    let path_lower = path.to_lowercase();
    
    // 1. Check for suspicious paths (enhanced list)
    let suspicious_paths = [
        // Common admin panels
        "admin", "login", "phpmyadmin", "wp-admin", "wp-login", "administrator",
        "cpanel", "webmail", "roundcube", "squirrelmail",
        
        // Configuration and sensitive files
        "config", ".env", ".git", "backup", "database", "sql", "dump",
        "config.php", "wp-config", "database.yml", "secrets",
        
        // Shell and backdoors
        "shell", "webshell", "cmd", "phpinfo", "info.php", "test.php",
        "exploit", "backdoor", "upload", "uploader", "c99", "r57",
        
        // Directory traversal attempts
        "../", "..\\", "etc/passwd", "windows/system32",
        
        // Common web vulnerabilities
        "xmlrpc", "wp-json", "api/", "rest/", "graphql",
        
        // Scanner specific paths
        "/.well-known/", "/robots.txt", "/sitemap.xml"
    ];
    
    if suspicious_paths.iter().any(|&pattern| path_lower.contains(pattern)) {
        return true;
    }
    
    // 2. Enhanced User-Agent analysis
    if let Some(user_agent) = headers.get("User-Agent") {
        if let Ok(ua_str) = user_agent.to_str() {
            let ua_lower = ua_str.to_lowercase();
            
            // Known scanners and tools
            let scanner_patterns = [
                // Security scanners
                "nmap", "masscan", "zmap", "gobuster", "dirb", "dirbuster",
                "nikto", "sqlmap", "burp", "owasp zap", "acunetix", "nessus",
                "openvas", "w3af", "skipfish", "arachni",
                
                // Automated tools
                "python-requests", "curl", "wget", "httpie", "postman",
                "insomnia", "paw", "restclient",
                
                // Bots and crawlers
                "bot", "crawler", "spider", "scraper", "parser",
                "scanner", "monitor", "checker", "validator",
                
                // Penetration testing frameworks
                "metasploit", "cobalt strike", "empire", "covenant",
                "sliver", "meterpreter",
                
                // Custom exploitation tools
                "exploit", "payload", "shellcode", "reverse_shell"
            ];
            
            if scanner_patterns.iter().any(|&pattern| ua_lower.contains(pattern)) {
                return true;
            }
            
            // Check for suspiciously short or malformed User-Agents
            if ua_str.len() < 10 || !ua_str.contains("/") {
                return true;
            }
        }
    } else {
        // Missing User-Agent is suspicious
        return true;
    }
    
    // 3. Header analysis for automation indicators
    let automation_indicators = [
        ("X-Forwarded-For", ""), ("X-Real-IP", ""), ("X-Originating-IP", ""),
        ("X-Scanner", ""), ("X-Tool", ""), ("X-Automated", ""),
        ("X-Requestor", ""), ("X-Source", "")
    ];
    
    for (header_name, _) in automation_indicators {
        if headers.contains_key(header_name) {
            return true;
        }
    }
    
    // 4. Missing common browser headers (indicates automation)
    let expected_browser_headers = ["Accept", "Accept-Language", "Accept-Encoding"];
    let missing_count = expected_browser_headers.iter()
        .filter(|&&header| !headers.contains_key(header))
        .count();
    
    if missing_count >= 2 {
        return true;
    }
    
    // 5. Enhanced body content analysis
    if let Some(body_content) = body {
        let body_lower = body_content.to_lowercase();
        
        // SQL injection patterns
        let sql_patterns = [
            "union select", "or 1=1", "and 1=1", "' or '", "\" or \"",
            "drop table", "insert into", "delete from", "update set",
            "exec(", "sp_", "xp_", "@@version", "information_schema",
            "load_file(", "into outfile", "into dumpfile"
        ];
        
        // XSS patterns
        let xss_patterns = [
            "<script", "javascript:", "onload=", "onerror=", "onclick=",
            "alert(", "confirm(", "prompt(", "document.cookie",
            "eval(", "setTimeout(", "setInterval("
        ];
        
        // Command injection patterns
        let cmd_patterns = [
            "system(", "exec(", "shell_exec(", "passthru(", "popen(",
            "proc_open(", "`", "$(", "${", "&&", "||", ";",
            "/bin/", "/usr/bin/", "cmd.exe", "powershell"
        ];
        
        // LDAP injection patterns
        let ldap_patterns = [
            ")(cn=", ")(uid=", ")(mail=", "*)(", "*)(",
            "|(cn=", "|(uid=", "|(mail="
        ];
        
        let all_patterns = [sql_patterns.as_slice(), xss_patterns.as_slice(), 
                          cmd_patterns.as_slice(), ldap_patterns.as_slice()].concat();
        
        if all_patterns.iter().any(|&pattern| body_lower.contains(pattern)) {
            return true;
        }
        
        // Check for suspicious base64 content
        if body_content.len() > 100 && body_content.chars().all(|c| {
            c.is_alphanumeric() || c == '+' || c == '/' || c == '='
        }) {
            return true;
        }
    }
    
    // 6. Path-based attack pattern detection
    let attack_patterns = [
        // Directory traversal
        r"\.\./", r"\.\.\\", r"%2e%2e%2f", r"%2e%2e%5c",
        
        // Null byte injection
        r"%00", r"\x00",
        
        // URL encoding attacks
        r"%27", r"%22", r"%3c", r"%3e", r"%28", r"%29",
        
        // Common exploit attempts
        r"union\+select", r"concat\(", r"char\(",
        
        // Template injection
        r"\{\{", r"\}\}", r"\{%", r"%\}",
        
        // Server-side includes
        r"<!--#", r"#exec", r"#include"
    ];
    
    for pattern in attack_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if regex.is_match(&path_lower) {
                return true;
            }
        }
    }
    
    // 7. Check for scan-like behavior (multiple rapid requests)
    // This would require integration with timing analysis
    
    // For now, consider most requests as potentially suspicious for logging
    // Set to false if you only want to log confirmed attacks
    true
}

// Advanced Fingerprinting & Scanner Detection Structures
#[derive(Debug, Clone)]
pub struct FingerprintingResult {
    pub scanner_type: Option<String>,
    pub tool_confidence: f32,
    pub browser_fingerprint: Option<BrowserFingerprint>,
    pub http_fingerprint: HttpFingerprint,
    pub timing_patterns: TimingPattern,
    pub threat_level: ThreatLevel,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BrowserFingerprint {
    pub is_real_browser: bool,
    pub engine: Option<String>,
    pub version: Option<String>,
    pub os: Option<String>,
    pub javascript_enabled: bool,
    pub canvas_fingerprint: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HttpFingerprint {
    pub header_order: Vec<String>,
    pub header_case_pattern: String,
    pub http_version: String,
    pub tls_ja3_hash: Option<String>,
    pub connection_behavior: String,
}

#[derive(Debug, Clone)]
pub struct TimingPattern {
    pub request_interval_ms: Option<u64>,
    pub burst_requests: u32,
    pub scan_pattern: ScanPattern,
}

#[derive(Debug, Clone)]
pub enum ScanPattern {
    Sequential,
    Random,
    Dictionary,
    Bruteforce,
    Normal,
}

#[derive(Debug, Clone)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

// Global timing tracking for pattern analysis
static TIMING_TRACKER: Lazy<Arc<Mutex<HashMap<String, Vec<DateTime<Utc>>>>>> = 
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

// Scanner signatures database
static SCANNER_SIGNATURES: Lazy<Vec<ScannerSignature>> = Lazy::new(|| {
    vec![
        // Nmap signatures
        ScannerSignature {
            name: "Nmap".to_string(),
            user_agent_patterns: vec![
                r"nmap".to_string(),
                r".*nmap.*".to_string(),
            ],
            header_patterns: vec![
                ("User-Agent".to_string(), r".*NSE.*".to_string()),
            ],
            path_patterns: vec![],
            timing_signature: Some(TimingSignature {
                min_interval_ms: 100,
                max_interval_ms: 2000,
                burst_size: 10,
            }),
            confidence_threshold: 0.8,
        },
        // Masscan signatures
        ScannerSignature {
            name: "Masscan".to_string(),
            user_agent_patterns: vec![
                r"masscan".to_string(),
                r".*masscan.*".to_string(),
            ],
            header_patterns: vec![],
            path_patterns: vec![],
            timing_signature: Some(TimingSignature {
                min_interval_ms: 1,
                max_interval_ms: 100,
                burst_size: 100,
            }),
            confidence_threshold: 0.9,
        },
        // Gobuster signatures
        ScannerSignature {
            name: "Gobuster".to_string(),
            user_agent_patterns: vec![
                r"gobuster".to_string(),
                r".*gobuster.*".to_string(),
            ],
            header_patterns: vec![],
            path_patterns: vec![
                r"/admin.*".to_string(),
                r"/login.*".to_string(),
                r"/config.*".to_string(),
            ],
            timing_signature: Some(TimingSignature {
                min_interval_ms: 50,
                max_interval_ms: 500,
                burst_size: 20,
            }),
            confidence_threshold: 0.7,
        },
        // Nikto signatures
        ScannerSignature {
            name: "Nikto".to_string(),
            user_agent_patterns: vec![
                r".*Nikto.*".to_string(),
                r".*nikto.*".to_string(),
            ],
            header_patterns: vec![],
            path_patterns: vec![
                r"/cgi-bin/.*".to_string(),
                r"/scripts/.*".to_string(),
            ],
            timing_signature: Some(TimingSignature {
                min_interval_ms: 200,
                max_interval_ms: 1000,
                burst_size: 5,
            }),
            confidence_threshold: 0.8,
        },
        // SQLMap signatures
        ScannerSignature {
            name: "SQLMap".to_string(),
            user_agent_patterns: vec![
                r".*sqlmap.*".to_string(),
            ],
            header_patterns: vec![],
            path_patterns: vec![],
            timing_signature: None,
            confidence_threshold: 0.9,
        },
        // Burp Suite signatures
        ScannerSignature {
            name: "Burp Suite".to_string(),
            user_agent_patterns: vec![
                r".*Burp.*".to_string(),
                r".*burp.*".to_string(),
            ],
            header_patterns: vec![],
            path_patterns: vec![],
            timing_signature: None,
            confidence_threshold: 0.8,
        },
        // Generic bot patterns
        ScannerSignature {
            name: "Generic Scanner/Bot".to_string(),
            user_agent_patterns: vec![
                r".*bot.*".to_string(),
                r".*crawler.*".to_string(),
                r".*scanner.*".to_string(),
                r".*spider.*".to_string(),
                r"python-requests.*".to_string(),
                r"curl.*".to_string(),
                r"wget.*".to_string(),
            ],
            header_patterns: vec![],
            path_patterns: vec![],
            timing_signature: None,
            confidence_threshold: 0.6,
        },
    ]
});

#[derive(Debug, Clone)]
pub struct ScannerSignature {
    pub name: String,
    pub user_agent_patterns: Vec<String>,
    pub header_patterns: Vec<(String, String)>,
    pub path_patterns: Vec<String>,
    pub timing_signature: Option<TimingSignature>,
    pub confidence_threshold: f32,
}

#[derive(Debug, Clone)]
pub struct TimingSignature {
    pub min_interval_ms: u64,
    pub max_interval_ms: u64,
    pub burst_size: u32,
}

// Advanced Fingerprinting & Scanner Detection Implementation
async fn perform_advanced_fingerprinting(
    client_ip: &str,
    headers: &HeaderMap,
    request_path: &str,
    _http_method: &str,
    http_version: &str,
    request_body: &Option<String>,
) -> FingerprintingResult {
    let mut result = FingerprintingResult {
        scanner_type: None,
        tool_confidence: 0.0,
        browser_fingerprint: None,
        http_fingerprint: create_http_fingerprint(headers, http_version),
        timing_patterns: analyze_timing_patterns(client_ip).await,
        threat_level: ThreatLevel::Low,
    };

    // 1. Scanner Detection
    let (scanner_type, confidence) = detect_scanner_tool(headers, request_path, request_body);
    result.scanner_type = scanner_type;
    result.tool_confidence = confidence;

    // 2. Browser Fingerprinting
    result.browser_fingerprint = Some(analyze_browser_fingerprint(headers));

    // 3. Determine Threat Level
    result.threat_level = calculate_threat_level(confidence, &result.timing_patterns, &result.browser_fingerprint);

    result
}

fn detect_scanner_tool(
    headers: &HeaderMap,
    request_path: &str,
    request_body: &Option<String>,
) -> (Option<String>, f32) {
    let mut best_match: Option<String> = None;
    let mut highest_confidence = 0.0;

    for signature in SCANNER_SIGNATURES.iter() {
        let mut confidence = 0.0;
        let mut _matches = 0;
        let mut _total_checks = 0;

        // Check User-Agent patterns
        if let Some(user_agent) = headers.get("User-Agent") {
            if let Ok(ua_str) = user_agent.to_str() {
                for pattern in &signature.user_agent_patterns {
                    _total_checks += 1;
                    if let Ok(regex) = Regex::new(pattern) {
                        if regex.is_match(&ua_str.to_lowercase()) {
                            _matches += 1;
                            confidence += 0.4; // High weight for UA matches
                        }
                    }
                }
            }
        }

        // Check header patterns
        for (header_name, pattern) in &signature.header_patterns {
            _total_checks += 1;
            if let Some(header_value) = headers.get(header_name) {
                if let Ok(header_str) = header_value.to_str() {
                    if let Ok(regex) = Regex::new(pattern) {
                        if regex.is_match(&header_str.to_lowercase()) {
                            _matches += 1;
                            confidence += 0.3;
                        }
                    }
                }
            }
        }

        // Check path patterns
        for pattern in &signature.path_patterns {
            _total_checks += 1;
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(&request_path.to_lowercase()) {
                    _matches += 1;
                    confidence += 0.2;
                }
            }
        }

        // Check for additional scanner indicators
        confidence += check_additional_scanner_indicators(headers, request_path, request_body);

        // Normalize confidence based on signature threshold
        if confidence > signature.confidence_threshold && confidence > highest_confidence {
            highest_confidence = confidence;
            best_match = Some(signature.name.clone());
        }
    }

    (best_match, highest_confidence.min(1.0))
}

fn check_additional_scanner_indicators(
    headers: &HeaderMap,
    request_path: &str,
    request_body: &Option<String>,
) -> f32 {
    let mut score = 0.0;

    // Check for suspicious headers
    let suspicious_headers = [
        "X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
        "X-Scanner", "X-Tool", "X-Automated"
    ];
    
    for header in suspicious_headers {
        if headers.contains_key(header) {
            score += 0.1;
        }
    }

    // Check for missing common browser headers
    let browser_headers = ["Accept", "Accept-Language", "Accept-Encoding", "Cache-Control"];
    let mut missing_headers = 0;
    for header in browser_headers {
        if !headers.contains_key(header) {
            missing_headers += 1;
        }
    }
    if missing_headers > 2 {
        score += 0.2;
    }

    // Check for SQL injection patterns in body
    if let Some(body) = request_body {
        let sql_patterns = [
            r"union\s+select", r"or\s+1=1", r"and\s+1=1", r"drop\s+table",
            r"insert\s+into", r"delete\s+from", r"update\s+set"
        ];
        
        for pattern in sql_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(&body.to_lowercase()) {
                    score += 0.3;
                    break;
                }
            }
        }
    }

    // Check for XSS patterns in path
    let xss_patterns = [
        r"<script", r"javascript:", r"onload=", r"onerror=", r"alert\("
    ];
    
    for pattern in xss_patterns {
        if request_path.to_lowercase().contains(pattern) {
            score += 0.2;
            break;
        }
    }

    score
}

fn analyze_browser_fingerprint(headers: &HeaderMap) -> BrowserFingerprint {
    let user_agent = headers.get("User-Agent")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    let accept_header = headers.get("Accept")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    let accept_language = headers.get("Accept-Language")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    let accept_encoding = headers.get("Accept-Encoding")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    // Analyze if this looks like a real browser
    let is_real_browser = analyze_browser_authenticity(
        user_agent, accept_header, accept_language, accept_encoding, headers
    );

    let (engine, version, os) = parse_user_agent(user_agent);

    // Generate canvas fingerprint hash (simulated)
    let canvas_fingerprint = if is_real_browser {
        Some(generate_canvas_fingerprint_hash(user_agent))
    } else {
        None
    };

    BrowserFingerprint {
        is_real_browser,
        engine,
        version,
        os,
        javascript_enabled: is_real_browser, // Simplified assumption
        canvas_fingerprint,
    }
}

fn analyze_browser_authenticity(
    user_agent: &str,
    accept: &str,
    accept_language: &str,
    accept_encoding: &str,
    headers: &HeaderMap,
) -> bool {
    let ua_lower = user_agent.to_lowercase();
    
    // Check for obvious non-browser user agents
    let non_browser_indicators = [
        "curl", "wget", "python", "requests", "bot", "crawler", "scanner",
        "nmap", "masscan", "gobuster", "nikto", "sqlmap", "burp"
    ];
    
    for indicator in non_browser_indicators {
        if ua_lower.contains(indicator) {
            return false;
        }
    }

    // Check for browser-specific patterns
    let browser_patterns = [
        "mozilla", "chrome", "safari", "firefox", "edge", "opera"
    ];
    
    let has_browser_pattern = browser_patterns.iter().any(|&pattern| ua_lower.contains(pattern));
    
    // Check for typical browser headers
    let has_accept = !accept.is_empty();
    let has_accept_language = !accept_language.is_empty();
    let has_accept_encoding = !accept_encoding.is_empty() && accept_encoding.contains("gzip");
    
    // Check for sec-fetch headers (modern browsers)
    let has_sec_fetch = headers.contains_key("sec-fetch-dest") || 
                       headers.contains_key("sec-fetch-mode") ||
                       headers.contains_key("sec-fetch-site");

    // Calculate authenticity score
    let mut score = 0;
    if has_browser_pattern { score += 2; }
    if has_accept { score += 1; }
    if has_accept_language { score += 1; }
    if has_accept_encoding { score += 1; }
    if has_sec_fetch { score += 2; }

    score >= 4 // Threshold for considering it a real browser
}

fn parse_user_agent(user_agent: &str) -> (Option<String>, Option<String>, Option<String>) {
    let ua_lower = user_agent.to_lowercase();
    
    let engine = if ua_lower.contains("webkit") {
        Some("WebKit".to_string())
    } else if ua_lower.contains("gecko") {
        Some("Gecko".to_string())
    } else if ua_lower.contains("trident") {
        Some("Trident".to_string())
    } else {
        None
    };

    let version = extract_version_from_ua(user_agent);
    let os = extract_os_from_ua(user_agent);

    (engine, version, os)
}

fn extract_version_from_ua(user_agent: &str) -> Option<String> {
    let patterns = [
        r"Chrome/(\d+\.\d+)",
        r"Firefox/(\d+\.\d+)",
        r"Safari/(\d+\.\d+)",
        r"Edge/(\d+\.\d+)",
        r"Opera/(\d+\.\d+)",
    ];

    for pattern in patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if let Some(captures) = regex.captures(user_agent) {
                if let Some(version) = captures.get(1) {
                    return Some(version.as_str().to_string());
                }
            }
        }
    }
    None
}

fn extract_os_from_ua(user_agent: &str) -> Option<String> {
    let ua_lower = user_agent.to_lowercase();
    
    if ua_lower.contains("windows") {
        Some("Windows".to_string())
    } else if ua_lower.contains("macintosh") || ua_lower.contains("mac os") {
        Some("macOS".to_string())
    } else if ua_lower.contains("linux") {
        Some("Linux".to_string())
    } else if ua_lower.contains("android") {
        Some("Android".to_string())
    } else if ua_lower.contains("ios") || ua_lower.contains("iphone") || ua_lower.contains("ipad") {
        Some("iOS".to_string())
    } else {
        None
    }
}

fn generate_canvas_fingerprint_hash(user_agent: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(user_agent.as_bytes());
    hasher.update(b"canvas_fingerprint_salt");
    let result = hasher.finalize();
    general_purpose::STANDARD.encode(&result[..8]) // Truncate for readability
}

fn create_http_fingerprint(headers: &HeaderMap, http_version: &str) -> HttpFingerprint {
    let header_order: Vec<String> = headers.keys()
        .map(|name| name.to_string())
        .collect();

    let header_case_pattern = analyze_header_case_pattern(headers);
    
    HttpFingerprint {
        header_order,
        header_case_pattern,
        http_version: http_version.to_string(),
        tls_ja3_hash: None, // Would require TLS layer access
        connection_behavior: analyze_connection_behavior(headers),
    }
}

fn analyze_header_case_pattern(headers: &HeaderMap) -> String {
    let mut pattern = String::new();
    for (name, _) in headers.iter() {
        let name_str = name.as_str();
        if name_str.chars().next().unwrap_or('a').is_uppercase() {
            pattern.push('U');
        } else {
            pattern.push('L');
        }
        if name_str.contains('-') {
            pattern.push('-');
        }
    }
    pattern
}

fn analyze_connection_behavior(headers: &HeaderMap) -> String {
    let connection = headers.get("Connection")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown");
    
    let keep_alive = headers.get("Keep-Alive")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("none");

    format!("Connection: {}, Keep-Alive: {}", connection, keep_alive)
}

async fn analyze_timing_patterns(client_ip: &str) -> TimingPattern {
    let mut timing_tracker = TIMING_TRACKER.lock().unwrap();
    let now = Utc::now();
    
    let requests = timing_tracker.entry(client_ip.to_string()).or_insert_with(Vec::new);
    requests.push(now);
    
    // Keep only last 100 requests for analysis
    if requests.len() > 100 {
        requests.drain(0..requests.len() - 100);
    }
    
    let request_interval_ms = if requests.len() > 1 {
        let last_two = &requests[requests.len() - 2..];
        let interval = last_two[1].signed_duration_since(last_two[0]);
        Some(interval.num_milliseconds() as u64)
    } else {
        None
    };

    let burst_requests = count_recent_burst_requests(&requests, now);
    let scan_pattern = determine_scan_pattern(&requests);

    // Clean old entries (older than 1 hour)
    let one_hour_ago = now - chrono::Duration::hours(1);
    requests.retain(|&timestamp| timestamp > one_hour_ago);

    TimingPattern {
        request_interval_ms,
        burst_requests,
        scan_pattern,
    }
}

fn count_recent_burst_requests(requests: &[DateTime<Utc>], now: DateTime<Utc>) -> u32 {
    let ten_seconds_ago = now - chrono::Duration::seconds(10);
    requests.iter()
        .filter(|&&timestamp| timestamp > ten_seconds_ago)
        .count() as u32
}

fn determine_scan_pattern(requests: &[DateTime<Utc>]) -> ScanPattern {
    if requests.len() < 3 {
        return ScanPattern::Normal;
    }

    let intervals: Vec<i64> = requests.windows(2)
        .map(|window| window[1].signed_duration_since(window[0]).num_milliseconds())
        .collect();

    // Check for very fast scanning (masscan-like)
    if intervals.iter().all(|&interval| interval < 100) {
        return ScanPattern::Bruteforce;
    }

    // Check for regular intervals (automated scanning)
    let avg_interval = intervals.iter().sum::<i64>() / intervals.len() as i64;
    let variance = intervals.iter()
        .map(|&interval| (interval - avg_interval).pow(2))
        .sum::<i64>() / intervals.len() as i64;

    if variance < 1000 { // Low variance = regular pattern
        ScanPattern::Sequential
    } else if avg_interval < 1000 { // Fast but irregular
        ScanPattern::Dictionary
    } else {
        ScanPattern::Random
    }
}

fn calculate_threat_level(
    scanner_confidence: f32,
    timing_patterns: &TimingPattern,
    browser_fingerprint: &Option<BrowserFingerprint>,
) -> ThreatLevel {
    let mut threat_score = 0.0;

    // Scanner detection confidence
    threat_score += scanner_confidence * 4.0;

    // Timing pattern analysis
    match timing_patterns.scan_pattern {
        ScanPattern::Bruteforce => threat_score += 3.0,
        ScanPattern::Sequential => threat_score += 2.0,
        ScanPattern::Dictionary => threat_score += 2.5,
        ScanPattern::Random => threat_score += 1.0,
        ScanPattern::Normal => threat_score += 0.0,
    }

    // Burst request analysis
    if timing_patterns.burst_requests > 50 {
        threat_score += 2.0;
    } else if timing_patterns.burst_requests > 10 {
        threat_score += 1.0;
    }

    // Browser authenticity
    if let Some(browser) = browser_fingerprint {
        if !browser.is_real_browser {
            threat_score += 2.0;
        }
    }

    // Convert score to threat level
    if threat_score >= 7.0 {
        ThreatLevel::Critical
    } else if threat_score >= 5.0 {
        ThreatLevel::High
    } else if threat_score >= 3.0 {
        ThreatLevel::Medium
    } else {
        ThreatLevel::Low
    }
}

// JavaScript fingerprinting payload generator
fn generate_javascript_fingerprinting() -> String {
    r#"
<script>
(function() {
    // Canvas fingerprinting
    function getCanvasFingerprint() {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = 200;
        canvas.height = 50;
        
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('Honeypot Canvas Test 🍯', 2, 2);
        
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillRect(100, 5, 80, 20);
        
        return canvas.toDataURL();
    }
    
    // WebGL fingerprinting
    function getWebGLFingerprint() {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (!gl) return 'WebGL not supported';
        
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        return {
            vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
            renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
        };
    }
    
    // Audio fingerprinting
    function getAudioFingerprint() {
        return new Promise((resolve) => {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const analyser = audioContext.createAnalyser();
            const gainNode = audioContext.createGain();
            
            oscillator.connect(analyser);
            analyser.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            oscillator.frequency.value = 1000;
            oscillator.start(0);
            
            setTimeout(() => {
                const fingerprint = Array.from(new Uint8Array(analyser.frequencyBinCount))
                    .reduce((acc, val) => acc + val, 0);
                oscillator.stop();
                resolve(fingerprint);
            }, 100);
        });
    }
    
    // Collect comprehensive fingerprint
    async function collectFingerprint() {
        const fp = {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            language: navigator.language,
            languages: navigator.languages,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            screen: {
                width: screen.width,
                height: screen.height,
                colorDepth: screen.colorDepth,
                pixelDepth: screen.pixelDepth
            },
            canvas: getCanvasFingerprint(),
            webgl: getWebGLFingerprint(),
            audio: await getAudioFingerprint(),
            plugins: Array.from(navigator.plugins).map(p => p.name),
            cookieEnabled: navigator.cookieEnabled,
            localStorage: !!window.localStorage,
            sessionStorage: !!window.sessionStorage,
            indexedDB: !!window.indexedDB,
            hardwareConcurrency: navigator.hardwareConcurrency,
            deviceMemory: navigator.deviceMemory,
            timestamp: Date.now()
        };
        
        // Send fingerprint to server
        fetch('/fingerprint', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(fp)
        }).catch(() => {}); // Ignore errors
    }
    
    // Execute fingerprinting
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', collectFingerprint);
    } else {
        collectFingerprint();
    }
})();
</script>
"#.to_string()
}

