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

use crate::common::SharedAppState; // Importiere SharedAppState aus dem 'common' Modul

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
    State(state): State<SharedAppState>, // Verwende SharedAppState
    uri: OriginalUri,
    headers: HeaderMap,
    http_version: Version,
) -> impl IntoResponse {
    log_http_interaction(method, addr, state, uri, headers, http_version, None).await
}

// Handler für POST-Anfragen (mit Body-Extraction)
async fn honeypot_handler_post(
    method: Method,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<SharedAppState>, // Verwende SharedAppState
    uri: OriginalUri,
    headers: HeaderMap,
    http_version: Version,
    body: String, // Extrahiere den Request Body als String
) -> impl IntoResponse {
    log_http_interaction(method, addr, state, uri, headers, http_version, Some(body)).await
}

// Allgemeine Funktion zum Loggen und Weiterleiten von HTTP-Interaktionen
async fn log_http_interaction(
    method: Method,
    addr: SocketAddr,
    state: SharedAppState, // Verwende SharedAppState
    uri: OriginalUri,
    headers: HeaderMap,
    http_version_raw: Version,
    request_body: Option<String>,
) -> impl IntoResponse {
    let client_ip = addr.ip().to_string();
    let client_port = addr.port();
    let full_uri = uri.to_string();
    let request_path = uri.path();
    let http_method = method.as_str();

    // Konvertiere HTTP-Version zu String
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
    let supabase_log_payload = json!({
        "source_ip": client_ip,
        "honeypot_type": "http",
        "interaction_data": interaction_data,
        "status": "logged"
    });

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

    // --- 2. Sende Daten an Python KI-Mockup ---
    let ki_api_endpoint = format!("{}/analyze/and-disinform/", state.python_ai_url);

    let ki_payload = json!({
        "source_ip": client_ip,
        "honeypot_type": "http",
        "interaction_data": interaction_data,
        "status": "logged"
    });

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
                    println!("Antwort von KI-Mockup: {:?}", ki_response_body);
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

    // Dummy-Antwort an den Angreifer
    Html("<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>")
}