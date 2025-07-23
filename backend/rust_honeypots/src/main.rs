use axum::{
    extract::{ConnectInfo, State, OriginalUri},
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use dotenv::dotenv;
use std::env;
use reqwest::Client;
use axum::http::{HeaderMap, Method};
use url::Url;

// Datenstruktur für den HTTP-Client und Konfiguration
#[derive(Clone)]
struct AppState {
    http_client: Client,
    supabase_api_url: String,
    supabase_service_role_key: String,
    python_ai_url: String, // NEU: URL der Python KI
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    let supabase_api_url = env::var("SUPABASE_LOCAL_URL")
        .expect("SUPABASE_LOCAL_URL muss gesetzt sein");
    let supabase_service_role_key = env::var("SUPABASE_LOCAL_SERVICE_ROLE_KEY")
        .expect("SUPABASE_LOCAL_SERVICE_ROLE_KEY muss gesetzt sein");
    let python_ai_url = env::var("PYTHON_AI_URL") // NEU: Umgebungsvariable für Python KI URL
        .expect("PYTHON_AI_URL muss gesetzt sein");


    let http_client = Client::new();

    let app_state = AppState {
        http_client,
        supabase_api_url,
        supabase_service_role_key,
        python_ai_url, // Hinzugefügt
    };

    let app = Router::new()
        .route("/", get(honeypot_handler))
        .route("/*path", get(honeypot_handler))
        .route("/", post(honeypot_handler_post))
        .route("/*path", post(honeypot_handler_post))
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("HTTP Honeypot lauscht auf http://{}", addr);

    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}

// Handler für GET-Anfragen
async fn honeypot_handler(
    method: Method,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    uri: OriginalUri,
    headers: HeaderMap,
) -> impl IntoResponse {
    log_and_forward_interaction(method, addr, state, uri, headers, None).await
}

// Handler für POST-Anfragen
async fn honeypot_handler_post(
    method: Method,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    uri: OriginalUri,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    log_and_forward_interaction(method, addr, state, uri, headers, Some(body)).await
}

// Allgemeine Funktion zum Loggen und Weiterleiten von Interaktionen
async fn log_and_forward_interaction(
    method: Method,
    addr: SocketAddr,
    state: AppState,
    uri: OriginalUri,
    headers: HeaderMap,
    request_body: Option<String>,
) -> impl IntoResponse {
    let client_ip = addr.ip().to_string();
    let request_path = uri.path();
    let user_agent = headers.get("User-Agent")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("N/A");
    let http_method = method.as_str();

    let mut query_params = serde_json::Map::new();
    if let Some(query) = uri.query() {
        if let Ok(parsed_url) = Url::parse(&format!("http://dummy.com?{}", query)) {
            for (key, value) in parsed_url.query_pairs() {
                query_params.insert(key.into_owned(), Value::String(value.into_owned()));
            }
        }
    }

    println!("Honeypot-Interaktion: IP: {}, Methode: {}, Pfad: {}, User-Agent: {}", client_ip, http_method, request_path, user_agent);
    if let Some(body) = &request_body {
        println!("Request Body: {}", body);
    }

    // Daten für die Datenbank und die KI
    let mut interaction_data = json!({
        "request_path": request_path,
        "method": http_method,
        "user_agent": user_agent,
        "headers": headers.iter().map(|(k, v)| {
            (k.to_string(), Value::String(v.to_str().unwrap_or("").to_string()))
        }).collect::<serde_json::Map<String, Value>>(),
        "query_parameters": query_params,
    });

    if let Some(body) = request_body.clone() { // Clone, da Body für Supabase und KI benötigt wird
        interaction_data["request_body"] = Value::String(body);
    }

    // --- 1. Logge in Supabase ---
    let supabase_log_payload = json!({
        "source_ip": client_ip,
        "honeypot_type": "http",
        "interaction_data": interaction_data, // Nutze die vollständigen Daten hier
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
            if res.status().is_success() {
                println!("Log erfolgreich in Supabase gespeichert. Status: {}", res.status());
            } else {
                eprintln!("Fehler beim Speichern des Logs in Supabase: Status {}", res.status());
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
    let ki_payload = json!({
        "source_ip": client_ip,
        "honeypot_type": "http",
        "interaction_data": interaction_data, // Sende die gleichen umfassenden Daten an die KI
        "status": "logged" // Status könnte von Honeypot immer 'logged' sein
    });

    let ki_api_endpoint = format!("{}/analyze-and-disinform/", state.python_ai_url);

    match state.http_client
        .post(&ki_api_endpoint)
        .header("Content-Type", "application/json")
        .json(&ki_payload)
        .send()
        .await
    {
        Ok(res) => {
            if res.status().is_success() {
                println!("Daten erfolgreich an Python KI-Mockup gesendet. Status: {}", res.status());
                if let Ok(ki_response_body) = res.json::<Value>().await {
                    println!("Antwort von KI-Mockup: {:?}", ki_response_body);
                    // Hier könntest du die Desinformation weiterverarbeiten
                    // oder basierend darauf eine spezifischere Honeypot-Antwort generieren.
                }
            } else {
                eprintln!("Fehler beim Senden an Python KI-Mockup: Status {}", res.status());
                if let Ok(body) = res.text().await {
                    eprintln!("Antwort Body von KI-Mockup: {}", body);
                }
            }
        },
        Err(e) => {
            eprintln!("Fehler beim Senden der Anfrage an Python KI-Mockup: {:?}", e);
        }
    }

    // Dummy-Antwort an den Angreifer (könnte später durch KI-Antwort beeinflusst werden)
    Html("<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>")
}