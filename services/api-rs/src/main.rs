
use axum::{
    extract::{State, Json},
    routing::{get, post},
    Router, http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use dotenvy::dotenv;
use figment::{Figment, providers::{Env, Serialized}};
use reqwest::Client;
use tower::{limit::ConcurrencyLimitLayer, ServiceBuilder};
use tracing::{info, error};
use tracing_subscriber;


#[derive(Debug, Deserialize, Serialize, Clone)]
struct Config {
    ch_http: String,
    ch_user: String,
    ch_pass: String,
    ch_db: String,
    ingest_timeout_ms: u64,
    ingest_retries: usize,
    api_port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ch_http: "http://localhost:8123".to_string(),
            ch_user: "trapd".to_string(),
            ch_pass: "trapd_pwd".to_string(),
            ch_db: "trapd".to_string(),
            ingest_timeout_ms: 5000,
            ingest_retries: 3,
            api_port: 8080,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct IngestEvent {
    ts_str: Option<String>,
    org_id: String,
    sensor_id: String,
    event_type: String,
    src_ip: String,
    src_port: u16,
    dst_port: u16,
    proto: String,
    severity: String,
    payload: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    clickhouse_version: String,
    events: u64,
    ok: bool,
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    // Config aus ENV

    let config: Config = Figment::from(Serialized::defaults(Config::default()))
        .merge(figment::providers::Env::raw().split("_"))
        .extract()
        .unwrap_or_else(|_| Config::default());

    let client = Client::builder()
        .timeout(Duration::from_millis(config.ingest_timeout_ms))
        .build()
        .unwrap();

    let shared = Arc::new((config.clone(), client));

    let app = Router::new()
        .route("/ingest", post(ingest_handler))
        .route("/health", get(health_handler))
        .layer(ServiceBuilder::new()
            .layer(ConcurrencyLimitLayer::new(32)) // Rate Limiting
        )
        .with_state(shared);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.api_port));
    info!("API running → http://{}/health", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn ingest_handler(
    State(state): State<Arc<(Config, Client)>>,
    body: axum::body::Bytes,
) -> Result<StatusCode, (StatusCode, String)> {
    let (config, client) = &*state;
    let body_str = String::from_utf8_lossy(&body);

    // Versuche als JSON-Array zu parsen
    let events: Result<Vec<IngestEvent>, _> = serde_json::from_str(&body_str);
    let lines: Vec<String> = if let Ok(evts) = events {
        // JSON-Array → JSONEachRow
        evts.into_iter().map(|e| serde_json::to_string(&e).unwrap()).collect()
    } else {
        // Versuche als JSONEachRow (newline-delimited JSON)
        body_str.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()
    };
    if lines.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "No valid events".to_string()));
    }

    let insert_body = lines.join("\n");
    let url = format!("{}/?user={}&password={}&database={}&query=INSERT INTO ingest_raw FORMAT JSONEachRow",
        config.ch_http, config.ch_user, config.ch_pass, config.ch_db);

    let mut last_err = None;
    for attempt in 0..config.ingest_retries {
        let resp = client.post(&url)
            .body(insert_body.clone())
            .header("Content-Type", "application/json")
            .send()
            .await;
        match resp {
            Ok(r) if r.status().is_success() => {
                info!("Inserted {} events", lines.len());
                return Ok(StatusCode::OK);
            }
            Ok(r) => {
                last_err = Some(format!("ClickHouse error: {}", r.text().await.unwrap_or_default()));
            }
            Err(e) => {
                last_err = Some(format!("Request error: {}", e));
            }
        }
        tokio::time::sleep(Duration::from_millis(100 * 2u64.pow(attempt as u32))).await;
    }
    error!("Insert failed: {:?}", last_err);
    Err((StatusCode::BAD_GATEWAY, last_err.unwrap_or_else(|| "Unknown error".to_string())))
}

async fn health_handler(State(state): State<Arc<(Config, Client)>>) -> Result<Json<HealthResponse>, StatusCode> {
    let (config, client) = &*state;
    let url_version = format!("{}/?user={}&password={}&database={}&query=SELECT version()", config.ch_http, config.ch_user, config.ch_pass, config.ch_db);
    let url_count = format!("{}/?user={}&password={}&database={}&query=SELECT count() FROM events", config.ch_http, config.ch_user, config.ch_pass, config.ch_db);
    let version = match client.get(&url_version).send().await {
        Ok(r) => r.text().await.unwrap_or_default().trim().to_string(),
        Err(_) => String::new(),
    };
    let events = match client.get(&url_count).send().await {
        Ok(r) => r.text().await.unwrap_or("0".to_string()).trim().parse().unwrap_or(0),
        Err(_) => 0,
    };
    let ok = !version.is_empty();
    Ok(Json(HealthResponse { clickhouse_version: version, events, ok }))
}
