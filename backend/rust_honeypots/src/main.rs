// backend/rust_honeypots/src/main.rs

use tokio::net::TcpListener;
use dotenv::dotenv;
use std::env;
use reqwest::Client;
use std::sync::Arc;

// Modul-Deklarationen
mod common;
mod http_honeypot;
mod ssh_honeypot;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let supabase_api_url = env::var("SUPABASE_LOCAL_URL")
        .expect("SUPABASE_LOCAL_URL muss gesetzt sein");
    let supabase_service_role_key = env::var("SUPABASE_LOCAL_SERVICE_ROLE_KEY")
        .expect("SUPABASE_LOCAL_SERVICE_ROLE_KEY muss gesetzt sein");
    let python_ai_url = env::var("PYTHON_AI_URL")
        .expect("PYTHON_AI_URL muss gesetzt sein");

    let http_client = Client::new();

    let app_state = Arc::new(common::AppState {
        http_client,
        supabase_api_url,
        supabase_service_role_key,
        python_ai_url,
    });

    // KORRIGIERT: app_state für jeden Task klonen, BEVOR sie gespawnt werden
    let http_app_state_clone = app_state.clone();
    let ssh_app_state_clone = app_state.clone();


    // --- HTTP Honeypot starten ---
    let http_addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("HTTP Honeypot lauscht auf http://{}", http_addr);
    let http_server_task = tokio::spawn(async move {
        let listener = TcpListener::bind(http_addr).await.unwrap();
        axum::serve(listener, http_honeypot::create_http_router(http_app_state_clone).into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .unwrap();
    });


    // --- SSH Honeypot starten ---
    let ssh_server_task = tokio::spawn(async move {
        ssh_honeypot::start_ssh_honeypot(ssh_app_state_clone).await;
    });


    // Warte, bis beide Server beendet sind (was sie im Normalfall nicht tun)
    tokio::select! {
        _ = http_server_task => println!("HTTP server exited"),
        _ = ssh_server_task => println!("SSH server exited"),
    }
}