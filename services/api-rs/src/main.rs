use axum::{routing::get, Router};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // Router
    let app = Router::new().route("/health", get(|| async { "ok" }));

    // Adresse & Listener
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("API running → http://{}/health", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    // axum 0.7: serve(listener, app)
    axum::serve(listener, app).await.unwrap();
}
