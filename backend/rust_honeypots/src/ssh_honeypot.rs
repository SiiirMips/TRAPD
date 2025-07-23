// backend/rust_honeypots/src/ssh_honeypot.rs

use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // Für read_exact, write_all
use serde_json::{json, Value};
use crate::common::SharedAppState;
use std::time::Duration; // Für Read-Timeout

// Öffentliche Funktion zum Starten des SSH-Honeypots
pub async fn start_ssh_honeypot(app_state: SharedAppState) {
    let ssh_addr = SocketAddr::from(([0, 0, 0, 0], 2222)); // SSH auf Port 2222
    println!("SSH Honeypot lauscht auf http://{}", ssh_addr);

    let mut listener = TcpListener::bind(ssh_addr).await.unwrap();

    loop {
        match listener.accept().await {
            Ok((socket, client_addr)) => {
                println!("SSH Honeypot: Neue Verbindung von {}", client_addr);
                let state = app_state.clone();
                tokio::spawn(async move {
                    handle_ssh_connection(socket, client_addr, state).await;
                });
            },
            Err(e) => eprintln!("SSH Listener Fehler: {:?}", e),
        }
    }
}

// Funktion zur Bearbeitung einer einzelnen SSH-Verbindung
async fn handle_ssh_connection(mut stream: TcpStream, client_addr: SocketAddr, state: SharedAppState) {
    let client_ip = client_addr.ip().to_string();
    let client_port = client_addr.port();

    // Schritt 1: Senden einer SSH-Protokollversion (Dummy)
    let server_banner = "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n"; // Standard OpenSSH Banner
    if let Err(e) = stream.write_all(server_banner.as_bytes()).await {
        eprintln!("Fehler beim Senden des SSH Banners an {}: {:?}", client_addr, e);
        return;
    }

    // Schritt 2: Empfangen der Client-Protokollversion und erster Daten
    let mut buffer = vec![0; 1024]; // Puffer für eingehende Daten
    let n_bytes_read = tokio::time::timeout(
        Duration::from_secs(5), // Timeout nach 5 Sekunden
        stream.read(&mut buffer)
    ).await;

    let client_data_raw = match n_bytes_read {
        Ok(Ok(n)) => String::from_utf8_lossy(&buffer[..n]).into_owned(),
        Ok(Err(e)) => { eprintln!("Fehler beim Lesen von SSH-Daten von {}: {:?}", client_addr, e); return; },
        Err(_) => { eprintln!("Timeout beim Lesen von SSH-Daten von {}", client_addr); return; }, // Timeout Error
    };

    println!("SSH Honeypot: Rohdaten von {} erhalten: {}", client_addr, client_data_raw.trim());

    // Versuch, Anmeldedaten zu extrahieren (sehr rudimentär!)
    // In einem echten Honeypot würde man hier komplexere SSH-Protokoll-Parsing-Bibliotheken verwenden.
    // Dies ist ein Heuristik-Ansatz für Login-Versuche.
    let mut username_attempt = "unknown";
    let mut password_attempt = "unknown";
    let mut login_method = "raw_tcp_interception";

    // Einfacher Regex-ähnlicher Match für "user XYZ" oder "pass ABC" im Rohdaten-Stream
    if let Some(user_idx) = client_data_raw.find("user") {
        if let Some(user_end_idx) = client_data_raw[user_idx..].find("\n") {
            let user_line = &client_data_raw[user_idx..user_idx + user_end_idx];
            if let Some(eq_idx) = user_line.find("=") {
                username_attempt = user_line[eq_idx+1..].trim();
            } else {
                username_attempt = user_line["user ".len()..].trim();
            }
        }
    }
    if let Some(pass_idx) = client_data_raw.find("pass") {
        if let Some(pass_end_idx) = client_data_raw[pass_idx..].find("\n") {
            let pass_line = &client_data_raw[pass_idx..pass_idx + pass_end_idx];
            if let Some(eq_idx) = pass_line.find("=") {
                password_attempt = pass_line[eq_idx+1..].trim();
            } else {
                password_attempt = pass_line["pass ".len()..].trim();
            }
        }
    }
    if client_data_raw.contains("ssh-connection") {
        login_method = "ssh_client_attempt";
        // In einem echten Szenario würde man hier die SSH-Protokollspezifikation parsen
        // und nicht nach "user" oder "pass" als Substring suchen.
    }

    // Daten für Supabase und KI vorbereiten
    let interaction_data = json!({
        "client_banner": client_data_raw.trim(), // Rohdaten des Clients
        "username_attempt": username_attempt,
        "password_attempt": password_attempt,
        "login_method": login_method,
        "client_ip": client_ip,
        "client_port": client_port,
    });

    // Logge in Supabase und sende an KI
    log_ssh_interaction(interaction_data, client_addr, state).await;

    // Senden einer Antwort (Dummy-Fehlermeldung)
    let response_banner = "Protocol mismatch.\r\n"; // Oder "Authentication failed."
    if let Err(e) = stream.write_all(response_banner.as_bytes()).await {
        eprintln!("Fehler beim Senden der SSH-Antwort an {}: {:?}", client_addr, e);
    }
}

// Funktion zum Loggen und Weiterleiten von SSH-Interaktionen
async fn log_ssh_interaction(interaction_data: Value, client_addr: SocketAddr, state: SharedAppState) {
    let client_ip = client_addr.ip().to_string();

    println!("SSH Honeypot: Logge SSH-Interaktion von {}", client_ip);

    // --- 1. Logge in Supabase (attacker_logs) ---
    let supabase_log_payload = json!({
        "source_ip": client_ip,
        "honeypot_type": "ssh", // SSH-Typ
        "interaction_data": interaction_data, // SSH-spezifische Daten
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
                println!("SSH Log erfolgreich in Supabase gespeichert. Status: {}", status_code);
            } else {
                eprintln!("Fehler beim Speichern des SSH Logs in Supabase: Status {}", status_code);
                if let Ok(body) = res.text().await {
                    eprintln!("Antwort Body: {}", body);
                }
            }
        },
        Err(e) => {
            eprintln!("Fehler beim Senden des SSH Logs an Supabase: {:?}", e);
        }
    }

    // --- 2. Sende Daten an Python KI-Mockup ---
    let ki_api_endpoint = format!("{}/analyze/and-disinform/", state.python_ai_url);

    let ki_payload = json!({
        "source_ip": client_ip,
        "honeypot_type": "ssh", // SSH-Typ
        "interaction_data": interaction_data, // SSH-spezifische Daten
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
                println!("SSH Daten erfolgreich an Python KI-Mockup gesendet. Status: {}", status_code);
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
}