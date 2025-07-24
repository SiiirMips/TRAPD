// backend/rust_honeypots/src/ssh_honeypot.rs

use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde_json::{json, Value};
use crate::common::SharedAppState;
use std::time::Duration; // Für Read-Timeout
use std::convert::TryInto; // Für TryInto

// Öffentliche Funktion zum Starten des SSH-Honeypots
pub async fn start_ssh_honeypot(app_state: SharedAppState) {
    let ssh_addr = SocketAddr::from(([0, 0, 0, 0], 2222)); // SSH auf Port 2222
    println!("SSH Honeypot lauscht auf http://{}", ssh_addr);

    let listener = TcpListener::bind(ssh_addr).await.unwrap();

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

    // Schritt 1: Senden des Server-Banners
    // Wir senden immer noch einen SSH-Banner, da Clients das erwarten.
    let server_banner = "SSH-2.0-OpenSSH_7.6p1 EchoChamber-Honeypot\r\n"; // Angepasster Banner
    if let Err(e) = stream.write_all(server_banner.as_bytes()).await {
        eprintln!("Fehler beim Senden des SSH Banners an {}: {:?}", client_addr, e);
        let _ = stream.shutdown().await;
        return;
    }

    // Schritt 2: Empfangen des Client-Banners (und erster Daten)
    let mut client_banner_buf = vec![0; 255]; // Max SSH banner length is 255
    let client_data_raw = match tokio::time::timeout(
        Duration::from_secs(2), // Gebe dem Client 2 Sekunden Zeit, den Banner zu senden
        stream.read(&mut client_banner_buf)
    ).await {
        Ok(Ok(n)) => String::from_utf8_lossy(&client_banner_buf[..n]).into_owned(),
        _ => String::from("No client banner or read error"),
    };

    println!("SSH Honeypot: Client-Banner erhalten: {}", client_data_raw.trim());

    // Rudimentäre Erkennung von Anmeldedaten im Rohdatenstrom
    let username_attempt = extract_from_raw(&client_data_raw, "user", "username").unwrap_or("unknown".to_string());
    let password_attempt = extract_from_raw(&client_data_raw, "pass", "password").unwrap_or("unknown".to_string());
    let login_method = if client_data_raw.contains("ssh-connection") { "ssh_client_attempt" } else { "raw_tcp_interception" };


    // Daten für Supabase und KI vorbereiten
    let interaction_data = json!({
        "client_banner": client_data_raw.trim(),
        "username_attempt": username_attempt,
        "password_attempt": password_attempt,
        "login_method": login_method,
        "client_ip": client_ip,
        "client_port": client_port,
    });

    // Logge in Supabase und sende an KI.
    // Die KI wird die Desinformation formulieren, um auf eine HTTP-Seite zu verweisen.
    let (disinformation_content, _ki_response_raw) = log_ssh_interaction(interaction_data, client_addr, state.clone()).await;
    
    // Die Antwort an den SSH-Client wird einfach ein generischer Fehler sein,
    // da wir die Desinformation über HTTP liefern.
    let response_message = format!("Authentication failed. Please check server status at http://{}:8080/system-status?ref={}\r\n", client_ip, "your_session_id_here"); // Dummy-ID
    // Hier können wir die Desinformation in den Query-Parameter einbetten
    let encoded_disinfo = urlencoding::encode(&disinformation_content).into_owned();
    let final_response_message = format!("Authentication failed. For more information, please visit http://{}:8080/system-status?details={}\r\n", client_ip, encoded_disinfo);


    if let Err(e) = stream.write_all(final_response_message.as_bytes()).await {
        eprintln!("Fehler beim Senden der Antwort an {}: {:?}", client_addr, e);
    }
    
    // Verbindung sauber schließen
    let _ = stream.shutdown().await;
}

// Helper function to extract simple key-value from raw string, if found
fn extract_from_raw(raw_data: &str, key_prefix: &str, _default_value: &str) -> Option<String> {
    let lower_raw = raw_data.to_lowercase();
    if let Some(start_idx) = lower_raw.find(key_prefix) {
        let after_key = &raw_data[start_idx + key_prefix.len()..];
        if let Some(val_start_idx) = after_key.find(|c: char| c == '=' || c.is_whitespace()) {
            let value_part = &after_key[val_start_idx..];
            if let Some(val_end_idx) = value_part.find('\n') {
                return Some(value_part[..val_end_idx].trim().to_string());
            }
        }
    }
    None
}


// Funktion zum Loggen und Weiterleiten von SSH-Interaktionen (Unverändert)
async fn log_ssh_interaction(interaction_data: Value, client_addr: SocketAddr, state: SharedAppState) -> (String, Value) { // Rückgabe von String und Value
    let client_ip = client_addr.ip().to_string();

    println!("SSH Honeypot: Logge SSH-Interaktion von {}", client_ip);

    // --- 1. Logge in Supabase (attacker_logs) ---
    let supabase_log_payload = json!({
        "source_ip": client_ip,
        "honeypot_type": "ssh",
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

    // --- 2. Sende Daten an Python KI-Mockup und erhalte Desinformation ---
    let ki_api_endpoint = format!("{}/analyze/and-disinform/", state.python_ai_url);

    let ki_payload = json!({
        "source_ip": client_ip,
        "honeypot_type": "ssh",
        "interaction_data": interaction_data,
        "status": "logged"
    });

    let mut disinformation_content = String::from("Authentication failed. Try again.");
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
                println!("SSH Daten erfolgreich an Python KI-Mockup gesendet. Status: {}", status_code);
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
            disinformation_content = "KI-Fehler: Konnte keine Antwort erhalten.".to_string(); // Fallback for network errors
        }
    }
    (disinformation_content, ki_response_raw)
}
