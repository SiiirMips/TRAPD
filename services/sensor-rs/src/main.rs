use chrono::Utc;
use serde::Serialize;
use tokio::time::{sleep, Duration};

#[derive(Serialize)]
struct Event {
    ts: String,
    org_id: &'static str,
    sensor_id: &'static str,
    event_type: &'static str,
    src_ip: &'static str,
    src_port: u16,
    dst_port: u16,
    proto: &'static str,
    severity: &'static str,
}

#[tokio::main]
async fn main() {
    println!("Sensor up (stub) – erzeugt Dummy-Events (stdout) …");
    loop {
        let e = Event {
            ts: Utc::now().to_rfc3339(),
            org_id: "demo",
            sensor_id: "sensor-1",
            event_type: "ssh.login",
            src_ip: "203.0.113.5",
            src_port: 54321,
            dst_port: 22,
            proto: "tcp",
            severity: "low",
        };
        println!("{}", serde_json::to_string(&e).unwrap());
        sleep(Duration::from_secs(3)).await;
    }
}
