use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() {
    println!("Processor up (stub) – wartet auf Events (später NATS/CH) …");
    loop {
        // Platzhalter-Work: später Batch/Korrelation/Insert
        sleep(Duration::from_secs(5)).await;
        println!("Processor heartbeat");
    }
}
