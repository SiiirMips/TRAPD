# TRAPD Ingestion Pipeline

## Setup

1. **Bootstrap Ingest SQL**
   ```powershell
   powershell -File tools/bootstrap-ingest.ps1
   ```
2. **API starten**
   ```powershell
   cd services/api-rs
   cargo run
   ```
3. **Health-Check**
   ```powershell
   Invoke-WebRequest http://localhost:8080/health
   ```
4. **Testdaten laden**
   ```powershell
   powershell -File tools/gen-load.ps1
   ```
5. **SQL-Check**
   ```powershell
   docker exec trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --query "SELECT count() FROM trapd.events"
   ```

## Endpunkte

- **POST /ingest**: JSON array oder JSONEachRow → ClickHouse ingest_raw
- **GET /health**: Version & Event-Count

## Konfiguration

- `.env.example` enthält alle Variablen
- `.env` wird nicht committet

## Acceptance Criteria

- ingest.sql angewendet, ingest_raw & mv_ingest_to_events existieren
- /health liefert ok:true, clickhouse_version nicht leer
- gen-load.ps1 schreibt ≥ 1000 Events, count() steigt
- Insert robust: Retries bei Ausfall
- Code baut & startet (cargo build -p api-rs --release)
- .env.example enthalten
- Nur HTTP-API zu ClickHouse
- JSONEachRow wird verwendet
- Saubere Logs
- Skripte Windows-kompatibel

## Bonus
- **POST /ingest/now**: Events ohne ts_str, Zeit wird serverseitig gesetzt
- **/metrics**: Prometheus-ready Zähler
