#!/usr/bin/env bash
# Wrapper-Skript zum Starten aller wichtigen lokalen Services des TRAPD-Projekts.
#
# Dieses Skript startet (sofern nicht explizit übersprungen):
#   - die lokale Supabase-Instanz (über die supabase CLI)
#   - das Python AI Backend (FastAPI/Uvicorn)
#   - den Rust-Honeypot (Cargo)
#   - das Next.js Frontend (npm)
#
# Optionale Argumente:
#   --skip-supabase   Supabase nicht starten
#   --skip-python     Python-Backend nicht starten
#   --skip-rust       Rust-Honeypot nicht starten
#   --skip-frontend   Frontend nicht starten
#   --help            Diese Hilfe anzeigen

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUPABASE_DIR="$ROOT_DIR/backend/supabase"
PYTHON_DIR="$ROOT_DIR/backend/python_ai"
RUST_DIR="$ROOT_DIR/backend/rust_honeypots"
FRONTEND_DIR="$ROOT_DIR/frontend"

SKIP_SUPABASE=false
SKIP_PYTHON=false
SKIP_RUST=false
SKIP_FRONTEND=false

usage() {
  sed -n '1,40p' "$0"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-supabase) SKIP_SUPABASE=true ;;
    --skip-python)   SKIP_PYTHON=true ;;
    --skip-rust)     SKIP_RUST=true ;;
    --skip-frontend) SKIP_FRONTEND=true ;;
    -h|--help)       usage; exit 0 ;;
    *)
      echo "Unbekannte Option: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

PIDS=()
NAMES=()

cleanup() {
  local exit_code=$?
  trap - EXIT SIGINT SIGTERM
  echo -e "\nBeende gestartete Services ..."
  for idx in "${!PIDS[@]}"; do
    local pid="${PIDS[$idx]}"
    local name="${NAMES[$idx]}"
    if kill -0 "$pid" >/dev/null 2>&1; then
      echo " -> Stoppe $name (PID $pid)"
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done
  # Warte auf das kontrollierte Beenden der Prozesse
  for pid in "${PIDS[@]}"; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      wait "$pid" 2>/dev/null || true
    fi
  done
  exit "$exit_code"
}

trap cleanup EXIT SIGINT SIGTERM

start_process() {
  local name="$1"
  local cmd="$2"
  echo "Starte $name ..."
  bash -c "$cmd" &
  local pid=$!
  PIDS+=("$pid")
  NAMES+=("$name")
  echo " -> $name läuft (PID $pid)"
}

# Lade optionale Umgebungsvariablen aus .env, falls vorhanden
ENV_FILE="$ROOT_DIR/.env"
if [[ -f "$ENV_FILE" ]]; then
  set -o allexport
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +o allexport
  echo "Umgebungsvariablen aus .env geladen"
fi

# Sinnvolle Defaults setzen, falls nicht gesetzt
export SUPABASE_LOCAL_URL="${SUPABASE_LOCAL_URL:-http://127.0.0.1:54321}"
export SUPABASE_LOCAL_SERVICE_ROLE_KEY="${SUPABASE_LOCAL_SERVICE_ROLE_KEY:-YOUR_SUPABASE_SERVICE_ROLE_KEY_HERE}"
export PYTHON_AI_PORT="${PYTHON_AI_PORT:-8000}"
export PYTHON_AI_URL="${PYTHON_AI_URL:-http://127.0.0.1:${PYTHON_AI_PORT}}"
RUST_HONEYPOT_PORT=8080
export NEXT_PORT="${NEXT_PORT:-3000}"

if [[ "$SUPABASE_LOCAL_SERVICE_ROLE_KEY" == "YOUR_SUPABASE_SERVICE_ROLE_KEY_HERE" ]]; then
  echo "WARNUNG: SUPABASE_LOCAL_SERVICE_ROLE_KEY ist nicht gesetzt und enthält noch den Platzhalter."
  echo "         Bitte trage den korrekten Service Role Key in .env ein."
fi

SERVICES_STARTED=0

if [[ "$SKIP_SUPABASE" == false ]]; then
  if command -v supabase >/dev/null 2>&1; then
    if [[ -d "$SUPABASE_DIR" ]]; then
      start_process "supabase" "cd '$SUPABASE_DIR' && supabase start"
      ((SERVICES_STARTED++))
    else
      echo "Supabase-Verzeichnis $SUPABASE_DIR nicht gefunden – überspringe Supabase." >&2
    fi
  else
    echo "Supabase CLI nicht gefunden. Installiere sie oder starte Supabase manuell." >&2
  fi
fi

if [[ "$SKIP_PYTHON" == false ]]; then
  if [[ -d "$PYTHON_DIR" ]]; then
    python_cmd="cd '$PYTHON_DIR' && "
    if [[ -d "$PYTHON_DIR/venv" ]]; then
      python_cmd+="source venv/bin/activate && "
    fi
    python_cmd+="PYTHONPATH='$PYTHON_DIR/src':${PYTHONPATH:-} python -m uvicorn main:app --app-dir src --host 0.0.0.0 --port '$PYTHON_AI_PORT' --reload"
    start_process "python-ai" "$python_cmd"
    ((SERVICES_STARTED++))
  else
    echo "Python-Backend-Verzeichnis $PYTHON_DIR nicht gefunden." >&2
  fi
fi

if [[ "$SKIP_RUST" == false ]]; then
  if command -v cargo >/dev/null 2>&1; then
    if [[ -d "$RUST_DIR" ]]; then
      start_process "rust-honeypots" "cd '$RUST_DIR' && RUST_LOG=${RUST_LOG:-info} cargo run"
      ((SERVICES_STARTED++))
    else
      echo "Rust-Honeypot-Verzeichnis $RUST_DIR nicht gefunden." >&2
    fi
  else
    echo "Cargo (Rust) wurde nicht gefunden. Installiere Rust, um den Honeypot zu starten." >&2
  fi
fi

if [[ "$SKIP_FRONTEND" == false ]]; then
  if command -v npm >/dev/null 2>&1; then
    if [[ -d "$FRONTEND_DIR" ]]; then
      frontend_cmd="cd '$FRONTEND_DIR' && npm run dev -- --hostname 0.0.0.0 --port '$NEXT_PORT'"
      start_process "frontend" "$frontend_cmd"
      ((SERVICES_STARTED++))
    else
      echo "Frontend-Verzeichnis $FRONTEND_DIR nicht gefunden." >&2
    fi
  else
    echo "npm wurde nicht gefunden. Bitte installiere Node.js/npm, um das Frontend zu starten." >&2
  fi
fi

if [[ "$SERVICES_STARTED" -eq 0 ]]; then
  echo "Es wurden keine Services gestartet. Überprüfe die Optionen oder installiere die benötigten Abhängigkeiten." >&2
  trap - EXIT SIGINT SIGTERM
  exit 1
fi

echo -e "\nAlle angeforderten Services wurden gestartet."
echo "Python API:       http://127.0.0.1:$PYTHON_AI_PORT"
echo "Rust Honeypot:    http://127.0.0.1:$RUST_HONEYPOT_PORT"
echo "Frontend (Next):  http://127.0.0.1:$NEXT_PORT"
echo "Supabase Studio:  http://127.0.0.1:54323 (Standard, sofern supabase start verwendet)"
echo -e "\nDrücke Strg+C zum Beenden."

# Warte, bis einer der Prozesse endet
set +e
wait -n
status=$?
set -e

echo "Ein Service wurde beendet (Exit-Code $status)."
# cleanup-Handler übernimmt das Stoppen der restlichen Prozesse
exit "$status"
