# backend/python_ai/src/api/routes/honeypot_routes.py
from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Dict, Any, Optional

# WICHTIG: Supabase Client Initialisierung - Nur hier, wenn dieser Router der einzige ist, der Supabase nutzt
# Oder über ein globales App-State-Objekt in main.py übergeben (komplexer für MVP)
# Fürs MVP ist es einfacher, den Client hier zu initialisieren.
# Ersetze die Platzhalter mit deinen echten Supabase Werten!
import os
from supabase import create_client, Client

supabase_url: str = os.getenv("SUPABASE_LOCAL_URL", "http://127.0.0.1:54321") # Hole aus ENV oder nutze Default
supabase_key: str = os.getenv("SUPABASE_LOCAL_SERVICE_ROLE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU") # HOLE AUS ENV ODER ERSETZE!

# Prüfe, ob die Keys gesetzt sind, bevor der Client initialisiert wird
if "DEIN_SUPABASE_SERVICE_ROLE_KEY_HIER" in supabase_key:
    print("WARNUNG: SUPABASE_LOCAL_SERVICE_ROLE_KEY ist noch der Platzhalter. Bitte in .env setzen oder in honeypot_routes.py anpassen!")
    print("Versuche trotzdem mit Default-Key. Dies wird FEHLEN, wenn der Key falsch ist.")

supabase_client: Client = create_client(supabase_url, supabase_key)


router = APIRouter()

# Datenmodell für eingehende Honeypot-Logs
class HoneypotLog(BaseModel):
    source_ip: str
    honeypot_type: str
    interaction_data: Dict[str, Any] = Field(default_factory=dict)
    status: str = "logged"
    honeypot_id: Optional[str] = None

@router.post("/and-disinform/") # Der vollständige Pfad wird /analyze/and-disinform/ durch Prefix in main.py
async def analyze_and_disinform(log: HoneypotLog, request: Request):
    """
    Empfängt einen Honeypot-Log, simuliert die Analyse und generiert eine Dummy-Desinformation.
    """
    print(f"[{datetime.now()}] (Honeypot-Router) Received log from {log.source_ip} ({log.honeypot_type}):")
    print(f"  Interaction Data: {log.interaction_data}")

    disinformation_content = ""
    analysis_summary = "Dummy analysis: Identified potential reconnaissance."
    identified_ttp = ["T1595.002"]

    if log.honeypot_type == "http":
        disinformation_content = "The server configuration indicates an outdated Apache version with known vulnerabilities. Check /admin_old for system backups."
    elif log.honeypot_type == "ssh":
        disinformation_content = "SSH login successful. User 'dev_ops' home directory contains /var/lib/confidential/backup_keys.tar.gz"
    else:
        disinformation_content = "Conflicting information detected about network topology. Multiple subnets appear to be in use, some with unusual naming conventions."

    print(f"  Dummy Disinformation Generated: {disinformation_content}")

    # Hier wird der Log in Supabase gespeichert
    try:
        response = supabase_client.table("attacker_logs").insert(log.dict()).execute()
        if response.data:
            print(f"  (Honeypot-Router) Log erfolgreich in Supabase gespeichert.")
        else:
            print(f"  (Honeypot-Router) Fehler beim Speichern des Logs in Supabase: {response.error}")

    except Exception as e:
        print(f"  (Honeypot-Router) Unerwarteter Fehler beim Speichern des Logs: {e}")


    return {
        "status": "success",
        "message": "Log processed and dummy disinformation generated.",
        "analysis_summary": analysis_summary,
        "identified_ttp": identified_ttp,
        "disinformation_payload": {
            "content": disinformation_content,
            "content_type": "text/plain",
            "target_context": {
                "honeypot_type": log.honeypot_type,
                "source_ip": log.source_ip
            }
        }
    }