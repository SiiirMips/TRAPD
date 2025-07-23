# backend/python_ai/src/api/routes/honeypot_routes.py
from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field # Pydantic v1.x importiert BaseModel direkt
from datetime import datetime
from typing import Dict, Any, Optional
import os
from supabase import create_client, Client

# Supabase Client Initialisierung
supabase_url: str = os.getenv("SUPABASE_LOCAL_URL")
supabase_key: str = os.getenv("SUPABASE_LOCAL_SERVICE_ROLE_KEY")

if not supabase_url or not supabase_key:
    print("FEHLER: Supabase URL oder Key nicht über Umgebungsvariablen geladen. Bitte .env prüfen!")


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

    print(f"  Dummy Desinformation Generated: {disinformation_content}")

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