from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Dict, Any, Optional
import uvicorn
import os
from dotenv import load_dotenv

# Lade Umgebungsvariablen (Dies ist wichtig, falls du später echte Keys nutzt,
# auch wenn die .env-Datei selbst nicht versioniert wird, könnte sie lokal existieren)
load_dotenv()

app = FastAPI(
    title="YourProjectName AI Mockup API", # Angepasst an den generischen Namen
    description="Mockup API for processing honeypot data and generating disinformation for YourProjectName.",
    version="0.1.0"
)

# Datenmodell für eingehende Honeypot-Logs
class HoneypotLog(BaseModel):
    source_ip: str
    honeypot_type: str
    interaction_data: Dict[str, Any] = Field(default_factory=dict)
    status: str = "logged"
    honeypot_id: Optional[str] = None # Optional, wenn Rust eine UUID senden würde

@app.get("/")
async def read_root():
    return {"message": "YourProjectName AI Mockup API is running!"} # Angepasst

@app.post("/analyze-and-disinform/")
async def analyze_and_disinform(log: HoneypotLog, request: Request):
    """
    Empfängt einen Honeypot-Log, simuliert die Analyse und generiert eine Dummy-Desinformation.
    """
    print(f"[{datetime.now()}] Received log from {log.source_ip} ({log.honeypot_type}):")
    print(f"  Interaction Data: {log.interaction_data}")

    # --- Hier würde die eigentliche KI-Analyse-Logik stattfinden ---
    # Für das MVP generieren wir einfach eine Dummy-Antwort basierend auf dem Typ des Honeypots.
    disinformation_content = ""
    analysis_summary = "Dummy analysis: Identified potential reconnaissance."
    identified_ttp = ["T1595.002"] # Beispiel TTP: Active Scannning

    if log.honeypot_type == "http":
        disinformation_content = "The server configuration indicates an outdated Apache version with known vulnerabilities. Check /admin_old for system backups."
    elif log.honeypot_type == "ssh": # Wenn wir später SSH implementieren
        disinformation_content = "SSH login successful. User 'dev_ops' home directory contains /var/lib/confidential/backup_keys.tar.gz"
    else:
        disinformation_content = "Conflicting information detected about network topology. Multiple subnets appear to be in use, some with unusual naming conventions."

    print(f"  Dummy Disinformation Generated: {disinformation_content}")

    # --- Hier würden wir die Desinformation und Analyse-Ergebnisse in Supabase speichern ---
    # Fürs MVP geben wir es nur zurück.

    return {
        "status": "success",
        "message": "Log processed and dummy disinformation generated.",
        "analysis_summary": analysis_summary,
        "identified_ttp": identified_ttp,
        "disinformation_payload": {
            "content": disinformation_content,
            "content_type": "text/plain", # Oder spezifischer (e.g., "ssh_banner", "file_content")
            "target_context": {
                "honeypot_type": log.honeypot_type,
                "source_ip": log.source_ip
            }
        }
    }

# Beispiel für eine Fehlerbehandlung (optional, aber gute Praxis)
@app.exception_handler(Exception)
async def validation_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": f"Internal server error: {exc}"},
    )


if __name__ == "__main__":
    # Binde an 0.0.0.0, damit es von außen erreichbar ist (im Homelab-Kontext)
    # Standardport für FastAPI/Uvicorn ist 8000
    uvicorn.run(app, host="0.0.0.0", port=8000)