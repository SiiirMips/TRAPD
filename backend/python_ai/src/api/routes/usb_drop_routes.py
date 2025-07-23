# backend/python_ai/src/api/routes/usb_drop_routes.py

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Dict, Any, Optional

# WICHTIG: Supabase Client Initialisierung
import os
from supabase import create_client, Client

# Lade Supabase URL und Key aus Umgebungsvariablen.
# Dies ist die empfohlene Methode für die Produktion.
# Für lokales Testen ohne .env-Datei können die Werte hier direkt eingesetzt werden,
# aber für eine saubere Konfiguration sollten sie in einer .env-Datei im python_ai-Verzeichnis liegen
# und in main.py mit load_dotenv() geladen werden.

# Beispiel für das Laden aus Umgebungsvariablen (bevorzugt):
supabase_url: str = os.getenv("SUPABASE_LOCAL_URL", "http://127.0.0.1:54321")
supabase_key: str = os.getenv("SUPABASE_LOCAL_SERVICE_ROLE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU")

# Initialisiere den Supabase Client
# Wenn die Umgebungsvariablen nicht gesetzt sind und der Default-Key verwendet wird,
# wird dies eine Fehlermeldung ausgeben, wenn der Key ungültig ist.
try:
    supabase_client: Client = create_client(supabase_url, supabase_key)
    print("(USB-Drop-Router) Supabase Client initialisiert.")
except Exception as e:
    print(f"(USB-Drop-Router) FEHLER: Supabase Client Initialisierung fehlgeschlagen: {e}")
    # In einem Produktionssystem würde man hier das Programm beenden oder eine Fallback-Strategie haben.


router = APIRouter()

# Neues Pydantic-Modell für USB-Drop-Daten
# Die Felder dieses Modells sollten den Spalten deiner 'usb_drop_logs' Tabelle entsprechen.
class UsbDropBeacon(BaseModel):
    usb_stick_id: str = Field(..., description="Unique ID of the USB stick")
    hostname: str = Field(..., description="Hostname of the executing machine")
    username: str = Field(..., description="Username of the logged-in user")
    internal_ip: str = Field(..., description="Internal IP address of the machine")
    payload_name: str = Field(..., description="Name of the executed file (e.g., 'Gehaltsliste.xlsx')")
    public_ip: Optional[str] = Field(None, description="Public IP address of the machine, if available")
    os_info: Optional[str] = Field(None, description="Operating System information")
    # Füge hier weitere relevante Felder hinzu, die der Payload sammelt (z.B. antivirus_status, domain_name)


@router.post("/beacon/") # Der vollständige Pfad wird /usb/beacon/ durch Prefix in main.py
async def receive_usb_beacon(beacon: UsbDropBeacon):
    """
    Empfängt eine Beacon-Nachricht von einem USB-Drop-Payload und speichert sie in der usb_drop_logs Tabelle.
    """
    print(f"[{datetime.now()}] (USB-Drop-Router) Received USB Beacon from Stick ID: {beacon.usb_stick_id}, User: {beacon.username}@{beacon.hostname}")
    print(f"  Payload: {beacon.payload_name}, Internal IP: {beacon.internal_ip}")

    # Daten für die Datenbank vorbereiten, um sie dem SQL-Schema anzupassen
    try:
        # Erstelle ein Dictionary, das den Spalten der 'usb_drop_logs' Tabelle entspricht
        data_to_save = {
            "usb_stick_id": beacon.usb_stick_id,
            "source_ip": beacon.internal_ip, # 'internal_ip' aus Beacon wird zu 'source_ip' in DB
            "hostname": beacon.hostname,
            "username": beacon.username,
            "payload_name": beacon.payload_name,
            "details": { # Alle weiteren Details kommen in das JSONB-Feld 'details'
                "public_ip": beacon.public_ip,
                "os_info": beacon.os_info,
                # Füge hier alle weiteren Beacon-Details hinzu, die nicht Top-Level-Spalten sind
            }
        }

        response = supabase_client.table("usb_drop_logs").insert(data_to_save).execute()

        if response.data:
            print(f"  (USB-Drop-Router) USB Beacon erfolgreich in 'usb_drop_logs' gespeichert.")
            return {"status": "success", "message": "USB Beacon received and logged."}
        else:
            # Supabase-Fehlerdetails ausgeben
            error_details = response.error.message if response.error else "Unknown error"
            print(f"  (USB-Drop-Router) Fehler beim Speichern des USB Beacons in Supabase: {error_details}")
            return JSONResponse(status_code=500, content={"message": f"Failed to log USB Beacon: {error_details}"})

    except Exception as e:
        print(f"  (USB-Drop-Router) Unerwarteter Fehler beim Speichern des USB Beacons: {e}")
        return JSONResponse(status_code=500, content={"message": f"Internal server error: {e}"})
