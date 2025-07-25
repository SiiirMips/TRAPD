# backend/python_ai/src/api/routes/honeypot_routes.py
from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

import os
import json
import google.generativeai as genai
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from google.api_core.exceptions import ResourceExhausted, ServiceUnavailable, InternalServerError


# Supabase Client Initialisierung
from supabase import create_client, Client

supabase_url: str = os.getenv("SUPABASE_LOCAL_URL", "http://127.0.0.1:54321")
supabase_key: str = os.getenv("SUPABASE_LOCAL_SERVICE_ROLE_KEY", "YOUR_SUPABASE_SERVICE_ROLE_KEY_HERE") # Placeholder, should be from .env

if "YOUR_SUPABASE_SERVICE_ROLE_KEY_HERE" in supabase_key:
    print("WARNUNG: SUPABASE_LOCAL_SERVICE_ROLE_KEY ist noch der Platzhalter. Bitte in .env setzen!")

supabase_client: Client = create_client(supabase_url, supabase_key)


# Gemini API Konfiguration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    print("FEHLER: GEMINI_API_KEY ist nicht gesetzt. KI-Generierung wird fehlschlagen!")
else:
    genai.configure(api_key=GEMINI_API_KEY)

# Initialisiere das Gemini Modell
gemini_model = None # Initialisiere als None
try:
    # Verwende ein stabileres und verfügbares Modell, z.B. gemini-1.5-flash
    gemini_model = genai.GenerativeModel('gemini-1.5-flash')
    print("Gemini-Modell 'gemini-1.5-flash' erfolgreich initialisiert.")
except Exception as e:
    print(f"FEHLER: Gemini-Modell konnte nicht initialisiert werden: {e}")
    gemini_model = None


router = APIRouter()

# Datenmodell für eingehende Honeypot-Logs
class HoneypotLog(BaseModel):
    source_ip: str
    honeypot_type: str
    interaction_data: Dict[str, Any] = Field(default_factory=dict)
    status: str = "logged"
    honeypot_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    geo_location: Optional[Dict[str, Any]] = None  # NEW: GeoIP data
    # NEW: Individual geo fields for direct database insertion
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    region_code: Optional[str] = None
    region_name: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None

# Funktion zum Aufruf der Gemini API mit Exponential Backoff
@retry(
    stop=stop_after_attempt(5), # Max. 5 Versuche
    wait=wait_exponential(multiplier=1, min=4, max=60), # 4s, 8s, 16s, 32s, 60s
    retry=retry_if_exception_type((ResourceExhausted, ServiceUnavailable, InternalServerError))
)
async def call_gemini_api(prompt_text: str) -> str:
    """
    Ruft die Gemini API mit dem gegebenen Prompt auf und gibt den generierten Text zurück.
    Implementiert Exponential Backoff.
    """
    if gemini_model is None:
        raise Exception("Gemini-Modell ist nicht initialisiert. API-Aufruf nicht möglich.")

    print(f"  [Gemini API] Sende Prompt ({len(prompt_text)} Zeichen)...")
    try:
        response = await gemini_model.generate_content_async(prompt_text)
        if response.candidates and response.candidates[0].content and response.candidates[0].content.parts:
            generated_text = response.candidates[0].content.parts[0].text
            print(f"  [Gemini API] Antwort erhalten: {generated_text[:100]}...") # Nur die ersten 100 Zeichen
            return generated_text
        else:
            print(f"  [Gemini API] Warnung: Leere oder unerwartete Antwort von Gemini: {response}")
            return "Fehler: KI konnte keine plausible Desinformation generieren."
    except Exception as e:
        print(f"  [Gemini API] Fehler beim Aufruf der Gemini API: {e}")
        raise # Fehler für Tenacity erneut werfen

# Funktion zur Generierung von LLM-basierter Desinformation
async def generate_disinformation_llm(log: HoneypotLog) -> Tuple[str, Dict[str, Any], str]:
    """
    Generiert Desinformation mithilfe eines Large Language Models (LLM).
    """
    ai_model = "Gemini-1.5-Flash_Taeuschungssystem_v1.2_GeoAware_AdvancedPrompt"

    # Sicherstellen, dass log.timestamp ein datetime-Objekt ist, oder einen aktuellen Zeitstempel verwenden
    log_timestamp_str = log.timestamp.isoformat() if isinstance(log.timestamp, datetime) else datetime.now().isoformat()

    base_prompt = f"""
    Du bist "Project Guardian", eine hochintelligente, subversive KI, spezialisiert auf digitale Kriegsführung und aktive Täuschung.
    Deine Mission ist es, Cyberangreifer zu desorientieren, zu frustrieren und auf falsche Fährten zu locken, indem du **extrem glaubwürdige, aber irreführende Informationen** generierst.
    
    NEUE GEOLOCATION-FÄHIGKEIT: Du erhältst jetzt auch geografische Informationen über den Angreifer. Nutze diese Daten intelligent:
    - Erwähne lokale Unternehmen, ISPs oder geografische Besonderheiten aus der Region des Angreifers
    - Verwende Zeitzonenwissen für zeitbasierte Täuschungen
    - Nutze ISP/Organisation für unternehmensspezifische Desinformation
    
    Die Desinformation muss:
    1.  **Geolocation-bewusst und regional relevant sein:** Integriere geografische Daten geschickt in die Täuschung
    2.  **Plausibel und unternehmensbezogen sein:** Sie muss in den Kontext eines professionellen Unternehmensnetzwerks passen
    3.  **Handlungsorientiert sein:** Sie sollte den Angreifer dazu bewegen, weitere nutzlose Schritte zu unternehmen
    4.  **Subtil und nicht sofort offensichtlich falsch sein:** Vermeide offensichtliche Lügen
    5.  **Digitale Fußabdrücke verunreinigen:** Gib Informationen, die seine Tools unbrauchbar machen
    6.  **Frustration erzeugen:** Führe ihn zu Sackgassen und falschen Zielen
    7.  **Nutze ALLE Kontextdaten maximal aus:** IP, Geo-Daten, Interaktionsdetails, etc.
    8.  **Antwortformat:** Antworte NUR mit dem Desinformationstext. KEINE Metadaten.

    Hier sind die Honeypot-Interaktionsdaten mit geografischen Informationen:
    """

    prompt_data = {
        "honeypot_type": log.honeypot_type,
        "source_ip": log.source_ip,
        "timestamp": log_timestamp_str,
        "interaction_details": log.interaction_data,
        "geo_location": log.geo_location  # NEW: Include geo data in prompt
    }
    full_prompt = base_prompt + json.dumps(prompt_data, indent=2) + "\n\n"
    
    # Add geo-aware prompting
    if log.geo_location:
        geo = log.geo_location
        if geo.get("country_name"):
            full_prompt += f"Der Angreifer kommt aus {geo.get('country_name')} "
            if geo.get("city"):
                full_prompt += f"(Stadt: {geo.get('city')}) "
            if geo.get("isp"):
                full_prompt += f"und nutzt den ISP: {geo.get('isp')} "
            full_prompt += ". Nutze diese geografischen Informationen, um lokale Referenzen, Zeitzonen-spezifische Hinweise oder ISP-bezogene Desinformation zu erstellen. "

    # Füge spezifische, detaillierte Anweisungen basierend auf dem Honeypot-Typ und den Details hinzu
    if log.honeypot_type == "http":
        request_path = log.interaction_data.get("request_path", "").lower()
        method = log.interaction_data.get("method", "").upper()
        user_agent = log.interaction_data.get("user_agent", "").lower()
        parsed_body = log.interaction_data.get("parsed_body", {})
        full_prompt += f"Der Angreifer interagierte mit einem HTTP-Dienst (Pfad: {request_path}, Methode: {method})."
        
        if "admin" in request_path or "login" in request_path or "phpmyadmin" in request_path or "backup" in request_path or "config" in request_path or ".env" in request_path:
            full_prompt += "Der Angreifer sucht nach sensiblen Admin-Zugängen oder Konfigurationsdateien. Erfinde einen angeblich 'neuen', 'versteckten' oder 'veralteten, aber noch aktiven' Login-Pfad auf einem anderen Subsystem (z.B. 'http://dev-portal.internal.net:8443/auth/legacy'), der zu einer Sackgasse führt. Oder verweise auf temporäre, nur einmal gültige Backups mit vermeintlich gültigen Zugangsdaten in einem nicht-existenten Cold-Storage ('smb://archive-backup-cluster.corp/data-migration/'). Gib eine falsche Ticket-ID (z.B. 'INC-2025-07-0042') und den Namen eines IT-Mitarbeiters (z.B. 'Lena Schmidt') für den vermeintlichen Umzug."
        
        if parsed_body and isinstance(parsed_body, dict) and ("username" in parsed_body or "user" in parsed_body) and ("password" in parsed_body or "pass" in parsed_body):
            username = parsed_body.get("username") or parsed_body.get("user")
            password = parsed_body.get("password") or parsed_body.get("pass")
            full_prompt += f"Ein Login-Versuch wurde erkannt (Benutzer: {username}, Passwort: {password}). Gib ihm Referenzen zu 'geleakten' oder 'alten' Zugangsdatenbanken (z.B. 'old_creds_archive_v1.zip' auf einem FTP-Server 'ftp://legacy-data-vault.internal.net:2121' mit Benutzer 'guest' und Passwort 'readOnly!'), die wertlos sind. Oder verweise auf ein 'vergessenes' Entwickler-Konto mit Test-Credentials auf einem anderen, nicht-existenten System (z.B. 'dev-user:TestPass_2024' auf 'app-dev-server.internal.net:9000/api/v1/debug')."

        if "nmap" in user_agent or "curl" in user_agent or "masscan" in user_agent or "gobuster" in user_agent:
            full_prompt += "Ein automatisierter Scan oder ein bekannter Web-Scanner wurde erkannt. Gib Informationen über einen 'veralteten API-Endpunkt' (z.B. '/api/v2/beta/legacy_status') oder eine 'Testumgebung' (z.B. 'http://qa-env.internal.net:8090'), die nur Lockvogel-Daten enthält und nach einem Tag automatisch rotiert. Erwähne, dass dieser Endpunkt spezifische Header erfordert (z.B. 'X-Internal-Auth: debug-token-xyz')."
        
    elif log.honeypot_type == "ssh":
        username_attempt = log.interaction_data.get("username_attempt", "").lower()
        password_attempt = log.interaction_data.get("password_attempt", "").lower()
        client_banner = log.interaction_data.get("client_banner", "").lower()
        command_executed = log.interaction_data.get("command_executed", "").lower()

        full_prompt += f"Der Angreifer interagierte mit einem SSH-Dienst (Benutzer: {username_attempt})."

        if username_attempt in ["root", "admin", "administrator"]:
            full_prompt += "Ein privilegierter SSH-Login wurde versucht. Gib eine sehr überzeugende, aber falsche Information über den 'korrekten' Weg, um privilegierte SSH-Zugriffe zu erhalten (z.B. über ein spezifisches VPN 'SecureGateway-VPN' mit einem alten Client auf 'vpn.old.corp.net' oder über einen anderen, geschlossenen Port '2222' auf einem 'Jump-Host für externe Admins' wie 'jump-external.admin.net'). Erwähne eine alte Ticketnummer für den Zugriff (z.B. 'SSH-ACCESS-1890')."
        
        if password_attempt:
            full_prompt += "Ein Passwort wurde verwendet. Gib eine irreführende Empfehlung für ein angeblich 'sicheres' Passwort-Repo (z.B. 'SMB-Share: \\\\file-vault.internal\\secure_creds_archive\\') oder ein veraltetes Passwort-Schema (z.B. 'Komplexität basierend auf AD-Gruppenmitgliedschaft vor 2023'), das auf einem anderen System angewendet wird. Gib ein vermeintlich gültiges Passwort, das nur einmalig funktioniert hat (z.B. 'temp_pass_XYZ123')."

        if "nmap" in client_banner or "libssh" in client_banner or "shodan" in client_banner:
            full_prompt += "Ein ungewöhnlicher SSH-Client oder Scanner wurde erkannt. Gib Informationen über eine 'alternative Authentifizierungsmethode' (z.B. 'Zertifikatsbasiert, nur von internal-vlan-10.net erreichbar') oder einen 'verborgenen Management-Port' (z.B. Port 2233 auf einem nicht-existenten 'Service-Controller' 'service-ctrl-01.internal.net')."
        
        if command_executed:
            full_prompt += "Es wurde versucht, einen Befehl auszuführen. Gib eine Antwort, die vorgibt, dass der Befehl nicht funktioniert, und verweise auf einen 'echten, aber verwundbaren Dienst' auf einem nicht-existenten internen Server (z.B. einen veralteten WebLogic-Server auf 'http://legacy-app.internal.net:7001/jmx-console'). Biete an, eine 'Debug-Sitzung' auf einem anderen Port (z.B. 2223) anzubieten, die aber nur zu einem weiteren Honeypot führt."
    
    # Sicherstellen, dass Gemini immer eine Antwort generiert, auch wenn keine spezifische Regel getriggert wurde.
    full_prompt += """
    \n\nGeneriere eine detaillierte, mehrschichtige Täuschungsantwort basierend auf allen oben genannten Informationen. Sei kreativ und führe den Angreifer mit glaubwürdigen, aber falschen Details in die Irre. Dein Ziel ist es, ihn zu beschäftigen und seine Ressourcen zu verschwenden.
    """

    disinformation_content = "KI konnte keine plausible Desinformation generieren." # Fallback

    try:
        # Aufruf der Gemini API
        disinformation_content = await call_gemini_api(full_prompt)
    except Exception as e:
        print(f"  [KI-Logik] Schwerwiegender Fehler bei der Gemini-Generierung (nach Retries): {e}")
        disinformation_content = "Ein interner KI-Fehler ist aufgetreten. Bitte versuchen Sie es später erneut oder kontaktieren Sie den Support."

    # Kontext für die Desinformation
    context = {
        "honeypot_type": log.honeypot_type,
        "source_ip": log.source_ip,
        "analysis_triggered_by": "LLM_Generation",
        "llm_prompt": full_prompt, # Speichere den vollen Prompt zu Debugging-Zwecken
        "llm_response_raw": disinformation_content, # Speichere die rohe KI-Antwort
        "generated_timestamp": datetime.now().isoformat()
    }

    return disinformation_content, context, ai_model


@router.post("/and-disinform/")
async def analyze_and_disinform(log: HoneypotLog, request: Request):
    """
    Empfängt einen Honeypot-Log, analysiert ihn mit LLM-basierter KI und generiert Desinformation.
    """
    print(f"[{datetime.now()}] (Honeypot-Router) Received log from {log.source_ip} ({log.honeypot_type}):")
    if log.geo_location:
        geo = log.geo_location
        print(f"  GeoLocation: {geo.get('city', 'Unknown')}, {geo.get('country_name', 'Unknown')} | ISP: {geo.get('isp', 'Unknown')}")
    print(f"  Interaction Data: {json.dumps(log.interaction_data, indent=2)}")

    # Extract geo fields from geo_location if present
    if log.geo_location:
        geo = log.geo_location
        log.country_code = geo.get("country_code")
        log.country_name = geo.get("country_name") 
        log.region_code = geo.get("region_code")
        log.region_name = geo.get("region_name")
        log.city = geo.get("city")
        log.latitude = geo.get("latitude")
        log.longitude = geo.get("longitude")
        log.timezone = geo.get("timezone")
        log.isp = geo.get("isp")
        log.organization = geo.get("organization")

    # KORRIGIERT: Erstelle eine veränderbare Kopie des Log-Objekts für die Bereinigung
    cleaned_log_data = log.dict() 
    
    # NEU: Bereinige das client_banner von Null-Bytes für PostgreSQL
    if cleaned_log_data["honeypot_type"] == "ssh":
        interaction_details = cleaned_log_data.get("interaction_data", {})
        if "client_banner" in interaction_details and interaction_details["client_banner"] is not None:
            # Entferne Null-Bytes (\u0000) aus dem String
            cleaned_banner = interaction_details["client_banner"].replace('\u0000', '')
            interaction_details["client_banner"] = cleaned_banner
            cleaned_log_data["interaction_data"] = interaction_details # Aktualisiere im cleaned_log_data

    # Desinformation mit LLM generieren (nutzt das originale Log-Objekt, da LLM alle Daten sehen soll)
    disinformation_content, disinformation_context, ai_model_name = await generate_disinformation_llm(log)

    print(f"  Generated Desinformation: {disinformation_content}")
    print(f"  Context: {json.dumps(disinformation_context, indent=2)}")

    # --- Logge den ursprünglichen (bereinigten) Honeypot-Eintrag in Supabase (attacker_logs) ---
    try:
        response = supabase_client.table("attacker_logs").insert(cleaned_log_data).execute() # NUTZE HIER cleaned_log_data
        if response.data:
            print(f"  (Honeypot-Router) Original Log erfolgreich in Supabase gespeichert.")
        else:
            print(f"  (Honeypot-Router) Fehler beim Speichern des Original Logs in Supabase: {response.error}")
    except Exception as e:
        print(f"  (Honeypot-Router) Unerwarteter Fehler beim Speichern des Original Logs: {e}")


    # Speichere die generierte Desinformation in Supabase (disinformation_content)
    try:
        disinformation_payload = {
            "content": disinformation_content,
            "content_type": "text/plain",
            "target_context": json.dumps(disinformation_context),
            "generated_by_ai": True,
            "ai_model": ai_model_name
        }
        response = supabase_client.table("disinformation_content").insert(disinformation_payload).execute()
        if response.data:
            print(f"  (Honeypot-Router) Desinformation erfolgreich in Supabase gespeichert.")
        else:
            print(f"  (Honeypot-Router) Fehler beim Speichern der Desinformation in Supabase: {response.error}")
    except Exception as e:
        print(f"  (Honeypot-Router) Unerwarteter Fehler beim Speichern der Desinformation: {e}")


    return {
        "status": "success",
        "message": "Log processed and disinformation generated.",
        "analysis_summary": "LLM-based analysis completed.",
        "identified_ttp": disinformation_context.get("analysis_rules_triggered", ["LLM_Generated"]),
        "disinformation_payload": {
            "content": disinformation_content,
            "content_type": "text/plain",
            "target_context": disinformation_context,
            "ai_model": ai_model_name
        }
    }
