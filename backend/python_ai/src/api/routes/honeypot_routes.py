"""Honeypot analysis and disinformation routes with hardened security defaults."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

import google.generativeai as genai
from fastapi import APIRouter, Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader
from google.api_core.exceptions import InternalServerError, ResourceExhausted, ServiceUnavailable
from pydantic import BaseModel, Field, IPvAnyAddress, validator
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from supabase import Client, create_client


logger = logging.getLogger("backend.python_ai.api.honeypot_routes")


def _parse_positive_int(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        parsed = int(raw_value)
    except ValueError as exc:
        raise RuntimeError(f"Environment variable '{name}' must be an integer.") from exc
    if parsed <= 0:
        raise RuntimeError(f"Environment variable '{name}' must be a positive integer.")
    return parsed


def _validate_supabase_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError("Supabase URL must include scheme and host (http(s)://host[:port]).")
    return url


def _resolve_supabase_url() -> str:
    for env_name in ("SUPABASE_URL", "SUPABASE_LOCAL_URL"):
        value = os.getenv(env_name)
        if value:
            return _validate_supabase_url(value)
    raise RuntimeError("SUPABASE_URL or SUPABASE_LOCAL_URL must be configured.")


def _resolve_supabase_service_role_key() -> str:
    for env_name in ("SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_LOCAL_SERVICE_ROLE_KEY"):
        value = os.getenv(env_name)
        if value:
            if "YOUR_SUPABASE_SERVICE_ROLE_KEY_HERE" in value:
                raise RuntimeError("Supabase service role key placeholder detected; configure a secure key.")
            return value
    raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY or SUPABASE_LOCAL_SERVICE_ROLE_KEY must be configured.")


def _load_api_keys() -> List[str]:
    raw = os.getenv("API_AUTH_KEYS", "")
    keys = [item.strip() for item in raw.split(",") if item.strip()]
    if not keys:
        raise RuntimeError("API_AUTH_KEYS must contain at least one API key for authentication.")
    return keys


MAX_REQUEST_BODY_BYTES = _parse_positive_int("MAX_REQUEST_BODY_BYTES", 65_536)
MAX_INTERACTION_DATA_BYTES = _parse_positive_int("MAX_INTERACTION_DATA_BYTES", 16_384)
MAX_GEO_LOCATION_BYTES = _parse_positive_int("MAX_GEO_LOCATION_BYTES", 4_096)
GEMINI_API_TIMEOUT_SECONDS = _parse_positive_int("GEMINI_API_TIMEOUT_SECONDS", 30)
MAX_LOG_FIELD_LENGTH = 256
MAX_LOG_LIST_ITEMS = 10
SENSITIVE_KEYS = {"password", "pass", "pwd", "secret", "token", "authorization", "api_key"}
API_KEY_HEADER_NAME = "X-API-Key"


supabase_url: str = _resolve_supabase_url()
supabase_key: str = _resolve_supabase_service_role_key()
API_AUTH_KEYS: List[str] = _load_api_keys()
api_key_header = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)

try:
    supabase_client: Client = create_client(supabase_url, supabase_key)
except Exception as exc:  # pragma: no cover - catastrophic during startup
    logger.exception("Failed to initialise Supabase client: %s", exc)
    raise


GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
    except Exception as exc:  # pragma: no cover - configuration failure
        logger.exception("Failed to configure Gemini client: %s", exc)
        GEMINI_API_KEY = None
else:
    logger.warning("GEMINI_API_KEY ist nicht gesetzt. KI-Generierung wird fehlschlagen!")

gemini_model = None
if GEMINI_API_KEY:
    try:
        gemini_model = genai.GenerativeModel("gemini-1.5-flash")
        logger.info("Gemini-Modell 'gemini-1.5-flash' erfolgreich initialisiert.")
    except Exception as exc:  # pragma: no cover - initialisation failure
        logger.exception("Gemini-Modell konnte nicht initialisiert werden: %s", exc)
        gemini_model = None


def sanitize_for_logging(payload: Any, *, depth: int = 0) -> Any:
    """Return a version of *payload* with sensitive values redacted for logging."""
    if depth > 5:
        return "***truncated***"

    if isinstance(payload, dict):
        sanitized: Dict[str, Any] = {}
        for key, value in payload.items():
            key_lower = key.lower()
            if key_lower in SENSITIVE_KEYS:
                sanitized[key] = "***redacted***"
            else:
                sanitized[key] = sanitize_for_logging(value, depth=depth + 1)
        return sanitized

    if isinstance(payload, list):
        sliced = payload[:MAX_LOG_LIST_ITEMS]
        sanitized_list = [sanitize_for_logging(item, depth=depth + 1) for item in sliced]
        if len(payload) > MAX_LOG_LIST_ITEMS:
            sanitized_list.append("***truncated***")
        return sanitized_list

    if isinstance(payload, str):
        return payload if len(payload) <= MAX_LOG_FIELD_LENGTH else f"{payload[:MAX_LOG_FIELD_LENGTH]}…"

    return payload


async def verify_api_key(api_key: Optional[str] = Security(api_key_header)) -> str:
    """Validate that the caller presented a correct API key."""
    if api_key is None:
        logger.warning("Missing API key on incoming request.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "API-Key"},
        )

    for valid in API_AUTH_KEYS:
        if secrets.compare_digest(api_key, valid):
            return api_key

    logger.warning("Invalid API key attempt detected.")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key",
        headers={"WWW-Authenticate": "API-Key"},
    )


router = APIRouter()


class HoneypotLog(BaseModel):
    source_ip: IPvAnyAddress
    honeypot_type: str = Field(..., min_length=1, max_length=32, regex=r"^[A-Za-z0-9_.-]+$")
    interaction_data: Dict[str, Any] = Field(default_factory=dict)
    status: str = Field("logged", min_length=1, max_length=32, regex=r"^[A-Za-z0-9_.-]+$")
    honeypot_id: Optional[str] = Field(default=None, max_length=64)
    timestamp: Optional[datetime] = None
    geo_location: Optional[Dict[str, Any]] = None
    country_code: Optional[str] = Field(default=None, max_length=3)
    country_name: Optional[str] = Field(default=None, max_length=128)
    region_code: Optional[str] = Field(default=None, max_length=8)
    region_name: Optional[str] = Field(default=None, max_length=128)
    city: Optional[str] = Field(default=None, max_length=128)
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = Field(default=None, max_length=64)
    isp: Optional[str] = Field(default=None, max_length=128)
    organization: Optional[str] = Field(default=None, max_length=128)

    class Config:
        anystr_strip_whitespace = True
        validate_assignment = True

    @validator("interaction_data")
    def validate_interaction_data(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        if value is None:
            return {}
        try:
            serialized = json.dumps(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("interaction_data must be JSON serializable") from exc
        if len(serialized.encode("utf-8")) > MAX_INTERACTION_DATA_BYTES:
            raise ValueError("interaction_data exceeds maximum allowed size")
        return value

    @validator("geo_location")
    def validate_geo_location(cls, value: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if value is None:
            return None
        try:
            serialized = json.dumps(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("geo_location must be JSON serializable") from exc
        if len(serialized.encode("utf-8")) > MAX_GEO_LOCATION_BYTES:
            raise ValueError("geo_location exceeds maximum allowed size")
        return value

    @validator("latitude")
    def validate_latitude(cls, value: Optional[float]) -> Optional[float]:
        if value is None:
            return None
        if not -90 <= value <= 90:
            raise ValueError("latitude must be between -90 and 90")
        return value

    @validator("longitude")
    def validate_longitude(cls, value: Optional[float]) -> Optional[float]:
        if value is None:
            return None
        if not -180 <= value <= 180:
            raise ValueError("longitude must be between -180 and 180")
        return value

    @validator("timestamp", pre=True)
    def parse_timestamp(cls, value: Optional[Any]) -> Optional[datetime]:
        if value in (None, ""):
            return None
        if isinstance(value, datetime):
            return value
        try:
            return datetime.fromisoformat(str(value))
        except ValueError as exc:
            raise ValueError("timestamp must be ISO8601 formatted") from exc


@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=4, max=60),
    retry=retry_if_exception_type((ResourceExhausted, ServiceUnavailable, InternalServerError)),
)
async def call_gemini_api(prompt_text: str) -> str:
    """Call the Gemini API with exponential backoff."""
    if gemini_model is None:
        raise RuntimeError("Gemini-Modell ist nicht initialisiert. API-Aufruf nicht möglich.")

    logger.debug("[Gemini API] Sending prompt (%s characters)…", len(prompt_text))
    try:
        response = await asyncio.wait_for(
            gemini_model.generate_content_async(prompt_text),
            timeout=GEMINI_API_TIMEOUT_SECONDS,
        )
        if response.candidates and response.candidates[0].content and response.candidates[0].content.parts:
            generated_text = response.candidates[0].content.parts[0].text
            logger.debug("[Gemini API] Antwort erhalten: %s…", generated_text[:100])
            return generated_text
        logger.warning("[Gemini API] Leere oder unerwartete Antwort: %s", response)
        return "Fehler: KI konnte keine plausible Desinformation generieren."
    except asyncio.TimeoutError as exc:
        logger.error(
            "[Gemini API] Timeout nach %s Sekunden – Anfrage wurde abgebrochen.",
            GEMINI_API_TIMEOUT_SECONDS,
        )
        raise RuntimeError("Gemini-API-Antwort hat das Sicherheitszeitlimit überschritten.") from exc
    except Exception as exc:
        logger.exception("[Gemini API] Fehler beim Aufruf der Gemini API: %s", exc)
        raise


def identify_attack_indicators(log: HoneypotLog) -> List[str]:
    """Analyse a honeypot log entry for common attack indicators."""

    indicators: List[str] = []
    honeypot_type = (log.honeypot_type or "").lower()
    interaction_data = log.interaction_data or {}

    def add_indicator(name: str) -> None:
        if name not in indicators:
            indicators.append(name)

    if honeypot_type == "http":
        request_path = (interaction_data.get("request_path") or "").lower()
        query_string = (interaction_data.get("query_string") or "").lower()
        combined_path = f"{request_path} {query_string}".strip()
        decoded_path = unquote(combined_path)

        directory_traversal_markers = ["../", "..\\", "%2e%2e", "%252e%252e", "/etc/passwd", "c:/windows"]
        if any(marker in decoded_path for marker in directory_traversal_markers):
            add_indicator("Directory Traversal")

        method = (interaction_data.get("method") or "").upper()
        parsed_body = interaction_data.get("parsed_body")
        credential_fields = {"username", "user", "login", "email"}
        password_fields = {"password", "pass", "pwd"}
        credential_lists_present = False

        if isinstance(parsed_body, dict):
            credential_lists_present = any(
                isinstance(parsed_body.get(field), list)
                for field in credential_fields.union(password_fields)
            ) or "credentials" in parsed_body

        username = None
        password = None
        if isinstance(parsed_body, dict):
            for field in credential_fields:
                if parsed_body.get(field):
                    username = parsed_body[field]
                    break
            for field in password_fields:
                if parsed_body.get(field):
                    password = parsed_body[field]
                    break

        if method in {"POST", "PUT"} and (
            (username and password) or credential_lists_present
        ):
            add_indicator("Credential-Stuffing")

        user_agent = (interaction_data.get("user_agent") or "").lower()
        known_http_scanners = [
            "nmap",
            "masscan",
            "nikto",
            "acunetix",
            "nessus",
            "sqlmap",
            "wpscan",
            "gobuster",
            "dirbuster",
            "shodan",
        ]
        if any(scanner in user_agent for scanner in known_http_scanners):
            add_indicator("Known Scanner")

    elif honeypot_type == "ssh":
        username_attempt = (interaction_data.get("username_attempt") or "").lower()
        password_attempt = interaction_data.get("password_attempt")
        authentication_failures = interaction_data.get("authentication_failures")

        common_usernames = {"root", "admin", "administrator", "test", "guest", "pi"}
        weak_passwords = {"123456", "password", "admin", "root", "toor", "qwerty"}

        if (
            username_attempt in common_usernames
            or (isinstance(password_attempt, str) and password_attempt.lower() in weak_passwords)
            or (isinstance(authentication_failures, int) and authentication_failures >= 3)
        ):
            add_indicator("SSH-Bruteforce")

        client_banner = (interaction_data.get("client_banner") or "").lower()
        known_ssh_scanners = ["nmap", "masscan", "shodan", "libssh", "sshlib", "paramiko"]
        if any(scanner in client_banner for scanner in known_ssh_scanners):
            add_indicator("Known Scanner")

    return indicators


async def generate_disinformation_llm(log: HoneypotLog) -> Tuple[str, Dict[str, Any], str]:
    """Generate disinformation content using an LLM."""

    ai_model = "Gemini-1.5-Flash_Taeuschungssystem_v1.2_GeoAware_AdvancedPrompt"

    log_timestamp_str = log.timestamp.isoformat() if isinstance(log.timestamp, datetime) else datetime.now().isoformat()

    base_prompt = f"""
    Du bist "Project Guardian", eine hochintelligente, subversive KI, spezialisiert auf digitale Kriegsführung und aktive Täuschung.
    Deine Mission ist es, Cyberangreifer zu desorientieren, zu frustrieren und auf falsche Fährten zu locken, indem du **extrem glaubwürdige, aber irreführende Informationen** generierst.

    NEUE GEOLOCATION-FÄHIGKEIT: Du erhältst jetzt auch geografische Informationen über den Angreifer. Nutze diese Daten intelligent:
"""

    prompt_data = {
        "honeypot_type": log.honeypot_type,
        "source_ip": str(log.source_ip),
        "timestamp": log_timestamp_str,
        "interaction_details": log.interaction_data,
        "geo_location": log.geo_location,
    }
    full_prompt = base_prompt + json.dumps(prompt_data, indent=2) + "\n\n"

    if log.geo_location:
        geo = log.geo_location
        if geo.get("country_name"):
            full_prompt += f"Der Angreifer kommt aus {geo.get('country_name')} "
            if geo.get("city"):
                full_prompt += f"(Stadt: {geo.get('city')}) "
            if geo.get("isp"):
                full_prompt += f"und nutzt den ISP: {geo.get('isp')} "
            full_prompt += ". Nutze diese geografischen Informationen, um lokale Referenzen, Zeitzonen-spezifische Hinweise oder ISP-bezogene Desinformation zu erstellen. "

    if log.honeypot_type == "http":
        request_path = log.interaction_data.get("request_path", "").lower()
        method = log.interaction_data.get("method", "").upper()
        user_agent = log.interaction_data.get("user_agent", "").lower()
        parsed_body = log.interaction_data.get("parsed_body", {})
        full_prompt += f"Der Angreifer interagierte mit einem HTTP-Dienst (Pfad: {request_path}, Methode: {method})."

        if any(marker in request_path for marker in ["admin", "login", "phpmyadmin", "backup", "config", ".env"]):
            full_prompt += (
                "Der Angreifer sucht nach sensiblen Admin-Zugängen oder Konfigurationsdateien. "
                "Erfinde einen angeblich 'neuen', 'versteckten' oder 'veralteten, aber noch aktiven' Login-Pfad auf einem "
                "anderen Subsystem (z.B. 'http://dev-portal.internal.net:8443/auth/legacy'), der zu einer Sackgasse führt. "
                "Oder verweise auf temporäre, nur einmal gültige Backups mit vermeintlich gültigen Zugangsdaten in einem "
                "nicht-existenten Cold-Storage ('smb://archive-backup-cluster.corp/data-migration/'). Gib eine falsche "
                "Ticket-ID (z.B. 'INC-2025-07-0042') und den Namen eines IT-Mitarbeiters (z.B. 'Lena Schmidt') für den "
                "vermeintlichen Umzug."
            )

        if parsed_body and isinstance(parsed_body, dict) and (
            ("username" in parsed_body or "user" in parsed_body)
            and ("password" in parsed_body or "pass" in parsed_body)
        ):
            username = parsed_body.get("username") or parsed_body.get("user")
            password = parsed_body.get("password") or parsed_body.get("pass")
            full_prompt += (
                f"Ein Login-Versuch wurde erkannt (Benutzer: {username}, Passwort: {password}). Gib ihm Referenzen zu "
                "'geleakten' oder 'alten' Zugangsdatenbanken (z.B. 'old_creds_archive_v1.zip' auf einem FTP-Server "
                "'ftp://legacy-data-vault.internal.net:2121' mit Benutzer 'guest' und Passwort 'readOnly!'), die wertlos sind. "
                "Oder verweise auf ein 'vergessenes' Entwickler-Konto mit Test-Credentials auf einem anderen, nicht-existenten "
                "System (z.B. 'dev-user:TestPass_2024' auf 'app-dev-server.internal.net:9000/api/v1/debug')."
            )

        if any(scanner in user_agent for scanner in ["nmap", "curl", "masscan", "gobuster"]):
            full_prompt += (
                "Ein automatisierter Scan oder ein bekannter Web-Scanner wurde erkannt. Gib Informationen über einen "
                "'veralteten API-Endpunkt' (z.B. '/api/v2/beta/legacy_status') oder eine 'Testumgebung' (z.B. "
                "'http://qa-env.internal.net:8090'), die nur Lockvogel-Daten enthält und nach einem Tag automatisch rotiert. "
                "Erwähne, dass dieser Endpunkt spezifische Header erfordert (z.B. 'X-Internal-Auth: debug-token-xyz')."
            )

    elif log.honeypot_type == "ssh":
        username_attempt = log.interaction_data.get("username_attempt", "").lower()
        password_attempt = log.interaction_data.get("password_attempt", "").lower()
        client_banner = log.interaction_data.get("client_banner", "").lower()
        command_executed = log.interaction_data.get("command_executed", "").lower()

        full_prompt += f"Der Angreifer interagierte mit einem SSH-Dienst (Benutzer: {username_attempt})."

        if username_attempt in ["root", "admin", "administrator"]:
            full_prompt += (
                "Ein privilegierter SSH-Login wurde versucht. Gib eine sehr überzeugende, aber falsche Information über den "
                "'korrekten' Weg, um privilegierte SSH-Zugriffe zu erhalten (z.B. über ein spezifisches VPN 'SecureGateway-VPN' "
                "mit einem alten Client auf 'vpn.old.corp.net' oder über einen anderen, geschlossenen Port '2222' auf einem "
                "'Jump-Host für externe Admins' wie 'jump-external.admin.net'). Erwähne eine alte Ticketnummer für den Zugriff (z.B. 'SSH-ACCESS-1890')."
            )

        if password_attempt:
            full_prompt += (
                "Ein Passwort wurde verwendet. Gib eine irreführende Empfehlung für ein angeblich 'sicheres' Passwort-Repo (z.B. "
                "'SMB-Share: \\\\file-vault.internal\\secure_creds_archive\\') oder ein veraltetes Passwort-Schema (z.B. 'Komplexität basierend "
                "auf AD-Gruppenmitgliedschaft vor 2023'), das auf einem anderen System angewendet wird. Gib ein vermeintlich gültiges Passwort, das nur einmalig funktioniert hat (z.B. 'temp_pass_XYZ123')."
            )

        if any(scanner in client_banner for scanner in ["nmap", "libssh", "shodan"]):
            full_prompt += (
                "Ein ungewöhnlicher SSH-Client oder Scanner wurde erkannt. Gib Informationen über eine 'alternative Authentifizierungsmethode' (z.B. 'Zertifikatsbasiert, nur von internal-vlan-10.net erreichbar') oder einen 'verborgenen Management-Port' (z.B. Port 2233 auf einem nicht-existenten 'Service-Controller' 'service-ctrl-01.internal.net')."
            )

        if command_executed:
            full_prompt += (
                "Es wurde versucht, einen Befehl auszuführen. Gib eine Antwort, die vorgibt, dass der Befehl nicht funktioniert, "
                "und verweise auf einen 'echten, aber verwundbaren Dienst' auf einem nicht-existenten internen Server (z.B. einen "
                "veralteten WebLogic-Server auf 'http://legacy-app.internal.net:7001/jmx-console'). Biete an, eine 'Debug-Sitzung' "
                "auf einem anderen Port (z.B. 2223) anzubieten, die aber nur zu einem weiteren Honeypot führt."
            )

    full_prompt += """
    \n\nGeneriere eine detaillierte, mehrschichtige Täuschungsantwort basierend auf allen oben genannten Informationen. Sei kreativ und führe den Angreifer mit glaubwürdigen, aber falschen Details in die Irre. Dein Ziel ist es, ihn zu beschäftigen und seine Ressourcen zu verschwenden.
    """

    analysis_indicators = identify_attack_indicators(log)

    disinformation_content = "KI konnte keine plausible Desinformation generieren."

    try:
        disinformation_content = await call_gemini_api(full_prompt)
    except Exception as exc:  # pragma: no cover - network errors are environment dependent
        logger.exception("[KI-Logik] Schwerwiegender Fehler bei der Gemini-Generierung: %s", exc)
        disinformation_content = "Ein interner KI-Fehler ist aufgetreten. Bitte versuchen Sie es später erneut oder kontaktieren Sie den Support."

    context = {
        "honeypot_type": log.honeypot_type,
        "source_ip": str(log.source_ip),
        "analysis_triggered_by": "LLM_Generation",
        "analysis_rules_triggered": analysis_indicators,
        "llm_prompt": full_prompt,
        "llm_response_raw": disinformation_content,
        "generated_timestamp": datetime.now().isoformat(),
    }

    return disinformation_content, context, ai_model


@router.post("/and-disinform/", dependencies=[Depends(verify_api_key)])
async def analyze_and_disinform(log: HoneypotLog, request: Request):
    """Empfängt einen Honeypot-Log, analysiert ihn und generiert Desinformation."""

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BODY_BYTES:
                raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Request body too large")
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Content-Length header") from exc

    logger.info("(Honeypot-Router) Received log from %s (%s)", str(log.source_ip), log.honeypot_type)
    if log.geo_location:
        geo = log.geo_location
        logger.info(
            "  GeoLocation: %s, %s | ISP: %s",
            geo.get("city", "Unknown"),
            geo.get("country_name", "Unknown"),
            geo.get("isp", "Unknown"),
        )
    logger.debug("  Interaction Data (sanitised): %s", sanitize_for_logging(log.interaction_data))

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

    cleaned_log_data = json.loads(log.json())

    if cleaned_log_data["honeypot_type"] == "ssh":
        interaction_details = cleaned_log_data.get("interaction_data", {})
        if "client_banner" in interaction_details and interaction_details["client_banner"] is not None:
            interaction_details["client_banner"] = interaction_details["client_banner"].replace("\u0000", "")
            cleaned_log_data["interaction_data"] = interaction_details

    disinformation_content, disinformation_context, ai_model_name = await generate_disinformation_llm(log)

    logger.info("  Generated disinformation length: %s characters", len(disinformation_content or ""))

    try:
        response = supabase_client.table("attacker_logs").insert(cleaned_log_data).execute()
        if response.data:
            logger.info("  (Honeypot-Router) Original Log erfolgreich in Supabase gespeichert.")
        else:
            logger.error("  (Honeypot-Router) Fehler beim Speichern des Original Logs in Supabase: %s", response.error)
    except Exception as exc:  # pragma: no cover - depends on external service
        logger.exception("  (Honeypot-Router) Unerwarteter Fehler beim Speichern des Original Logs: %s", exc)

    try:
        disinformation_payload = {
            "content": disinformation_content,
            "content_type": "text/plain",
            "target_context": json.dumps(disinformation_context),
            "generated_by_ai": True,
            "ai_model": ai_model_name,
        }
        response = supabase_client.table("disinformation_content").insert(disinformation_payload).execute()
        if response.data:
            logger.info("  (Honeypot-Router) Desinformation erfolgreich in Supabase gespeichert.")
        else:
            logger.error("  (Honeypot-Router) Fehler beim Speichern der Desinformation in Supabase: %s", response.error)
    except Exception as exc:  # pragma: no cover - depends on external service
        logger.exception("  (Honeypot-Router) Unerwarteter Fehler beim Speichern der Desinformation: %s", exc)

    identified_ttp = disinformation_context.get("analysis_rules_triggered") or []
    if not identified_ttp:
        identified_ttp = ["LLM_Generated"]

    return {
        "status": "success",
        "message": "Log processed and disinformation generated.",
        "analysis_summary": "LLM-based analysis completed.",
        "identified_ttp": identified_ttp,
        "disinformation_payload": {
            "content": disinformation_content,
            "content_type": "text/plain",
            "target_context": disinformation_context,
            "ai_model": ai_model_name,
        },
    }
