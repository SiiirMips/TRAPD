import asyncio
import os
import sys
import types
from pathlib import Path

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from starlette.testclient import TestClient

# Stub google modules so the honeypot routes can be imported without optional dependencies.
google_module = types.ModuleType("google")
google_module.__path__ = []  # mark as package
sys.modules["google"] = google_module

os.environ.setdefault("SUPABASE_LOCAL_URL", "http://127.0.0.1:54321")
os.environ.setdefault("SUPABASE_LOCAL_SERVICE_ROLE_KEY", "test-service-role-key")
os.environ.setdefault("API_AUTH_KEYS", "unit-test-key")
os.environ.setdefault("APP_ALLOWED_HOSTS", "127.0.0.1,localhost,testserver")


generativeai_module = types.ModuleType("google.generativeai")

def _configure_stub(**_kwargs):
    return None


class _StubGenerativeModel:
    def __init__(self, *_args, **_kwargs):
        pass

    async def generate_content_async(self, _prompt_text: str):
        class _StubResponse:
            candidates = []

        return _StubResponse()


generativeai_module.configure = _configure_stub
generativeai_module.GenerativeModel = _StubGenerativeModel
sys.modules["google.generativeai"] = generativeai_module
setattr(google_module, "generativeai", generativeai_module)


api_core_module = types.ModuleType("google.api_core")
api_core_module.__path__ = []
sys.modules["google.api_core"] = api_core_module


exceptions_module = types.ModuleType("google.api_core.exceptions")


class _StubGoogleException(Exception):
    """Simple base class for stubbed Google API exceptions."""


def _make_exception(name: str):
    return type(name, (_StubGoogleException,), {})


exceptions_module.ResourceExhausted = _make_exception("ResourceExhausted")
exceptions_module.ServiceUnavailable = _make_exception("ServiceUnavailable")
exceptions_module.InternalServerError = _make_exception("InternalServerError")

sys.modules["google.api_core.exceptions"] = exceptions_module
setattr(api_core_module, "exceptions", exceptions_module)
setattr(google_module, "api_core", api_core_module)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


supabase_module = types.ModuleType("supabase")


class _StubSupabaseResponse:
    def __init__(self, data=None, error=None):
        self.data = [{}] if data is None else data
        self.error = error


class _StubSupabaseInsert:
    def execute(self):
        return _StubSupabaseResponse()


class _StubSupabaseTable:
    def insert(self, *_args, **_kwargs):
        return _StubSupabaseInsert()


class _StubSupabaseClient:
    def table(self, *_args, **_kwargs):
        return _StubSupabaseTable()


def _create_supabase_client(_url, _key):
    return _StubSupabaseClient()


supabase_module.create_client = _create_supabase_client
supabase_module.Client = _StubSupabaseClient
sys.modules["supabase"] = supabase_module


from backend.python_ai.src.api.routes.honeypot_routes import (  # noqa: E402
    MAX_INTERACTION_DATA_BYTES,
    HoneypotLog,
    identify_attack_indicators,
    sanitize_for_logging,
    verify_api_key,
)
from backend.python_ai.src.main import DEFAULT_SECURITY_HEADERS, create_app  # noqa: E402


def test_identify_attack_indicators_http_directory_traversal_and_scanner():
    log = HoneypotLog(
        source_ip="1.2.3.4",
        honeypot_type="http",
        interaction_data={
            "request_path": "/../../etc/passwd",
            "method": "GET",
            "user_agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
        },
    )

    indicators = identify_attack_indicators(log)

    assert "Directory Traversal" in indicators
    assert "Known Scanner" in indicators


def test_identify_attack_indicators_http_credential_stuffing():
    log = HoneypotLog(
        source_ip="5.6.7.8",
        honeypot_type="http",
        interaction_data={
            "request_path": "/login",
            "method": "POST",
            "parsed_body": {
                "username": "admin",
                "password": "Password1!",
            },
        },
    )

    indicators = identify_attack_indicators(log)

    assert "Credential-Stuffing" in indicators
    assert "Directory Traversal" not in indicators


def test_identify_attack_indicators_ssh_bruteforce_and_scanner():
    log = HoneypotLog(
        source_ip="9.9.9.9",
        honeypot_type="ssh",
        interaction_data={
            "username_attempt": "root",
            "password_attempt": "123456",
            "client_banner": "SSH-2.0-libssh_0.9.5",
            "authentication_failures": 5,
        },
    )

    indicators = identify_attack_indicators(log)

    assert "SSH-Bruteforce" in indicators
    assert "Known Scanner" in indicators


def test_verify_api_key_accepts_valid_key():
    assert asyncio.run(verify_api_key(api_key="unit-test-key")) == "unit-test-key"


def test_verify_api_key_rejects_invalid_key():
    with pytest.raises(HTTPException):
        asyncio.run(verify_api_key(api_key="invalid-key"))


def test_sanitize_for_logging_masks_sensitive_fields():
    payload = {
        "password": "secret",
        "nested": {"token": "abc", "value": "ok"},
        "list": ["keep", {"pass": "hidden"}],
    }

    sanitized = sanitize_for_logging(payload)

    assert sanitized["password"] == "***redacted***"
    assert sanitized["nested"]["token"] == "***redacted***"
    assert sanitized["list"][1]["pass"] == "***redacted***"


def test_honeypot_log_rejects_oversized_interaction_data():
    oversized_value = "x" * (MAX_INTERACTION_DATA_BYTES + 1)

    with pytest.raises(ValidationError):
        HoneypotLog(
            source_ip="1.1.1.1",
            honeypot_type="http",
            interaction_data={"payload": oversized_value},
        )


def test_app_applies_security_headers_and_strips_server_header():
    app = create_app()

    with TestClient(app) as client:
        response = client.get("/health")

    for header_name, expected_value in DEFAULT_SECURITY_HEADERS.items():
        assert response.headers.get(header_name) == expected_value

    lower_case_headers = {key.lower() for key in response.headers.keys()}
    assert "server" not in lower_case_headers
