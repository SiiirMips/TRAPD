import sys
import types
from pathlib import Path

# Stub google modules so the honeypot routes can be imported without optional dependencies.
google_module = types.ModuleType("google")
google_module.__path__ = []  # mark as package
sys.modules["google"] = google_module


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
    HoneypotLog,
    identify_attack_indicators,
)


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

    result = identify_attack_indicators(log)
    indicators = result["indicators"]

    assert "Directory Traversal" in indicators
    assert "Known Scanner" in indicators
    assert result["scanner_type"] == "Nmap"
    assert result["scan_pattern"] == "directory-traversal"
    assert result["threat_level"] in {"high", "critical"}
    assert result["tool_confidence"] >= 0.75
    assert result["tool_confidence"] <= 1
    assert result["is_real_browser"] is False


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

    result = identify_attack_indicators(log)
    indicators = result["indicators"]

    assert "Credential-Stuffing" in indicators
    assert "Directory Traversal" not in indicators
    assert result["scan_pattern"] == "credential-stuffing"
    assert result["threat_level"] in {"medium", "high"}
    assert 0 <= result["tool_confidence"] <= 1


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

    result = identify_attack_indicators(log)
    indicators = result["indicators"]

    assert "SSH-Bruteforce" in indicators
    assert "Known Scanner" in indicators
    assert result["scanner_type"] == "libssh"
    assert result["scan_pattern"] in {"ssh-bruteforce", "post-exploitation"}
    assert result["threat_level"] in {"high", "critical"}
