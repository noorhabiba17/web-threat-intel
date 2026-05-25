import os
import re
from typing import ClassVar


def _resolve_host(host: str) -> str:
    """Resolve hostname via Google DNS-over-HTTPS (bypasses local DNS blocks)."""
    try:
        import requests
        resp = requests.get(f"https://dns.google/resolve?name={host}&type=A", timeout=5)
        data = resp.json()
        for ans in data.get("Answer", []):
            if ans.get("type") == 1:
                return ans["data"]
    except Exception:
        pass
    return host


_DEFAULT_DB = os.environ.get(
    "DATABASE_URL",
    "postgresql://neondb_owner:npg_j1cxKDdeH0Ff@ep-wild-lake-aozilfkb.c-2.ap-southeast-1.aws.neon.tech/neondb?sslmode=require",
)
# Resolve Neon hostname via DoH if DNS is blocked
_match = re.search(r"@([^:/]+)", _DEFAULT_DB)
if _match:
    original_host = _match.group(1)
    resolved_ip = _resolve_host(original_host)
    if resolved_ip != original_host:
        _DEFAULT_DB = _DEFAULT_DB.replace(f"@{original_host}", f"@{resolved_ip}", 1)
        # Neon requires endpoint ID when connecting by IP
        endpoint_id = original_host.split(".")[0]
        sep = "&" if "?" in _DEFAULT_DB else "?"
        _DEFAULT_DB += f"{sep}options=endpoint%3D{endpoint_id}"


class Config:
    SECRET_KEY: ClassVar[str] = os.environ.get("SECRET_KEY", "change-this-in-production-please-1234567890")
    SQLALCHEMY_DATABASE_URI: ClassVar[str] = _DEFAULT_DB
    SQLALCHEMY_TRACK_MODIFICATIONS: ClassVar[bool] = False
    SESSION_COOKIE_HTTPONLY: ClassVar[bool] = True
    SESSION_COOKIE_SAMESITE: ClassVar[str] = "Lax"
    PERMANENT_SESSION_LIFETIME: ClassVar[int] = 60 * 60 * 8
