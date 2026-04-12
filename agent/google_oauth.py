"""Gemini OAuth token management for Hermes Agent.

Reads, validates, refreshes, and writes Google OAuth credentials stored
at ~/.gemini/gemini_oauth.json (host) or /gemini/gemini_oauth.json (Docker).

Follows the same pattern as anthropic_adapter.py's credential lifecycle:
read_claude_code_credentials / is_claude_code_token_valid / refresh / write.
"""

import json
import logging
import os
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

GEMINI_TOKEN_URL = "https://oauth2.googleapis.com/token"


def _gemini_oauth_path() -> Path:
    """Resolve the Gemini OAuth credential file path.

    Inside Docker the host's ~/.gemini is mounted at /gemini.
    On the host, fall back to ~/.gemini.
    """
    docker_path = Path("/gemini/gemini_oauth.json")
    if docker_path.exists():
        return docker_path
    return Path.home() / ".gemini" / "gemini_oauth.json"


def read_gemini_oauth_credentials() -> Optional[Dict[str, Any]]:
    """Read Gemini OAuth credentials from disk.

    Returns dict with access_token, refresh_token, client_id, client_secret,
    expires_at, scope — or None if not found / invalid.
    """
    cred_path = _gemini_oauth_path()
    if not cred_path.exists():
        return None
    try:
        data = json.loads(cred_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not data.get("access_token"):
            logger.debug("Gemini OAuth file exists but has no access_token")
            return None
        return data
    except (json.JSONDecodeError, OSError) as e:
        logger.debug("Failed to read Gemini OAuth credentials: %s", e)
        return None


def is_gemini_token_valid(creds: Dict[str, Any]) -> bool:
    """Check if the Gemini access token is still valid (5-minute buffer)."""
    expires_at = creds.get("expires_at", 0)
    if not expires_at:
        return bool(creds.get("access_token"))
    return time.time() < (expires_at - 300)


def refresh_gemini_oauth(creds: Dict[str, Any]) -> Dict[str, Any]:
    """Refresh an expired Gemini OAuth token.

    Returns updated creds dict with new access_token and expires_at.
    Raises on failure.
    """
    refresh_token = creds.get("refresh_token", "")
    client_id = creds.get("client_id", "")
    client_secret = creds.get("client_secret", "")

    if not refresh_token:
        raise ValueError("No refresh_token in Gemini credentials")
    if not client_id:
        raise ValueError("No client_id in Gemini credentials")

    data = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
    }).encode()

    req = urllib.request.Request(
        GEMINI_TOKEN_URL,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=10) as resp:
        result = json.loads(resp.read().decode())

    access_token = result.get("access_token", "")
    if not access_token:
        raise ValueError("Gemini refresh response missing access_token")

    expires_in = result.get("expires_in", 3600)
    updated = dict(creds)
    updated["access_token"] = access_token
    updated["expires_at"] = time.time() + expires_in
    # Google may issue a new refresh token
    if result.get("refresh_token"):
        updated["refresh_token"] = result["refresh_token"]

    return updated


def write_gemini_oauth_credentials(creds: Dict[str, Any]) -> None:
    """Atomic write of Gemini OAuth credentials back to disk."""
    cred_path = _gemini_oauth_path()
    cred_path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(
        dir=str(cred_path.parent), suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(creds, f, indent=2)
            f.write("\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, str(cred_path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def resolve_gemini_oauth_token() -> Optional[str]:
    """Main entry point: read, validate, refresh if needed, return access_token.

    Returns None if no credentials found or refresh fails.
    """
    creds = read_gemini_oauth_credentials()
    if not creds:
        return None

    if is_gemini_token_valid(creds):
        return creds["access_token"]

    # Token expired — attempt refresh
    try:
        refreshed = refresh_gemini_oauth(creds)
        write_gemini_oauth_credentials(refreshed)
        logger.debug("Successfully refreshed Gemini OAuth token")
        return refreshed["access_token"]
    except Exception as e:
        logger.warning("Failed to refresh Gemini OAuth token: %s", e)
        return None
