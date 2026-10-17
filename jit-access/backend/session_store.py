"""Stockage ephemere des credentials STS en attente de retrait par l'agent local."""
import secrets
import threading
from datetime import datetime, timezone, timedelta

_LOCK = threading.Lock()
_SESSIONS: dict[str, dict] = {}


def create_agent_session(credentials: dict, user_email: str, request_id: str) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(48)
    claim_deadline = datetime.now(timezone.utc) + timedelta(seconds=90)
    with _LOCK:
        _SESSIONS[token] = {
            "credentials": credentials,
            "user_email": user_email,
            "request_id": request_id,
            "claim_deadline": claim_deadline,
        }
    return token, claim_deadline


def claim_agent_session(token: str) -> dict | None:
    now = datetime.now(timezone.utc)
    with _LOCK:
        item = _SESSIONS.pop(token, None)  # usage unique, meme en cas d'echec ensuite
    if not item or now > item["claim_deadline"]:
        return None
    return item
