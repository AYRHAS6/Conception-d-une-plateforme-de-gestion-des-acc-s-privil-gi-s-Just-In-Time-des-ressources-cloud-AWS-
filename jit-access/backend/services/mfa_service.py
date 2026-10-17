"""
Service MFA (TOTP)
"""
import pyotp

# Stockage temporaire en memoire pour le developpement.
USER_TOTP_SECRETS: dict[str, str] = {}


def is_enrolled(user_email: str) -> bool:
    """True si cet utilisateur a deja un secret TOTP enregistre."""
    return user_email in USER_TOTP_SECRETS


def get_or_create_secret(user_email: str) -> str:
    if user_email not in USER_TOTP_SECRETS:
        USER_TOTP_SECRETS[user_email] = pyotp.random_base32()
    return USER_TOTP_SECRETS[user_email]


def get_provisioning_uri(user_email: str) -> str | None:
    """
    Renvoie l'URI de provisioning UNIQUEMENT si c'est le tout premier
    enrolement de cet utilisateur (secret vient d'etre cree).
    Renvoie None si l'utilisateur est deja enrole : pas besoin de
    re-scanner un QR code a chaque demande.
    """
    already_enrolled = is_enrolled(user_email)
    secret = get_or_create_secret(user_email)

    if already_enrolled:
        return None

    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=user_email, issuer_name="JIT-Access-Project")


def verify_code(user_email: str, code: str) -> bool:
    secret = USER_TOTP_SECRETS.get(user_email)
    if secret is None:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code)