"""
Validation des tokens JWT émis par Keycloak.

Le backend ne gère JAMAIS de mot de passe : il reçoit un token
déjà émis par Keycloak , et vérifie que ce token est authentique et valide.
"""
import os
import httpx
from jose import jwt, JWTError
from fastapi import HTTPException, Header
from functools import lru_cache

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "jit-realm")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "jit-backend")


@lru_cache()
def get_jwks():
    """
    Recupere les cles publiques de Keycloak (JWKS) une seule fois,
    puis les met en cache. Ces cles servent a verifier la signature
    des tokens sans avoir a recontacter Keycloak a chaque requete.
    """
    url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
    response = httpx.get(url)
    response.raise_for_status()
    return response.json()


def validate_token(authorization: str = Header(...)) -> dict:
    """
    Dependance FastAPI: extrait et valide le token Bearer envoye
    par le frontend a chaque requete protegee.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token manquant ou mal forme")

    token = authorization.replace("Bearer ", "")

    try:
        jwks = get_jwks()
        # Recupere le header du token pour trouver la bonne cle (kid)
        unverified_header = jwt.get_unverified_header(token)
        key = next((k for k in jwks["keys"] if k["kid"] == unverified_header["kid"]), None)

        if key is None:
            raise HTTPException(status_code=401, detail="Cle de signature introuvable")

        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience="account",  
            options={"verify_aud": False},  
        )
        return payload

    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Token invalide: {str(e)}")