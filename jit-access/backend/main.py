"""

Orchestration du flux complet :
  1. Reception demande -> 2. Verification ticket (Jira)
  -> 3. Decision (OPA) -> 4. MFA (TOTP) -> 5. Provisioning (AWS STS)

"""
from dotenv import load_dotenv
load_dotenv()  

import uuid
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware

from auth import validate_token
from models import AccessRequest, MfaVerification
from services import jira_service, opa_service, mfa_service, aws_service, splunk_service
import session_store

app = FastAPI(title="JIT Access Backend")

# CORS - autorise le frontend (origine differente : port 5500)
# a appeler ce backend (port 8000) depuis le navigateur.

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://127.0.0.1:5500",
        "https://localhost:5500",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Stockage temporaire en memoire des demandes en attente de MFA.
PENDING_REQUESTS: dict[str, dict] = {}


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/api/access-requests")
def create_access_request(payload: AccessRequest, user: dict = Depends(validate_token)):
    """
    ETAPES 1 a 4 :
    - Recupere le ticket depuis Jira
    - Assemble le contexte
    - Interroge OPA
    - Si allow : cree une demande en attente de MFA
    """
    user_email = user.get("email")

    # ETAPE 2 - Verification du ticket
    ticket = jira_service.get_ticket(payload.ticket_id)
    if ticket is None:
        splunk_service.send_event("access_denied", {
            "user_email": user_email,
            "ticket_id": payload.ticket_id,
            "reason": "ticket_not_found",
        })
        raise HTTPException(status_code=404, detail="Ticket Jira introuvable")

    # ETAPE 3 - Assemblage du contexte + decision OPA
    user_roles = user.get("realm_access", {}).get("roles", [])

    opa_input = {
        "user": {
            "email": user_email,
            "roles": user_roles,
        },
        "request": {
            "requested_role": payload.requested_role.value,
            "resource_name": payload.resource_name,
            "duration_minutes": payload.duration_minutes,
        },
        "ticket": ticket,
        "context": {
            "current_time": datetime.utcnow().isoformat() + "Z",
        },
    }

    allowed = opa_service.evaluate_access(opa_input)
    if not allowed:
        splunk_service.send_event("access_denied", {
            "user_email": user_email,
            "ticket_id": payload.ticket_id,
            "requested_role": payload.requested_role.value,
            "reason": "policy_rejected",
        })
        return {"status": "denied", "reason": "Politique de securite non satisfaite"}

    # ETAPE 4 - Creation d'une demande en attente de MFA
    request_id = str(uuid.uuid4())
    PENDING_REQUESTS[request_id] = {
        "user_email": user_email,
        "payload": payload.dict(),
        "created_at": datetime.utcnow(),
    }

    splunk_service.send_event("mfa_required", {
        "user_email": user_email,
        "ticket_id": payload.ticket_id,
        "requested_role": payload.requested_role.value,
        "request_id": request_id,
    })

    return {
        "status": "mfa_required",
        "request_id": request_id,
    }


@app.post("/api/access-requests/{request_id}/verify-mfa")
def verify_mfa_and_grant(request_id: str, payload: MfaVerification, user: dict = Depends(validate_token)):
    """
    ETAPES 5 a 7 :
    - Verifie le code MFA
    - Si valide : provisioning REEL via AWS STS
    - Enregistre l'audit
    """
    pending = PENDING_REQUESTS.get(request_id)
    if pending is None:
        raise HTTPException(status_code=404, detail="Demande introuvable ou expiree")

    user_email = user.get("email")

    # ETAPE 5 - Verification MFA
    if not mfa_service.verify_code(user_email, payload.otp_code):
        splunk_service.send_event("mfa_failed", {
            "user_email": user_email,
            "request_id": request_id,
        })
        raise HTTPException(status_code=401, detail="Code MFA invalide")

    # ETAPE 6 - Provisioning  via AWS STS
    request_payload = pending["payload"]
    try:
        credentials = aws_service.assume_role_for_request(
            requested_role=request_payload["requested_role"],
            ticket_id=request_payload["ticket_id"],
            duration_minutes=request_payload["duration_minutes"],
        )
    except Exception as e:
        splunk_service.send_event("provisioning_failed", {
            "user_email": user_email,
            "request_id": request_id,
            "error": str(e),
        })
        raise HTTPException(status_code=502, detail=f"Erreur AWS STS : {str(e)}")

    del PENDING_REQUESTS[request_id]

    splunk_service.send_event("access_granted", {
        "user_email": user_email,
        "request_id": request_id,
        "ticket_id": request_payload["ticket_id"],
        "requested_role": request_payload["requested_role"],
        "resource_name": request_payload["resource_name"],
        "duration_minutes": request_payload["duration_minutes"],
    })

    # Les secrets STS ne sont PLUS renvoyes au navigateur.
    # Un jeton opaque, aleatoire, a usage unique permet a l'agent local
    # de les retirer directement du backend via HTTPS.
    launch_token, claim_deadline = session_store.create_agent_session(
        credentials=credentials,
        user_email=user_email,
        request_id=request_id,
    )

    return {
        "status": "granted",
        "launch_token": launch_token,
        "claim_deadline": claim_deadline.isoformat(),
        "expiration": credentials["expiration"],
    }


@app.get("/api/mfa/enroll")
def enroll_mfa(user: dict = Depends(validate_token)):
    """
    Endpoint utilitaire pour recuperer l'URI d'enrolement TOTP
    (converti en QR code cote frontend).
    """
    user_email = user.get("email")
    uri = mfa_service.get_provisioning_uri(user_email)
    return {"provisioning_uri": uri}

@app.post("/api/agent/claim")
def agent_claim(authorization: str | None = Header(default=None)):
    """Retrait a usage unique des credentials par l'agent local."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Jeton agent manquant")
    token = authorization.removeprefix("Bearer ").strip()
    item = session_store.claim_agent_session(token)
    if item is None:
        raise HTTPException(status_code=401, detail="Jeton agent invalide, expire ou deja utilise")

    splunk_service.send_event("agent_credentials_claimed", {
        "user_email": item["user_email"],
        "request_id": item["request_id"],
    })
    return {"credentials": item["credentials"]}
