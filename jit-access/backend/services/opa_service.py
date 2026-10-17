"""
Service OPA - VERSION REELLE.

Interroge le serveur OPA pour obtenir
une decision d'autorisation, basee sur les regles Rego definies
dans opa/policies/jit_authz.rego.

"""
import os
import httpx

OPA_URL = os.getenv("OPA_URL", "http://localhost:8181")



def evaluate_access(opa_input: dict) -> bool:
    """
    Envoie le contexte a OPA et renvoie la decision (True/False).

    Endpoint interroge : /v1/data/jit/authz/allow
    (correspond au package "jit.authz" et a la regle "allow"
    definis dans le fichier .rego)
    """
    response = httpx.post(
        f"{OPA_URL}/v1/data/jit/authz/allow",
        json={"input": opa_input},
        timeout=5.0,
    )
    response.raise_for_status()
    return response.json().get("result", False)

    