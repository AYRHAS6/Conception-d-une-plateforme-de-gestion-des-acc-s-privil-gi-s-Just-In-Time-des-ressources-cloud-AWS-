"""
Service Jira 

Appelle l'API REST Jira Cloud (v3) pour recuperer un ticket
et en extraire les champs necessaires a la decision OPA.

"""
import os
import httpx

JIRA_URL = os.getenv("JIRA_URL")
JIRA_EMAIL = os.getenv("JIRA_EMAIL")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")


def get_ticket(ticket_id: str) -> dict | None:
    """
    Recupere un ticket Jira par son identifiant.

    Renvoie un dict normalise avec les champs utiles :
    - id, summary        
    - status, priority     
    - assignee             
    - created         
    Renvoie None si le ticket n'existe pas .
    """
    url = f"{JIRA_URL}/rest/api/3/issue/{ticket_id}"

    response = httpx.get(
        url,
        auth=(JIRA_EMAIL, JIRA_API_TOKEN),
        headers={"Accept": "application/json"},
        timeout=10.0,
    )

    if response.status_code == 404:
        return None

    response.raise_for_status()
    data = response.json()
    fields = data["fields"]

    # L'assignee peut etre absent (ticket non assigne) -> on gere le cas
    assignee_email = None
    if fields.get("assignee") is not None:
        assignee_email = fields["assignee"].get("emailAddress")

    return {
        "id": data["key"],
        "summary": fields.get("summary"),
        "status": fields["status"]["name"],
        "priority": fields["priority"]["name"] if fields.get("priority") else None,
        "assignee": assignee_email,
        "created": fields.get("created"),
    }


