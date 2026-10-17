"""
Service Splunk - envoie les evenements du flux JIT vers Splunk
via le HTTP Event Collector (HEC), pour observabilite et alerting.

"""
import os
import httpx
from datetime import datetime

SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "https://localhost:8088/services/collector/event")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "00000000-0000-0000-0000-000000000000")


def send_event(event_type: str, data: dict) -> None:
    """
    Envoie un evenement structure a Splunk.
    """
    payload = {
        "event": {
            "event_type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            **data,
        },
        "sourcetype": "jit_access_logs",
    }

    try:
        httpx.post(
            SPLUNK_HEC_URL,
            headers={"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"},
            json=payload,
            timeout=3.0,
            verify=False,  
        )
    except httpx.HTTPError:
        # On avale l'erreur : un Splunk down ne doit
        # jamais empecher une decision d'acces legitime de se derouler.
        pass