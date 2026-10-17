"""Agent JIT local Windows.

Recoit uniquement un launch_token depuis le navigateur, retire les credentials
STS directement du backend HTTPS, puis lance PowerShell avec les variables AWS.
La fenetre PowerShell est fermee a l'heure d'expiration renvoyee par AWS STS.
"""
import json
import os
import ssl
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

AGENT_HOST = "127.0.0.1"
AGENT_PORT = 8765
BACKEND_CLAIM_URL = os.getenv("JIT_BACKEND_CLAIM_URL", "https://localhost:8000/api/agent/claim")
CA_CERT = os.getenv("JIT_CA_CERT", os.path.join(os.path.dirname(__file__), "certs", "localhost.crt"))
AGENT_CERT = os.getenv("JIT_AGENT_CERT", os.path.join(os.path.dirname(__file__), "certs", "localhost.crt"))
AGENT_KEY = os.getenv("JIT_AGENT_KEY", os.path.join(os.path.dirname(__file__), "certs", "localhost.key"))


def claim_credentials(launch_token: str) -> dict:
    req = Request(BACKEND_CLAIM_URL, method="POST", headers={"Authorization": f"Bearer {launch_token}"})
    context = ssl.create_default_context(cafile=CA_CERT)
    with urlopen(req, context=context, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))["credentials"]


def launch_powershell(creds: dict) -> None:
    expiration = datetime.fromisoformat(creds["expiration"].replace("Z", "+00:00"))
    remaining = (expiration - datetime.now(timezone.utc)).total_seconds()
    if remaining <= 0:
        raise RuntimeError("Les credentials STS sont deja expires")

    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"] = creds["access_key"]
    env["AWS_SECRET_ACCESS_KEY"] = creds["secret_key"]
    env["AWS_SESSION_TOKEN"] = creds["session_token"]

    intro = (
        "Write-Host 'Session AWS JIT active' -ForegroundColor Green; "
        f"Write-Host 'Expiration STS: {creds['expiration']}'; "
        "aws sts get-caller-identity; "
        "Write-Host 'La fenetre sera fermee automatiquement a expiration.' -ForegroundColor Yellow"
    )
    creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
    proc = subprocess.Popen(
        ["powershell.exe", "-NoLogo", "-NoExit", "-Command", intro],
        env=env,
        creationflags=creationflags,
    )

    def close_at_expiration():
        time.sleep(max(0, remaining))
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    threading.Thread(target=close_at_expiration, daemon=True).start()


class Handler(BaseHTTPRequestHandler):
    def _reply(self, status: int, body: dict):
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "https://localhost:5500")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        self._reply(204, {})

    def do_POST(self):
        if self.path != "/launch":
            return self._reply(404, {"detail": "Not found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length) or b"{}")
            token = data.get("launch_token")
            if not token:
                return self._reply(400, {"detail": "launch_token manquant"})
            creds = claim_credentials(token)
            launch_powershell(creds)
            self._reply(200, {"status": "launched", "expiration": creds["expiration"]})
        except (HTTPError, URLError) as exc:
            self._reply(502, {"detail": f"Impossible de joindre le backend: {exc}"})
        except Exception as exc:
            self._reply(500, {"detail": str(exc)})

    def log_message(self, fmt, *args):
        print("[agent]", fmt % args)


def main():
    if os.name != "nt":
        raise SystemExit("Cet agent est prevu pour Windows/PowerShell.")
    server = ThreadingHTTPServer((AGENT_HOST, AGENT_PORT), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(AGENT_CERT, AGENT_KEY)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    print(f"Agent JIT actif sur https://{AGENT_HOST}:{AGENT_PORT}")
    server.serve_forever()

if __name__ == "__main__":
    main()
