import http.server, ssl
from functools import partial
from pathlib import Path
ROOT = Path(__file__).resolve().parent
handler = partial(http.server.SimpleHTTPRequestHandler, directory=str(ROOT / "frontend"))
server = http.server.ThreadingHTTPServer(("127.0.0.1", 5500), handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(ROOT / "certs/localhost.crt", ROOT / "certs/localhost.key")
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print("Frontend: https://localhost:5500")
server.serve_forever()
