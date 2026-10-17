Set-Location "$PSScriptRoot\backend"
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --ssl-keyfile "..\certs\localhost.key" --ssl-certfile "..\certs\localhost.crt"
