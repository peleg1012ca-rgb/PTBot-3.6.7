"""Local WSGI entrypoint. Use an SSH tunnel or a TLS reverse proxy for remote access."""

from pathlib import Path

if not (Path(__file__).resolve().parent / "instance/operator.json").is_file():
    raise SystemExit("First create an operator: .venv/bin/python manage.py user")
from waitress import serve
from app import app
from xss_store import recover_interrupted
recover_interrupted(app.config["DATABASE_PATH"])
from recon_store import recover_interrupted as recover_recon
recover_recon(app.config["DATABASE_PATH"])

serve(app, host="127.0.0.1", port=5000, threads=4)
