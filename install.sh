#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-lock.txt
.venv/bin/python -m unittest discover -s tests -v
printf '\nCreate your login with: .venv/bin/python manage.py user\nInitialize with: .venv/bin/python manage.py init\nStart with: bash start.sh\n'
