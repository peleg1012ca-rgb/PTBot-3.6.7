#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
bash install.sh
bash install-browser.sh
.venv/bin/python manage.py init
if [ ! -f instance/operator.json ]; then
    .venv/bin/python manage.py user
fi
.venv/bin/python manage.py demo
printf '\nPTBot 3.6.7 ready. Run: bash start.sh\nIn a second terminal: bash start-lab.sh\n'
