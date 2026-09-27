#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
.venv/bin/python -m pip install -r requirements-browser.txt
.venv/bin/python -m playwright install chromium
printf '\nChromium installed. XSS execution verification is ready.\n'
