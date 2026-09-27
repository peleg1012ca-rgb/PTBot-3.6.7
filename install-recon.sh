#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
# Kali / Debian / Ubuntu. Dependencies are explicit; no pip sudo installs.
sudo apt-get update
sudo apt-get install -y nmap whatweb git
.venv/bin/python -m pip install 'dnspython==2.8.0'
if [[ "${1:-}" == "--whatwaf" ]]; then
    mkdir -p tools
    if [[ ! -e tools/WhatWaf ]]; then
        git clone https://github.com/Ekultek/WhatWaf.git tools/WhatWaf
        git -C tools/WhatWaf checkout 06c815ac541c9bba5c1a0f43ad8abfd44d6abcde
    fi
    if [[ ! -f tools/WhatWaf/lib/settings.py ]]; then
        printf 'WhatWaf source not found. Set PTBOT_WHATWAF_DIR to your installation.\n' >&2
        exit 1
    fi
fi
printf '\nRecon tools installed. Restart PTBot and open Assessments → Website Recon.\n'
