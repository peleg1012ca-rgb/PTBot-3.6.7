# Release 3.6.7

Based on the supplied PTBot 3.5.4 source archive.

- Replaced general XSS Lab branding with Assessments; retained focused XSS checks and legacy URL compatibility.
- Added scoped asynchronous Website Recon jobs, SQLite persistence, cancel/status endpoints, interrupted-run recovery and engagement ownership checks.
- Added DNS, HTTP/TLS overview, passive CT/TLS/HTML candidate discovery, WhatWeb level-1 execution, WhatWaf passive signature adapter and bounded Nmap selected-port execution.
- Added a navy Recon dashboard with provenance, module coverage, history, subdomain filtering, JSON export and browser print/PDF.
- Preserved existing permissions: new subdomain discovery requires a grant; technology_fingerprint now permits WhatWeb HTTP requests. Existing grants retain their recorded RPM budget.
- Preserved the compatible data filename and added a non-destructive schema migration.
- Added optional tool installation and configuration, including a pinned external WhatWaf source checkout.

## Coverage limits

One seed URL; one resolved address used for HTTP/TLS/Nmap connections. No crawling, CT candidate reachability probing, Nmap version scanning or WhatWaf active probe/bypass flow. Tool or provider failures are surfaced as incomplete coverage. Passive detections require contextual review. The app does not contain an autonomous AI exploitation agent.
