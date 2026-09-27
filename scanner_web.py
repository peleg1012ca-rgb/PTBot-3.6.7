import subprocess
import json
import requests
from database import add_finding

SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security"
]

def run_web_enum(scan_id, target_url):
    # 1. שליחת בקשת HTTP רשמית
    try:
        response = requests.get(target_url, timeout=10)
        req_headers = json.dumps(dict(response.request.headers), indent=2)
        resp_headers = json.dumps(dict(response.headers), indent=2)
        
        evidence = f"--- REQUEST ---\nGET {target_url}\nHeaders:\n{req_headers}\n\n" \
                   f"--- RESPONSE ---\nStatus: {response.status_code}\nHeaders:\n{resp_headers}\n" \
                   f"Body Snippet:\n{response.text[:300]}"

        # שמירת ממצא מידע (Info) של תגובת HTTP
        add_finding(
            scan_id,
            title=f"HTTP Service Enumeration ({response.status_code})",
            description=f"Target responded with status code {response.status_code}",
            evidence=evidence,
            source_tool="requests (Python)",
            confidence="High",
            remediation="N/A - Informational Finding"
        )

        # 2. בדיקת Security Headers - הבחנה בין כותרת חסרה לחולשה
        for header in SECURITY_HEADERS:
            if header not in response.headers:
                add_finding(
                    scan_id,
                    title=f"Missing Security Header: {header}",
                    description=f"The HTTP response does not include the {header} header. This is a configuration recommendation.",
                    evidence=f"Missing Header: {header}\nResponse Headers:\n{resp_headers}",
                    source_tool="Web Config Checker",
                    confidence="High",
                    remediation=f"Configure the web server to send the '{header}' header in all responses."
                )

        # 3. בדיקת Cookie Flags
        for cookie in response.cookies:
            missing_flags = []
            if not cookie.secure:
                missing_flags.append("Secure")
            if not cookie.has_nonstandard_attr('httponly') and not getattr(cookie, 'httponly', False):
                missing_flags.append("HttpOnly")
            
            if missing_flags:
                add_finding(
                    scan_id,
                    title=f"Cookie Missing Security Flags ({cookie.name})",
                    description=f"Cookie '{cookie.name}' is missing flags: {', '.join(missing_flags)}.",
                    evidence=f"Cookie: {cookie.name}={cookie.value}\nFlags Missing: {missing_flags}",
                    source_tool="Web Config Checker",
                    confidence="High",
                    remediation="Set Secure and HttpOnly flags on all sensitive cookies."
                )

    except Exception as e:
        add_finding(
            scan_id,
            title="HTTP Connection Failed",
            description=f"Failed to connect to {target_url}",
            evidence=str(e),
            source_tool="requests (Python)",
            confidence="High",
            remediation="Ensure the web service is running and accessible."
        )

    # 4. הפעלת WhatWeb בצורה נקייה וסגורה
    try:
        cmd = ["whatweb", "-q", "--log-json=-", target_url]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if res.returncode == 0 and res.stdout.strip():
            # חילוץ ה-JSON במידה ויש עודפים
            raw_output = res.stdout.strip()
            json_start = raw_output.find("[")
            if json_start != -1:
                clean_json = raw_output[json_start:]
                data = json.loads(clean_json)
                plugins = data[0].get("plugins", {}) if data else {}
                
                tech_summary = ", ".join(plugins.keys())
                add_finding(
                    scan_id,
                    title="Technology Detection (WhatWeb)",
                    description=f"Identified technologies: {tech_summary}",
                    evidence=res.stdout,
                    source_tool="WhatWeb 0.6.3",
                    confidence="High",
                    remediation="Keep all identified components and software updated."
                )
    except Exception as e:
        print(f"WhatWeb Execution Error: {e}")
