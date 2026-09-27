import socket
from urllib.parse import urlparse
import requests
from config import ALLOWED_LAB_TARGETS

def is_ip_allowed(ip_str):
    return ip_str in ALLOWED_LAB_TARGETS

def validate_target(target_input):
    """
    בודק IP או URL ומוודא שהם מורשים.
    מחזיר (is_valid, resolved_ip, target_url, error_message)
    """
    target_input = target_input.strip()
    
    # במידה והוזן URL
    if target_input.startswith("http://") or target_input.startswith("https://"):
        parsed = urlparse(target_input)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        target_url = target_input
    else:
        # במידה והוזן IP או Hostname
        hostname = target_input
        target_url = f"http://{hostname}:8000" if hostname == "127.0.0.1" else f"http://{hostname}"

    try:
        resolved_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return False, None, None, f"Could not resolve hostname: {hostname}"

    if not is_ip_allowed(resolved_ip):
        return False, resolved_ip, target_url, f"Target IP {resolved_ip} is OUT OF SCOPE!"

    # בדיקת Redirects
    try:
        res = requests.head(target_url, allow_redirects=True, timeout=5)
        final_url = res.url
        final_hostname = urlparse(final_url).hostname
        final_ip = socket.gethostbyname(final_hostname)
        if not is_ip_allowed(final_ip):
            return False, final_ip, final_url, f"Redirected to OUT OF SCOPE target: {final_ip}"
    except Exception:
        # במידה והשרת עדיין לא למעלה או לא מגיב ל-HEAD, נמשיך אם ה-IP הבסיסי תקין
        pass

    return True, resolved_ip, target_url, None
