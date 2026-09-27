import threading
from database import update_scan_status
from scanner_nmap import run_nmap_scan
from scanner_web import run_web_enum

def async_scan_task(scan_id, resolved_ip, target_url):
    try:
        # שלב 1: סריקת פורטים
        update_scan_status(scan_id, "Scanning Ports")
        nmap_ok = run_nmap_scan(scan_id, resolved_ip)
        
        # שלב 2: סריקת Web
        update_scan_status(scan_id, "Checking Web")
        run_web_enum(scan_id, target_url)
        
        # שלב 3: סיום
        update_scan_status(scan_id, "Completed")
    except Exception as e:
        print(f"Task Failed: {e}")
        update_scan_status(scan_id, "Failed")

def start_scan_in_background(scan_id, resolved_ip, target_url):
    thread = threading.Thread(target=async_scan_task, args=(scan_id, resolved_ip, target_url))
    thread.daemon = True
    thread.start()
