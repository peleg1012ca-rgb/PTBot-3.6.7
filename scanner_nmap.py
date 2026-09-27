import subprocess
import xml.etree.ElementTree as ET
from database import add_service

def run_nmap_scan(scan_id, ip_address):
    # הפעלה בטוחה ללא shell=True עם רשימת ארגומנטים מפורשת
    cmd = ["nmap", "-p-", "-sV", "-oX", "-", ip_address]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            return False
            
        # פרסור פלט XML מ-Nmap
        root = ET.fromstring(result.stdout)
        for host in root.findall('host'):
            ports = host.find('ports')
            if ports is None:
                continue
            for port_elem in ports.findall('port'):
                state = port_elem.find('state')
                if state is not None and state.get('state') == 'open':
                    port_num = int(port_elem.get('portid'))
                    protocol = port_elem.get('protocol')
                    
                    service_elem = port_elem.find('service')
                    service_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                    product = service_elem.get('product', '') if service_elem is not None else ''
                    version = service_elem.get('version', '') if service_elem is not None else ''
                    full_version = f"{product} {version}".strip()
                    
                    add_service(scan_id, port_num, protocol, service_name, full_version)
        return True
    except Exception as e:
        print(f"Nmap Scan Error: {e}")
        return False
