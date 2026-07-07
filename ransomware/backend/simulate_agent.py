import time
import requests
import sys

BASE_URL = "http://localhost:8000/api"
DEVICE_ID = "agent-simulated-x"
HOSTNAME = "agent-simulated-x"

def print_header(title):
    print("\n" + "="*50)
    print(f"  {title}")
    print("="*50)

def register_self():
    print(f"Connecting to backend {BASE_URL}...")
    payload = {
        "id": DEVICE_ID,
        "hostname": HOSTNAME,
        "ip_address": "192.168.1.189",
        "mac_address": "00:0C:29:BD:A8:11",
        "os_type": "Windows",
        "firewall_status": "enabled"
    }
    try:
        r = requests.post(f"{BASE_URL}/devices/register", json=payload)
        if r.status_code in [200, 201]:
            print(f"Successfully registered device: {DEVICE_ID}")
            return True
        else:
            print(f"Registration failed: Code {r.status_code}, {r.text}")
            return False
    except Exception as e:
        print(f"Failed to connect to backend: {e}")
        return False

def send_log(log_type, action, details):
    payload = {
        "device_id": DEVICE_ID,
        "type": log_type,
        "action": action,
        "details": details
    }
    try:
        r = requests.post(f"{BASE_URL}/threats/logs", json=payload)
        if r.status_code in [200, 201]:
            print(f"Successfully sent log [{log_type.upper()}] -> action: '{action}'")
            return r.json()
        else:
            print(f"Failed to send log: Code {r.status_code}, {r.text}")
            return None
    except Exception as e:
        print(f"Error sending log: {e}")
        return None

def send_heartbeat(status="online", firewall="enabled", trust=None):
    payload = {
        "status": status,
        "firewall_status": firewall
    }
    if trust is not None:
        payload["trust_score"] = trust
        
    try:
        r = requests.post(f"{BASE_URL}/devices/{DEVICE_ID}/heartbeat", json=payload)
        if r.status_code == 200:
            data = r.json()
            print(f"Heartbeat OK: status={status}, trust={data.get('trust_score')}/100, firewall={firewall}")
        else:
            print(f"Heartbeat failed: Code {r.status_code}")
    except Exception as e:
        print(f"Error sending heartbeat: {e}")

def trigger_ransomware_scenario():
    print_header("SIMULATING RANSOMWARE ENCRYPTION ATTACK")
    print("Step 1: Outlook processes email attachment...")
    send_log("process", "started", {"name": "outlook.exe", "pid": 4810, "command": "outlook.exe"})
    time.sleep(1)
    
    print("Step 2: Browser launches payload URL...")
    send_log("process", "started", {"name": "chrome.exe", "pid": 9220, "command": "chrome.exe https://invoice-portal.net/payload.exe"})
    time.sleep(1)
    
    print("Step 3: Executing malicious payload invoice.pdf.exe...")
    send_log("process", "started", {"name": "invoice.pdf.exe", "pid": 1104, "command": "invoice.pdf.exe"})
    time.sleep(1.5)
    
    print("Step 4: Executing shadow copy removal command...")
    send_log("process", "started", {"name": "powershell.exe", "command": "vssadmin delete shadows /all /quiet"})
    time.sleep(1)
    
    print("Step 5: Rapidly rewriting/encrypting user documents...")
    send_log("file", "modified", {"modified_count": 45, "entropy": 7.9, "extension": ".locked", "directory": "C:\\Users\\User\\Documents"})
    print("\n--> Ransomware event should be triggered in backend!")

def trigger_deception_scenario():
    print_header("SIMULATING DECEPTION ENGINE TRIGGER")
    print("Step 1: Unsigned scanner.exe executed in temp folder...")
    send_log("process", "started", {"name": "scanner.exe", "pid": 3209, "command": "C:\\Users\\User\\AppData\\Local\\Temp\\scanner.exe"})
    time.sleep(1)
    
    print("Step 2: Process attempts scanning documents directory...")
    send_log("file", "scanned", {"path": "C:\\Users\\User\\Documents"})
    time.sleep(1)
    
    print("Step 3: Process reads sensitive Decoy / Honeypot excel file...")
    send_log("file", "accessed", {"path": "C:\\Users\\User\\Documents\\salary.xlsx", "privileges": "READ"})
    print("\n--> Deception decoy alert should be triggered in backend!")

def trigger_usb_scenario():
    print_header("SIMULATING UNAUTHORIZED USB INSERTION")
    print("Step 1: USB Mass Storage driver connection event...")
    send_log("usb", "connected", {"vendor_id": "0930", "product_id": "6545", "serial": "USB1238912"})
    time.sleep(1)
    
    print("Step 2: USB partition mounted as drive E:...")
    send_log("usb", "mounted", {"label": "CorporateBackups", "authorized": False, "status": "Unauthorized"})
    print("\n--> USB block alert should be triggered in backend!")

def trigger_identity_scenario():
    print_header("SIMULATING CREDENTIAL THEFT / LSASS DUMP")
    print("Step 1: Command line running as SYSTEM user...")
    send_log("process", "started", {"name": "cmd.exe", "pid": 990, "command": "cmd.exe /c whoami"})
    time.sleep(1)
    
    print("Step 2: Attempting LSASS memory injection/dump...")
    send_log("process", "started", {"name": "lsass.exe", "action": "dump_attempt", "command": "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump 676 C:\\lsass.dmp full"})
    print("\n--> Identity credential dumping alert should be triggered in backend!")

def main():
    print_header("SENTINELCRYPT EDR - AGENT SIMULATOR")
    if not register_self():
        print("Backend must be running. Start FastAPI backend first.")
        sys.exit(1)
        
    send_heartbeat()
    
    while True:
        print("\nChoose an agent simulation command:")
        print("1. Send Heartbeat (status=online)")
        print("2. Send Heartbeat (status=offline)")
        print("3. Simulate Ransomware Attack (File modification burst)")
        print("4. Simulate Deception Asset Access (salary.xlsx decoy file read)")
        print("5. Simulate Unauthorized USB Mass Storage connection")
        print("6. Simulate Identity Abuse / LSASS memory dump")
        print("7. Recover simulated device (Clear alerts/Restore trust score)")
        print("8. Exit")
        
        choice = input("\nEnter choice [1-8]: ").strip()
        
        if choice == "1":
            send_heartbeat(status="online")
        elif choice == "2":
            send_heartbeat(status="offline")
        elif choice == "3":
            trigger_ransomware_scenario()
        elif choice == "4":
            trigger_deception_scenario()
        elif choice == "5":
            trigger_usb_scenario()
        elif choice == "6":
            trigger_identity_scenario()
        elif choice == "7":
            print_header("RECOVERING SIMULATED DEVICE")
            send_heartbeat(status="online", firewall="enabled", trust=100)
        elif choice == "8":
            print("Exiting simulator...")
            break
        else:
            print("Invalid choice, try again.")

if __name__ == "__main__":
    main()
