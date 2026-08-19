import json
import os
import requests
from datetime import datetime

# Path where Canary alerts and logs will be recorded
CANARY_LOG_PATH = os.path.join("..", "..", "ml_engine", "data", "canary_alerts.json")

def create_canary_token_file(filename="admin_passwords.txt"):
    """Generates a decoy file containing a tracked Canary credential/link."""
    token_data = (
        "=== CONFIDENTIAL ADMIN CREDENTIALS ===\n"
        "DB_USER: admin_root\n"
        "DB_PASS: SuperSecret2026!\n"
        "MANAGEMENT_URL: http://canarytokens.com/feedback/tags/terms/index.html\n"
    )
    
    filepath = os.path.join("..", "honeypot", filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    with open(filepath, "w") as f:
        f.write(token_data)
        
    print(f"[+] Decoy Canary File generated successfully at: {filepath}")

def trigger_canary_alert(token_name, attacker_ip):
    """Simulates/records a Canary Token trigger event when an attacker opens the decoy."""
    alert_event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": "canary_token_triggered",
        "token_name": token_name,
        "src_ip": attacker_ip,
        "severity": "CRITICAL",
        "message": f"Unauthorized access detected on Canary File: {token_name}"
    }

    # Ensure output directory exists
    os.makedirs(os.path.dirname(CANARY_LOG_PATH), exist_ok=True)

    # Read existing alerts or start a new list
    alerts = []
    if os.path.exists(CANARY_LOG_PATH):
        try:
            with open(CANARY_LOG_PATH, "r") as f:
                alerts = json.load(f)
        except json.JSONDecodeError:
            alerts = []

    alerts.append(alert_event)

    # Save updated alert log
    with open(CANARY_LOG_PATH, "w") as f:
        json.dump(alerts, f, indent=4)

    print(f"[ALERT] Canary Token '{token_name}' was accessed by IP {attacker_ip}!")

if __name__ == "__main__":
    # Step 1: Create decoy file in honeypot directory
    create_canary_token_file()
    
    # Step 2: Simulate an attacker accessing the file
    print("--- Simulating Attack Event ---")
    trigger_canary_alert("admin_passwords.txt", "192.168.1.105")
