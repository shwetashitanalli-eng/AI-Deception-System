# ml_engine/log_parser.py
# Parses raw honeypot events and extracts ML features

import os
import pandas as pd
import json
import joblib
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "isolation_forest.joblib")

def parse_raw_honeypot_logs(input_file):
    """
    Parses raw honeypot events (JSON or text format) and creates structured data.
    Extracts ML features required for threat detection.
    """
    print(f"[*] Parsing raw honeypot logs from {input_file}...")
    
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Honeypot log file not found at {input_file}")
    
    records = []
    
    # Check if JSON or text format
    if input_file.endswith('.json') or input_file.endswith('.jsonl'):
        with open(input_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line.strip()) if line.strip() else None
                    if event:
                        record = extract_features_from_json(event)
                        if record:
                            records.append(record)
                except json.JSONDecodeError:
                    continue
    else:
        # Text log format
        with open(input_file, 'r') as f:
            records = parse_text_logs(f)
    
    if not records:
        print("[!] Warning: No records parsed from honeypot logs. Using empty dataset.")
        return pd.DataFrame()
    
    df = pd.DataFrame(records)
    print(f"[+] Successfully parsed {len(df)} honeypot session records.")
    print(f"[*] Features extracted: timestamp, source_ip, command_count, session_duration_seconds, failed_login_attempts, unique_commands, suspicious_command_count")
    
    return df

def extract_features_from_json(event):
    """
    Extracts ML features from a single JSON honeypot event.
    """
    try:
        # Handle various honeypot log formats
        record = {
            "timestamp": event.get("timestamp", datetime.now().isoformat()),
            "source_ip": event.get("src_ip") or event.get("source_ip") or event.get("ip"),
            "command_count": event.get("command_count", len(event.get("commands", []))),
            "session_duration_seconds": event.get("session_duration", 0),
            "failed_login_attempts": event.get("failed_logins", 0),
            "unique_commands": event.get("unique_commands", len(set(event.get("commands", [])))),
            "suspicious_command_count": count_suspicious_commands(event.get("commands", [])),
            "has_canary_trigger": event.get("canary_triggered", 0)
        }
        
        # Validate required fields
        if not record["source_ip"]:
            return None
            
        return record
    except Exception as e:
        print(f"[!] Error parsing event: {e}")
        return None

def parse_text_logs(file_obj):
    """
    Parses text-based honeypot logs (if raw format is text).
    """
    records = []
    # Placeholder for custom text parsing logic
    # This would depend on your actual log format
    return records

def count_suspicious_commands(commands):
    """
    Counts commands that are typically associated with reconnaissance or exploitation.
    """
    suspicious_keywords = [
        'nmap', 'netstat', 'ifconfig', 'find', 'locate', 'which',
        'ssh-keygen', 'ssh-copy-id', 'wget', 'curl', 'nc', 'python',
        'perl', 'bash', 'sh', 'chmod', 'sudo', 'passwd', 'cat',
        'tar', 'zip', 'gzip', 'wget', 'git', 'compile'
    ]
    
    if not commands:
        return 0
    
    count = 0
    for cmd in commands:
        cmd_lower = str(cmd).lower()
        for keyword in suspicious_keywords:
            if keyword in cmd_lower:
                count += 1
                break
    
    return count

def score_new_session(new_session_data):
    """
    Evaluates new honeypot session data using the trained Isolation Forest model.
    Returns prediction and threat score.
    """
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found at {MODEL_PATH}. Please run threat_model.py first.")
    
    try:
        model_data = joblib.load(MODEL_PATH)
        model = model_data['model']
        scaler = model_data['scaler']
    except Exception as e:
        raise RuntimeError(f"Error loading model: {e}")
    
    features = [
        'command_count', 
        'session_duration_seconds', 
        'failed_login_attempts', 
        'unique_commands', 
        'suspicious_command_count'
    ]
    
    try:
        df_input = pd.DataFrame([new_session_data], columns=features)
        X_scaled = scaler.transform(df_input)
        
        prediction = model.predict(X_scaled)[0]
        score = ((0.5 - model.decision_function(X_scaled)[0]) * 100)
        score = int(max(0, min(100, score)))
        
        status = "CRITICAL THREAT (Human Actor)" if prediction == -1 else "Normal Bot Noise"
        
        print(f"\n[+] Inbound Session Evaluation -> Status: {status} | AI Threat Score: {score}/100")
        
        return prediction, score
    except Exception as e:
        print(f"[!] Error scoring session: {e}")
        return None, 0

if __name__ == "__main__":
    # Test with sample data
    sample_attack = {
        'command_count': 45,
        'session_duration_seconds': 320,
        'failed_login_attempts': 1,
        'unique_commands': 12,
        'suspicious_command_count': 5
    }
    try:
        score_new_session(sample_attack)
    except Exception as e:
        print(f"[!] Error: {e}")
