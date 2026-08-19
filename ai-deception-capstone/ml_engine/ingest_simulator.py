"""
Lightweight ingestion for demo: converts raw_honeypot_events.jsonl into
processed_threat_feed.json using heuristic scoring and existing threat_model helpers.
This avoids requiring a trained IsolationForest model for the dashboard demo.
"""
import os
import json
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_PATH = os.path.join(BASE_DIR, 'data', 'raw_honeypot_events.jsonl')
OUT_JSON = os.path.join(BASE_DIR, 'data', 'processed_threat_feed.json')

def heuristic_score(evt):
    # Basic heuristic combining multiple features into 0-100 score
    failed = evt.get('failed_login_attempts', 0)
    commands = evt.get('command_count', 0)
    duration = evt.get('session_duration_seconds', 0)
    suspicious = evt.get('suspicious_command_count', 0)
    canary = 1 if evt.get('canary_triggered') else 0

    score = 0
    score += min(30, (failed / 10000.0) * 30)
    score += min(40, (commands / 80.0) * 40)
    score += min(20, (duration / 1200.0) * 20)
    score += min(30, (suspicious / 15.0) * 30)
    if canary:
        score = max(score, 70)
    return int(max(0, min(100, score)))

def classify_severity(score):
    if score >= 80:
        return 'Critical'
    if score >= 60:
        return 'High'
    if score >= 30:
        return 'Medium'
    return 'Low'

def classify_type(evt):
    if evt.get('failed_login_attempts', 0) > 100:
        return 'Brute Force Attack'
    if evt.get('suspicious_command_count', 0) > 5 and evt.get('command_count', 0) > 20:
        return 'Reconnaissance/Exploitation'
    if evt.get('canary_triggered'):
        return 'Canary Token Triggered'
    if evt.get('session_duration_seconds', 0) > 300:
        return 'Interactive Session Attack'
    return 'Anomalous Activity'

def generate_description(evt, ttype, severity):
    ip = evt.get('ip') or evt.get('source_ip') or evt.get('source')
    if ttype == 'Brute Force Attack':
        return f"High-volume login attempts from {ip} ({evt.get('failed_login_attempts')} failures)."
    if ttype == 'Reconnaissance/Exploitation':
        return f"Reconnaissance commands observed from {ip}. {evt.get('suspicious_command_count',0)} suspicious commands."
    if ttype == 'Canary Token Triggered':
        return f"Decoy resource interaction from {ip}. Canary triggered."
    if ttype == 'Interactive Session Attack':
        return f"Long interactive session from {ip} ({evt.get('session_duration_seconds')}s)."
    return f"Anomalous activity from {ip}."

def ingest():
    if not os.path.exists(RAW_PATH):
        print('[!] No raw events to ingest.')
        return

    out = []
    with open(RAW_PATH, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except Exception:
                continue

            # normalize
            record = {
                'timestamp': evt.get('timestamp', datetime.utcnow().isoformat() + 'Z'),
                'source_ip': evt.get('ip') or evt.get('source_ip') or evt.get('src_ip'),
                'command_count': int(evt.get('command_count', len(evt.get('commands', [])) if isinstance(evt.get('commands'), list) else 0)),
                'session_duration_seconds': int(evt.get('session_duration_seconds', evt.get('session_duration', 0) or 0)),
                'failed_login_attempts': int(evt.get('failed_login_attempts', evt.get('failed_logins', 0) or 0)),
                'unique_commands': int(len(set(evt.get('commands', []))) if isinstance(evt.get('commands'), list) else 0),
                'suspicious_command_count': int(evt.get('suspicious_command_count', 0)),
                'has_canary_trigger': 1 if evt.get('canary_triggered') else 0
            }

            score = heuristic_score(record)
            severity = classify_severity(score)
            ttype = classify_type(record)
            desc = generate_description(record, ttype, severity)

            out.append({
                'timestamp': record['timestamp'],
                'source_ip': record['source_ip'],
                'command_count': record['command_count'],
                'session_duration_seconds': record['session_duration_seconds'],
                'failed_login_attempts': record['failed_login_attempts'],
                'unique_commands': record['unique_commands'],
                'suspicious_command_count': record['suspicious_command_count'],
                'anomaly_label': 1 if score < 50 else -1,
                'ai_threat_score': score,
                'severity': severity,
                'threat_type': ttype,
                'description': desc,
                'has_canary_trigger': record['has_canary_trigger']
            })

    # Save processed feed
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=2)

    print(f"[+] Ingested {len(out)} events -> {OUT_JSON}")

if __name__ == '__main__':
    ingest()
