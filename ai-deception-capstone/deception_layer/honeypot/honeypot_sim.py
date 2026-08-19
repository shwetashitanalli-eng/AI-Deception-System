"""
Simple, safe honeypot simulator for local testing.
Writes synthetic JSON lines to the ML engine raw events file so the ML pipeline can ingest them.
This script is intentionally non-malicious and designed for local/demo use only.
"""
import json
import os
import random
import time
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Allow overriding the output path via environment variable for container mounts
RAW_LOG_PATH = os.environ.get('RAW_LOG_PATH') or os.path.normpath(os.path.join(BASE_DIR, '..', '..', 'ml_engine', 'data', 'raw_honeypot_events.jsonl'))

SAMPLE_COMMANDS = [
    ['id'],
    ['nmap', 'ifconfig'],
    ['ls', 'cat', 'passwd'],
    ['wget', 'python -c "print(1)"'],
    ['nc -e /bin/sh'],
]

def generate_event():
    ip = f"185.44.{random.randint(1,255)}.{random.randint(1,255)}" if random.random() < 0.1 else f"45.33.{random.randint(1,255)}.{random.randint(1,255)}"
    commands = random.choice(SAMPLE_COMMANDS)
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'ip': ip,
        'command_count': len(commands),
        'session_duration_seconds': random.randint(1, 1200),
        'failed_login_attempts': random.randint(0, 20),
        'commands': commands,
        'canary_triggered': random.choice([False] * 9 + [True])  # 10% chance
    }
    return event


def write_event(event):
    os.makedirs(os.path.dirname(RAW_LOG_PATH), exist_ok=True)
    with open(RAW_LOG_PATH, 'a', encoding='utf-8') as f:
        f.write(json.dumps(event) + '\n')


def main_once():
    event = generate_event()
    write_event(event)
    print(f"[+] Wrote event: {event['ip']} canary={event['canary_triggered']}")

if __name__ == '__main__':
    # If run directly, write a single event and exit (useful for testing)
    main_once()
