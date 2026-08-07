# ml_engine/data/generate_data.py

import pandas as pd
import numpy as np
import random
import os

def generate_honeypot_dataset(num_samples=1500, output_path="honeypot_logs.csv"):
    """
    Generates synthetic Cowrie honeypot logs for Isolation Forest ML training.
    """
    np.random.seed(42)
    random.seed(42)

    data = []

    # Common bot/human commands for feature representation
    bot_ips = [f"45.33.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(20)]
    human_ips = [f"185.44.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(5)]

    for _ in range(num_samples):
        # 95% Chance of automated Bot traffic
        if random.random() < 0.95:
            ip = random.choice(bot_ips)
            failed_logins = random.randint(500, 10000)   # High brute force noise
            session_duration = random.randint(1, 15)      # Very short sessions
            command_count = random.randint(0, 3)          # Very few commands typed
            has_canary_trigger = 0

        # 5% Chance of Targeted / Human Attacker
        else:
            ip = random.choice(human_ips)
            failed_logins = random.randint(1, 15)        # Low login failures (credentials obtained)
            session_duration = random.randint(60, 1200)   # Longer interactive sessions (1 to 20 mins)
            command_count = random.randint(15, 80)        # Deep reconnaissance / active interaction
            
            # Low probability that human attacker triggers a canary token
            has_canary_trigger = 1 if random.random() < 0.15 else 0

        data.append({
            "source_ip": ip,
            "failed_login_attempts": failed_logins,
            "session_duration_seconds": session_duration,
            "command_count": command_count,
            "has_canary_trigger": has_canary_trigger
        })

    df = pd.DataFrame(data)
    
    # Save CSV
    df.to_csv(output_path, index=False)
    print(f"[+] Dataset generated successfully with {num_samples} records at: {output_path}")

if __name__ == "__main__":
    generate_honeypot_dataset()
