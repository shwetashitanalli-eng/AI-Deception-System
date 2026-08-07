import os
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data", "honeypot_logs.csv")
MODEL_PATH = os.path.join(BASE_DIR, "models", "isolation_forest.joblib")

def train_and_evaluate():
    print(f"[*] Loading dataset from {DATA_PATH}...")
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Dataset missing at {DATA_PATH}")
        
    df = pd.read_csv(DATA_PATH)
    
    # Selecting the numerical behavioral features
    features = [
        'command_count', 
        'session_duration_seconds', 
        'failed_login_attempts', 
        'unique_commands', 
        'suspicious_command_count'
    ]
    
    X = df[features]
    
    # Scale features for better machine learning precision
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print("[*] Training Isolation Forest Anomaly Detection Engine...")
    # contamination=0.08 models your targeted human threat ratio
    model = IsolationForest(n_estimators=150, contamination=0.08, random_state=42)
    model.fit(X_scaled)

    # Predict anomalies (-1 = High-risk threat, 1 = Normal bot noise)
    df['anomaly_label'] = model.predict(X_scaled)
    
    # Generate normalized threat scores (0 to 100)
    scores = model.decision_function(X_scaled)
    df['ai_threat_score'] = ((0.5 - scores) * 100).clip(0, 100).astype(int)

    # Save model and scaler binaries
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump({'model': model, 'scaler': scaler}, MODEL_PATH)
    
    # Save processed threat feed for frontend consumption
    output_feed = os.path.join(BASE_DIR, "data", "processed_threat_feed.csv")
    critical_threats = df[df['anomaly_label'] == -1].sort_values(by='ai_threat_score', ascending=False)
    critical_threats.to_csv(output_feed, index=False)
    
    print(f"[+] Training complete. Model saved to {MODEL_PATH}")
    print(f"[!] Filtered {len(critical_threats)} high-priority threats out of {len(df)} total logs.")

if __name__ == "__main__":
    train_and_evaluate()