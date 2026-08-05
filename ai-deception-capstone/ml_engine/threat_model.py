# ml_engine/threat_model.py

import os
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

# Define default paths relative to this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DATA_PATH = os.path.join(BASE_DIR, "data", "honeypot_logs.csv")
DEFAULT_MODEL_PATH = os.path.join(BASE_DIR, "models", "isolation_forest.joblib")


def train_threat_model(data_path=DEFAULT_DATA_PATH, save_model_path=DEFAULT_MODEL_PATH):
    """
    Loads honeypot logs, trains an Isolation Forest model, 
    and saves the model binary for live inference.
    """
    print(f"[*] Loading Honeypot log dataset from: {data_path}")
    if not os.path.exists(data_path):
        raise FileNotFoundError(
            f"Dataset not found at '{data_path}'. Please run 'generate_data.py' first!"
        )

    df = pd.read_csv(data_path)

    # Features selected for anomaly profiling
    features = ['failed_login_attempts', 'session_duration_seconds', 'command_count']
    X = df[features]

    # Contamination=0.05 assumes roughly 5% of incoming connections are high-severity targeted attacks
    print("[*] Training Isolation Forest Model...")
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(X)

    # Predict: -1 indicates anomaly (targeted threat), 1 indicates normal (bot noise)
    df['anomaly_label'] = model.predict(X)

    # Calculate normalized AI Threat Score (0 to 100)
    scores = model.decision_function(X)
    df['ai_threat_score'] = ((0.5 - scores) * 100).clip(0, 100).astype(int)

    # Save trained model artifact
    os.makedirs(os.path.dirname(save_model_path), exist_ok=True)
    joblib.dump(model, save_model_path)
    print(f"[+] Model artifact saved to: {save_model_path}")

    # Summary
    critical_threats = df[df['anomaly_label'] == -1]
    print(f"[!] Total logs analyzed: {len(df)}")
    print(f"[!] Critical anomalous sessions flagged: {len(critical_threats)}")

    return df


def score_live_session(features_df, model_path=DEFAULT_MODEL_PATH):
    """
    Evaluates new real-time honeypot sessions using the saved model.
    """
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file missing at '{model_path}'. Train model first.")

    model = joblib.load(model_path)
    predictions = model.predict(features_df)
    scores = model.decision_function(features_df)
    threat_scores = ((0.5 - scores) * 100).clip(0, 100).astype(int)

    return predictions, threat_scores


if __name__ == "__main__":
    train_threat_model()
