import json
import os
import pandas as pd
from sklearn.ensemble import IsolationForest

def parse_cowrie_logs(log_path):
    """Parses raw Cowrie JSON logs into structured feature metrics."""
    if not os.path.exists(log_path):
        print(f"Log file not found: {log_path}")
        return pd.DataFrame()

    with open(log_path, 'r') as f:
        logs = json.load(f)

    sessions = {}
    for entry in logs:
        session_id = entry.get("session")
        event_id = entry.get("eventid")
        if not session_id:
            continue

        if session_id not in sessions:
            sessions[session_id] = {
                "session_id": session_id,
                "failed_logins": 0,
                "command_count": 0,
                "file_uploads": 0
            }

        if event_id == "cowrie.login.failed":
            sessions[session_id]["failed_logins"] += 1
        elif event_id == "cowrie.command.input":
            sessions[session_id]["command_count"] += 1
        elif event_id == "cowrie.session.file_upload":
            sessions[session_id]["file_uploads"] += 1

    return pd.DataFrame(list(sessions.values()))

def calculate_threat_scores(df):
    """Trains Isolation Forest and assigns threat scores to sessions."""
    features = ["failed_logins", "command_count", "file_uploads"]
    X = df[features]

    # Initialize Isolation Forest model
    model = IsolationForest(contamination=0.2, random_state=42)
    model.fit(X)

    # Anomaly flag (-1 = Anomaly, 1 = Normal)
    df["anomaly_flag"] = model.predict(X)
    
    # Raw decision function converted to a 0-1 Threat Score (Higher = Riskier)
    scores = model.decision_function(X)
    df["threat_score"] = (scores.max() - scores) / (scores.max() - scores.min() + 1e-6)

    return df

if __name__ == "__main__":
    # Example path relative to ml_engine folder
    sample_log_path = os.path.join("data", "cowrie_sample.json")
    
    df_features = parse_cowrie_logs(sample_log_path)
    if not df_features.empty:
        results = calculate_threat_scores(df_features)
        print("--- Machine Learning Threat Assessment ---")
        print(results[["session_id", "failed_logins", "command_count", "file_uploads", "threat_score", "anomaly_flag"]])
