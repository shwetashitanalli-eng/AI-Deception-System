import os
import pandas as pd
import joblib

# Define paths matching your ml_engine folder structure
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "isolation_forest.joblib")

def score_new_session(new_session_data):
    """
    Evaluates new honeypot session data using the trained Isolation Forest model.
    """
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found at {MODEL_PATH}. Please run threat_model.py first.")
        
    model = joblib.load(MODEL_PATH)
    
    features = [
        'command_count', 
        'session_duration_seconds', 
        'failed_login_attempts', 
        'unique_commands', 
        'suspicious_command_count'
    ]
    
    df_input = pd.DataFrame([new_session_data], columns=features)
    
    prediction = model.predict(df_input)[0]
    score = ((0.5 - model.decision_function(df_input)[0]) * 100)
    score = int(max(0, min(100, score)))
    
    status = "CRITICAL THREAT (Human Actor)" if prediction == -1 else "Normal Bot Noise"
    
    print(f"\n[+] Inbound Session Evaluation -> Status: {status} | AI Threat Score: {score}/100")
    
    return prediction, score

if __name__ == "__main__":
    sample_attack = {
        'command_count': 45,
        'session_duration_seconds': 320,
        'failed_login_attempts': 1,
        'unique_commands': 12,
        'suspicious_command_count': 5
    }
    score_new_session(sample_attack)
