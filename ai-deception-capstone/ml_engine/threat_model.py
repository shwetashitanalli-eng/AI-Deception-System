import numpy as np
from sklearn.ensemble import IsolationForest

class ThreatModelEngine:
    def __init__(self):
        self.model = IsolationForest(contamination=0.15, random_state=42)
        # Baseline training data: [command_count, session_duration, failed_login_attempts]
        X_train = np.array([
            [1, 12.5, 0], [2, 15.0, 1], [0, 5.2, 2],
            [25, 340.0, 8], [42, 610.5, 14], [50, 890.0, 20]
        ])
        self.model.fit(X_train)

    def predict_session(self, cmd_count, duration, failed_logins):
        features = np.array([[cmd_count, duration, failed_logins]])
        prediction = self.model.predict(features)[0] # -1 for anomaly, 1 for normal
        decision_score = self.model.decision_function(features)[0]
        score = float(np.clip((0.5 - decision_score) * 100, 5, 99))
        return {
            "is_anomaly": prediction == -1,
            "threat_score": round(score, 1),
            "status": "Anomaly" if prediction == -1 else "Normal"
        }

ml_engine = ThreatModelEngine()