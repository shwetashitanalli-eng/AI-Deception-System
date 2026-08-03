"""
threat_model.py
Scikit-learn training logic for anomaly detection (Isolation Forest).
This is a minimal skeleton — wire up with your dataset and feature extraction.
"""
import json
import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest

DATA_DIR = Path(__file__).resolve().parent / "data"
MODELS_DIR = Path(__file__).resolve().parent / "models"
MODELS_DIR.mkdir(exist_ok=True)


def load_json_logs(data_dir=DATA_DIR):
    # Placeholder: iterate over JSON files and yield feature dicts
    for p in data_dir.glob('*.json'):
        with p.open() as f:
            for line in f:
                try:
                    yield json.loads(line)
                except Exception:
                    continue


def extract_features(record):
    # Placeholder feature extraction
    # Replace with domain-specific features from Cowrie logs
    return [record.get('duration', 0), record.get('bytes', 0)]


def train_model():
    X = [extract_features(r) for r in load_json_logs()]
    if not X:
        print('No training data found in', DATA_DIR)
        return
    clf = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    clf.fit(X)
    model_path = MODELS_DIR / 'isolation_forest.pkl'
    joblib.dump(clf, model_path)
    print('Saved model to', model_path)


if __name__ == '__main__':
    train_model()
