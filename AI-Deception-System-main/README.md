# AI-Deception-System

This repository contains a skeleton for an AI-driven deception platform used for setting up honeypots (Cowrie), generating canary tokens, running an ML anomaly detection engine, and a simple dashboard.

Structure created:

ai-deception-capstone/
├── deception_layer/          
│   ├── honeypot/             # Dockerized Cowrie SSH trap
│   │   ├── Dockerfile
│   │   └── cowrie.cfg
│   └── canary_tokens/        # Script to generate decoy files
│       └── generate_token.py
├── ml_engine/                # AI Anomaly Detection
│   ├── data/                 # Raw JSON logs from honeypot
│   ├── models/               # Saved Isolation Forest pickle files
│   └── threat_model.py       # Scikit-learn training logic
├── dashboard/                # Analyst UI (Simulated below)
│   └── app.js                # React/Streamlit frontend
└── docker-compose.yml        # Orchestration

Notes:
- The files are placeholders to help you get started. Replace with production-ready configs and code.
- To build and run the honeypot, replace the Dockerfile/cowrie.cfg with Cowrie's official configuration and build steps.
