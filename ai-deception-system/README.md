# ai-deception-system

Repository skeleton for an AI-driven deception and detection platform.

Structure:

ai-deception-system/
│
├── deception_layer/             # Cowrie & Canary setup scripts
│   ├── cowrie_config/           # Custom Cowrie SSH configuration settings
│   ├── sample_logs/             # Raw captured log files (e.g., cowrie_sample.json)
│   └── canary_tokens/           # Webhook handlers and trigger configs
│
├── ml_engine/                   # Data processing & Machine Learning
│   ├── log_parser.py            # Extracts features (commands, failed logins, file events)
│   ├── model.py                 # Isolation Forest training and inference logic
│   └── trained_model.pkl        # Saved Isolation Forest model artifact (placeholder)
│
├── soc_dashboard/               # Security Operations Center UI
│   ├── app.py                   # Main Streamlit / Flask dashboard app
│   ├── components/              # UI widgets (alerts table, graphs, threat metrics)
│   └── database.sqlite          # Stores parsed events, alerts, and threat scores (placeholder)
│
├── tests/                       # Attack simulation & pipeline verification scripts
│   └── attack_simulator.py      # Automates simulated SSH logins & file drop triggers
│
├── requirements.txt             # Python dependencies (pandas, scikit-learn, streamlit)
└── README.md                    # Setup guide and internship documentation

Notes:
- These files are placeholders to help you get started. Replace with production-ready code and configs.
- Avoid committing large binary artifacts (trained models, DB files) directly to the repo in production; use external artifact storage.
