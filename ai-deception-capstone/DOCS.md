# AI Deception Capstone — Documentation

This document summarizes how to run, test, and extend the AI-Deception System demo (safe, local-only defaults).

## Overview

Components (local/demo):
- `ml_engine` — ingestion and analysis. For the demo, `ml_engine/ingest_simulator.py` converts raw events to `data/processed_threat_feed.json` (heuristic). A full model lives in `ml_engine/threat_model.py`.
- `deception_layer/honeypot` — safe honeypot simulator `honeypot_sim.py` that writes JSONL events to `ml_engine/data/raw_honeypot_events.jsonl` (10% chance of canary trigger).
- `docker-compose.yml` — orchestrates a demo stack (simulator and ingestion). The compose file is configured for local demos, not production.

## Quickstart — Local (no Docker required)

1. Run the simulator once (or use the loop):

```powershell
cd ai-deception-capstone
python deception_layer/honeypot/honeypot_sim.py  # single event
# or looped
./start-honeypot.ps1
```

2. Convert raw events to processed feed:

```powershell
./run-ingest.ps1
# or
python ml_engine/ingest_simulator.py
```

## Quickstart — Docker (requires Docker & Compose)

```bash
cd ai-deception-capstone
docker-compose up --build -d
docker-compose ps
docker-compose logs --tail=50 --follow ml_engine
```

Notes:
- The `ml_engine` image runs `ingest_simulator.py` repeatedly and writes `data/processed_threat_feed.json` to the mounted `./ml_engine/data`.
- `cowrie-honeypot` runs the safe simulator and writes to the mounted `./ml_engine/data` path.

## Important files

- `ml_engine/ingest_simulator.py` — heuristic ingestion converting `raw_honeypot_events.jsonl` → `processed_threat_feed.json`.
- `deception_layer/honeypot/honeypot_sim.py` — safe local simulator that appends JSON lines to the raw log.
- `docker-compose.yml` — demo compose orchestrating services and mounts.

## Running tests & verification

Manual verification steps performed during development:
- Start `py_server.py` and confirm root and `/api/alerts` respond.
- Run simulator and run ingest; confirm `ml_engine/data/processed_threat_feed.json` updates.
- Use `curl` or browser to view `http://localhost:3000` and verify UI elements reflect the feed.

Automated checks you can add:
- Simple healthchecks or curl-based scripts that assert `/api/stats` returns expected JSON keys.
- Unit tests for `ml_engine/log_parser.py` and `threat_model.py` using pytest and sample CSV/JSON fixtures.

## Security & Safety

- This project uses synthetic data and an intentionally lightweight simulator — do not deploy the simulator to production or expose it to the Internet.
- If you replace the simulator with a real honeypot (e.g., Cowrie), ensure network isolation, legal compliance, and secure log handling.

## Troubleshooting

- `docker-compose` missing: install Docker Desktop (Windows) or the Docker Engine + Compose plugin.
- Port 3000 already in use: stop the process or change the port in `dashboard/py_server.py` and `docker-compose.yml`.
- If `processed_threat_feed.json` is not present: run the ingestion script manually (`python ml_engine/ingest_simulator.py`) and check `ml_engine/data` permissions.

## Next steps / Extensions

- Replace `ingest_simulator.py` with real `threat_model.py` pipeline after training a model.
- Add integration tests, CI pipeline, and a small webserver health-check endpoint for all services.
- Expand the dashboard UI with role-based access, alert acknowledgment, and export features.

---

If you want, I can also add a `CONTRIBUTING.md`, or generate a simple `requirements.txt` / `pyproject.toml` to pin interpreter dependencies.
