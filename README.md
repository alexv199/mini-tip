# Mini Threat-Intelligence Platform (Python + Flask)

A small learning-oriented Threat Intelligence Platform that periodically downloads public threat feeds (URLhaus URLs, Spamhaus DROP/EDROP CIDRs), stores them in SQLite, and exposes a simple web UI and JSON API for searching indicators.

## Features
- Scheduled ingestion of URLhaus (malicious URLs) and Spamhaus (CIDR blocklists)
- SQLite storage with idempotent UPSERTs
- Searchable web UI built with Flask
- REST API endpoint for programmatic access
- Manual refresh trigger
- CI-ready structure

## Stack
- Python 3.10+
- Flask web framework
- SQLite database
- APScheduler for background jobs
- requests library for HTTP fetching
- HTML/CSS (vanilla) for UI

## Quickstart
```bash
# Clone repository
git clone https://github.com/<your-username>/mini-tip.git
cd mini-tip

# Create virtual environment & install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Initialize database
python init_db.py

# Run application
python app.py
