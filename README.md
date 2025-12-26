# HomeSOC (local mini-SIEM)
HomeSOC is a local-first SOC-style log pipeline:
- ingest Linux auth logs
- normalize to a single schema (SQLite)
- run Sigma-inspired YAML detection rules
- generate MITRE-mapped alerts
- triage workflow: status + analyst notes + evidence

## Demo (60 seconds)
1) Load sample logs
2) Run rules
3) Open Alerts and click an alert to see evidence

## Run locally
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
