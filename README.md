# ThreatLens

ThreatLens is a phishing and threat intelligence monitoring platform.

## Project structure

- `frontend/` - UI and static web assets
- `backend/` - FastAPI backend services and routes
- `database/` - SQL schema and seed scripts

## Run backend

```bash
cd ThreatLens/backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```
