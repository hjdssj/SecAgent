# Demo Runbook

## Fast Demo

```powershell
docker compose up -d redis
python scripts\clear_redis.py
python scripts\publish_sample_logs.py
cd backend
python -m app.services.event_consumer
uvicorn app.main:app --reload --port 8000
```

Second terminal:

```powershell
cd frontend
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

## WAF Demo

```powershell
docker compose up -d redis waf
python scripts\clear_redis.py
python scripts\simulate_attack.py all
cd backend
python -m app.collector.waf_log_collector --from-start
python -m app.services.event_consumer
uvicorn app.main:app --reload --port 8000
```

Second terminal:

```powershell
cd frontend
npm run dev
```
