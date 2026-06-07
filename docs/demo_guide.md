# Demo Guide

## Goal

Run a full demo from traffic generation to SOC dashboard alert display.

## Option A: Sample Log Demo

Use this when you want a fast and stable demo without depending on WAF traffic.

```powershell
docker compose up -d redis
python scripts\clear_redis.py
python scripts\publish_sample_logs.py
cd backend
python -m app.services.event_consumer
uvicorn app.main:app --reload --port 8000
```

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

## Option B: WAF Log Demo

Use this when you want to show real WAF log ingestion.

```powershell
docker compose up -d redis waf
python scripts\clear_redis.py
python scripts\simulate_attack.py all
cd backend
python -m app.collector.waf_log_collector --from-start
python -m app.services.event_consumer
uvicorn app.main:app --reload --port 8000
```

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

## Expected Alert Types

```text
SQL Injection -> critical
XSS -> high / critical depending on context
Path Traversal -> high / critical depending on context
Unknown / normal request -> low
```

## Useful Checks

```powershell
docker exec secrag-redis redis-cli XLEN security:events
docker exec secrag-redis redis-cli XLEN security:alerts
```

```text
http://127.0.0.1:8000/docs
GET /api/alerts/recent
```

## Option C: Single-Server Compose Demo

Use this when you want to run the deployable profile. This starts the bundled `business-demo` service, so no external business server is required.

```powershell
docker compose -f docker-compose.prod.yml up -d --build
python scripts\deploy_check.py --skip-audit-log
python scripts\simulate_attack.py all
python scripts\deploy_check.py
```

Open:

```text
http://127.0.0.1:5173
```

Notes:

```text
Default traffic path: http://127.0.0.1:8080 -> WAF -> business-demo:3000.
Set WAF_PROXY_PASS before protecting a real service.
Start with MODSEC_RULE_ENGINE=DetectionOnly for real business traffic.
```
