# Troubleshooting

## Docker cannot pull WAF image

Symptom:

```text
failed to fetch oauth token
failed to connect to docker.io
```

Fix:

```text
Check Docker Desktop network/proxy settings.
Retry docker compose up -d waf.
Use sample log demo when network is unstable.
```

## Redis connection failed

Start Redis:

```powershell
docker compose up -d redis
```

Check:

```powershell
docker exec secrag-redis redis-cli PING
```

Expected:

```text
PONG
```

## WAF log is empty

Check WAF container:

```powershell
docker ps
docker logs secrag-waf --tail 100
```

Send demo traffic:

```powershell
python scripts\simulate_attack.py all
```

Check logs:

```powershell
Get-ChildItem data\waf_logs -Recurse
```

## Frontend CORS error

Backend must run on:

```text
http://127.0.0.1:8000
```

Frontend must run on:

```text
http://127.0.0.1:5173
```

`backend/app/main.py` already allows:

```text
http://127.0.0.1:5173
http://localhost:5173
```

## PowerShell shows garbled Chinese

The API and browser usually render UTF-8 correctly. If PowerShell output looks garbled, verify in Swagger or the React frontend.

Useful checks:

```text
http://127.0.0.1:8000/docs
http://127.0.0.1:5173
```

## Frontend has no alerts

Generate alerts:

```powershell
python scripts\clear_redis.py
python scripts\publish_sample_logs.py
cd backend
python -m app.services.event_consumer
```

Then refresh:

```text
http://127.0.0.1:5173
```
