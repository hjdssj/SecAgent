# Single-Server Deployment

This guide describes the stage 13 deployment target: run SecAgent on one server with WAF, Redis, backend, frontend, collector, and consumer.

## Runtime Architecture

```text
User traffic
  -> WAF: Nginx + ModSecurity + OWASP CRS
  -> WAF_PROXY_PASS business service
  -> business-demo by default for local validation
  -> ModSecurity audit.log
  -> collector
  -> Redis security:events
  -> consumer
  -> Redis security:alerts
  -> DB alerts table
  -> FastAPI backend
  -> React SOC console
```

## Required Configuration

Edit `.env` before deployment:

```text
WAF_PROXY_PASS=http://business-demo:3000
MODSEC_RULE_ENGINE=DetectionOnly
VITE_API_BASE_URL=http://SERVER_IP:8000
BACKEND_CORS_ORIGINS=http://SERVER_IP:5173,http://127.0.0.1:5173
```

The default `WAF_PROXY_PASS` points to the bundled `business-demo` service. When protecting a real service, change it to that service's address and use `DetectionOnly` first. Switch to `on` only after reviewing false positives.

## Services

```text
redis      - Redis Stream, memory, cache
business-demo - local upstream service used to validate WAF proxying
waf        - reverse proxy WAF
backend    - FastAPI API service
frontend   - built React SOC console served by Nginx
collector  - follows ModSecurity audit log and publishes SecurityEvent objects
consumer   - follows Redis Stream and generates persisted alerts
```

## Start

```powershell
docker compose -f docker-compose.prod.yml up -d --build
```

## Verify

```powershell
python scripts\deploy_check.py
```

If the WAF has not generated `audit.log` yet, run:

```powershell
python scripts\deploy_check.py --skip-audit-log
```

Service URLs:

```text
WAF health:      http://127.0.0.1:8080/__waf_health
WAF proxy:       http://127.0.0.1:8080/
Business demo:   http://127.0.0.1:3000/
Backend health:  http://127.0.0.1:8000/api/health
Frontend:        http://127.0.0.1:5173
```

## Generate Demo Traffic

```powershell
python scripts\simulate_attack.py all
```

Then wait for collector and consumer, and open:

```text
http://127.0.0.1:5173
```

## Important Environment Variables

```text
WAF_PROXY_PASS - upstream business service protected by WAF
BUSINESS_DEMO_PORT - host port for the bundled local upstream service
MODSEC_RULE_ENGINE - DetectionOnly or on
WAF_AUDIT_LOG_PATH - host-side audit log path for collector
REDIS_HOST - Redis host, set to redis inside docker-compose.prod.yml
SECAGENT_DB_PATH - SQLite database path
VITE_API_BASE_URL - backend API URL compiled into frontend
```

## Switch WAF Mode

Detection only:

```text
MODSEC_RULE_ENGINE=DetectionOnly
```

Blocking mode:

```text
MODSEC_RULE_ENGINE=on
```

Restart WAF after changing mode:

```powershell
docker compose -f docker-compose.prod.yml up -d --build waf
```

## Logs

WAF logs:

```text
data/waf_logs/nginx/
data/waf_logs/modsecurity/audit/audit.log
```

Collector offset:

```text
data/waf_logs/.collector.offset
```

Runtime database:

```text
data/secagent.db
```

## Replace The Demo Upstream

For a real business service on the same host:

```text
WAF_PROXY_PASS=http://host.docker.internal:3000
```

For a service on another server or container network:

```text
WAF_PROXY_PASS=http://YOUR_BUSINESS_HOST:PORT
```

After changing `.env`, restart the WAF:

```powershell
docker compose -f docker-compose.prod.yml up -d --build waf
```

## Stop

```powershell
docker compose -f docker-compose.prod.yml down
```
