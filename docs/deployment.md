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
WAF_COLLECTOR_IGNORED_PATHS - comma-separated request paths ignored before publishing to Redis, default /__waf_health
REDIS_HOST - Redis host, set to redis inside docker-compose.prod.yml
SECAGENT_DB_PATH - SQLite database path
VITE_API_BASE_URL - backend API URL compiled into frontend
LLM_ENABLED - enable optional LLM report enhancement
LLM_BASE_URL - OpenAI-compatible base URL, DashScope compatible mode is supported
LLM_API_KEY - LLM API key, keep this in .env only
LLM_MODEL - chat completion model name
LLM_UNKNOWN_CLASSIFIER_ENABLED - enable LLM fallback classification only for rule-unknown attacks
LLM_UNKNOWN_CLASSIFIER_MIN_CONFIDENCE - minimum confidence required to accept an LLM fallback classification
LLM_ONLY_FOR_REVIEW - only call LLM for alerts requiring human review
LLM_MIN_RISK_LEVEL - minimum risk level that can trigger LLM
EMBEDDING_ENABLED - enable embedding calls for optional Milvus vector retrieval
EMBEDDING_MODEL - embedding model name, for example text-embedding-v4
EMBEDDING_API_KEY - embedding API key, can reuse DashScope credentials
EMBEDDING_DIMENSION - embedding vector dimension expected by Milvus
MILVUS_ENABLED - enable optional Milvus vector retrieval
MILVUS_HOST - Milvus host
MILVUS_PORT - Milvus port
MILVUS_KNOWLEDGE_COLLECTION - collection for knowledge-base chunks
MILVUS_MEMORY_COLLECTION - collection for optional long-term analysis memory
LONG_TERM_MEMORY_ENABLED - enable optional Milvus long-term analysis memory writes
LONG_TERM_MEMORY_SEARCH_ENABLED - enable similar historical memory recall during enriched/deep analysis
LONG_TERM_MEMORY_MIN_RISK_LEVEL - minimum risk level written to long-term memory
LONG_TERM_MEMORY_WRITE_AUTO_CLOSED - whether auto-closed alerts can be written
LONG_TERM_MEMORY_REQUIRE_ANALYST_NOTE - require analyst_note before memory write
```

## Optional Milvus Vector Retrieval

Milvus is optional. When `MILVUS_ENABLED=false`, SecAgent keeps using BM25 retrieval and the analysis pipeline is unchanged.

To enable vector retrieval:

```text
EMBEDDING_ENABLED=true
EMBEDDING_API_KEY=your-key
MILVUS_ENABLED=true
MILVUS_HOST=localhost
MILVUS_PORT=19530
```

Rebuild knowledge vectors after changing Markdown files:

```powershell
python scripts\rebuild_knowledge_vectors.py --recreate
```

The rebuild script reads `backend/app/data/knowledge_base/*.md`, embeds each `KnowledgeChunk`, and writes vectors to `MILVUS_KNOWLEDGE_COLLECTION`.

## Optional Long-Term Analysis Memory

Long-term memory is optional and disabled by default. It writes compact alert analysis summaries to Milvus after the deterministic alert has already been generated.

```text
LONG_TERM_MEMORY_ENABLED=false
LONG_TERM_MEMORY_SEARCH_ENABLED=false
LONG_TERM_MEMORY_MIN_RISK_LEVEL=high
LONG_TERM_MEMORY_WRITE_AUTO_CLOSED=false
LONG_TERM_MEMORY_REQUIRE_ANALYST_NOTE=false
MILVUS_MEMORY_COLLECTION=secagent_analysis_memory
```

To enable it, embedding and Milvus must also be enabled:

```text
EMBEDDING_ENABLED=true
EMBEDDING_API_KEY=your-key
MILVUS_ENABLED=true
LONG_TERM_MEMORY_ENABLED=true
LONG_TERM_MEMORY_SEARCH_ENABLED=true
```

When search is enabled, enriched and deep analyses can append similar historical memories to evidence and `report_markdown`. If embedding or Milvus is unavailable, SecAgent still generates alerts normally and records the skipped reason in the analysis workflow.

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

Default collector noise filter:

```text
WAF_COLLECTOR_IGNORED_PATHS=/__waf_health
```

This keeps WAF health probes out of `security:events`, Memory, persisted alerts, and the SOC console.

To preview old persisted health-check alerts:

```powershell
python scripts\cleanup_health_alerts.py
```

To delete the previewed alerts:

```powershell
python scripts\cleanup_health_alerts.py --apply
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
