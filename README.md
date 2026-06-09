# SecRAG Agent

SecRAG Agent is a SOC-oriented security analysis and response demo system. It connects WAF logs, Redis Streams, rule-based attack detection, optional LLM fallback classification for rule-unknown attacks, local RAG security knowledge, threat intelligence, event memory, alert persistence, optional LLM report enhancement, and a React SOC console into one runnable pipeline.

## Highlights

- WAF integration with Nginx + ModSecurity + OWASP CRS.
- Single-server deployment profile with WAF reverse proxy, collector, consumer, backend, frontend, and Redis.
- Redis Stream event pipeline for `security:events` and `security:alerts`.
- Attack detection for SQL Injection, XSS, Path Traversal, Command Injection, scanners, and optional LLM-assisted Unknown fallback.
- RAG retrieval with structured documents, Query Rewrite, BM25, optional Milvus vector retrieval, citations, and scores.
- RAG knowledge-base management with document listing, Markdown upload, and a frontend Knowledge page.
- Enterprise context RAG and AutoTriage for business owner, asset criticality, and review routing.
- Optional OpenAI-compatible LLM report generation for high-value alerts.
- SQLite / SQLAlchemy alert persistence with workflow status updates.
- Local threat intelligence, Redis-backed source IP memory, and optional Milvus long-term analysis memory with similar-event recall.
- White-traffic control with collector-side benign filtering, suspicious `200` preservation, and time-window alert aggregation.
- FastAPI backend and React SOC dashboard.

## Architecture

```text
Attack traffic
  -> Nginx + ModSecurity WAF
  -> business-demo upstream service
  -> WAF audit log
  -> waf_log_collector.py
  -> benign traffic filtering / suspicious 200 preservation
  -> Redis Stream: security:events
  -> event_consumer.py
  -> LogParserAgent
  -> LLMUnknownAttackClassifier
  -> DecisionAgent
  -> RAGAgent
  -> Query Rewrite + HybridRetriever
  -> ContextAgent
  -> AutoTriagePolicy
  -> LongTermMemorySearch
  -> ThreatIntelAgent
  -> EventMemory
  -> LLMReportEnhancer
  -> LongTermMemoryStore
  -> event_id deduplication / alert aggregation
  -> Redis Stream: security:alerts
  -> DB: alerts
  -> FastAPI /api/alerts/recent
  -> React SOC Console
```

## Traffic Funnel and Noise Control

SecRAG Agent is designed to analyze WAF security events, not full web access traffic. In a real environment, normal business traffic is the majority, WAF-blocked attacks are a minority, and SOC-worthy alerts are an even smaller subset.

The runtime pipeline uses a funnel:

```text
Full HTTP traffic
  -> WAF / ModSecurity RelevantOnly audit logging
  -> Collector filtering
  -> Redis security events
  -> Rule analysis / optional RAG / optional LLM
  -> Aggregated SOC alerts
```

Collector-side filtering keeps clear benign traffic out of Redis by default:

```text
drop:
  health checks
  static assets
  normal 200 requests without rule hits or suspicious features

keep:
  WAF rule hits
  HTTP status >= 400
  suspicious User-Agent values such as sqlmap / nikto / nmap
  attack keywords in URL, query, message, or raw log
  sensitive-path interactions on /login, /admin, /api, /upload, /download, /search
```

The system does not assume `200` means benign. A direct-`200` attack can still be preserved when it touches sensitive paths, contains attack features, uses scanner-like User-Agent values, or matches suspicious behavior. The goal is not to analyze every `200`, but to route suspicious `200` traffic into `observe` or `analyze` paths while dropping ordinary white traffic.

Repeated alerts are aggregated in the database. By default, events with the same:

```text
source_ip + target + attack_type
```

within `ALERT_AGGREGATION_WINDOW_SECONDS=300` are merged into one alert with:

```text
event_count
event_ids
first_seen
last_seen
```

Late LLM enrichment for the same `event_id` updates the existing alert without increasing `event_count`. Repeated lower-risk events do not downgrade an existing high-risk aggregate.

## Tech Stack

```text
Backend: FastAPI, Pydantic, Redis, SQLAlchemy, SQLite
Collector: Python, ModSecurity JSON audit log parser
WAF: Nginx, ModSecurity, OWASP CRS
RAG: structured Markdown knowledge base, Query Rewrite, BM25, optional Milvus vector retrieval, HybridRetriever, citation output
LLM: optional OpenAI-compatible chat completions for Unknown fallback classification and analyst report enhancement
Frontend: React, TypeScript, Vite, lucide-react, react-markdown
Infrastructure: Docker Compose
```

## Single-Server Deployment

```powershell
docker compose -f docker-compose.prod.yml up -d --build
python scripts\deploy_check.py --skip-audit-log
```

The deployable profile starts a local `business-demo` upstream by default, so the WAF chain can run end to end on one machine:

```text
http://127.0.0.1:8080 -> WAF -> http://business-demo:3000
```

Before using it with a real service, replace the upstream configuration:

```text
WAF_PROXY_PASS=http://your-business-service
MODSEC_RULE_ENGINE=DetectionOnly
VITE_API_BASE_URL=http://YOUR_SERVER:8000
```

For local deployment, the compose profile in `docker-compose.prod.yml` is the source of truth.

## Quick Start

### 1. Start Redis and WAF

```powershell
docker compose up -d redis waf
```

### 2. Install backend dependencies

```powershell
cd backend
pip install -r requirements.txt
```

### 3. Generate sample alerts

From the project root:

```powershell
python scripts\clear_redis.py
python scripts\publish_sample_logs.py
cd backend
python -m app.services.event_consumer
```

### 4. Start backend API

From `backend/`:

```powershell
uvicorn app.main:app --reload --port 8000
```

### 5. Start frontend

From `frontend/`:

```powershell
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

## WAF Demo Flow

```powershell
docker compose up -d redis waf
python scripts\simulate_attack.py all
cd backend
python -m app.collector.waf_log_collector --from-start
python -m app.services.event_consumer
```

Then query:

```text
http://127.0.0.1:8000/docs
GET /api/alerts/recent
```

Or view:

```text
http://127.0.0.1:5173
```

## API

```text
GET  /api/health
POST /api/analyze
GET  /api/analysis/{session_id}/result
POST /api/analysis/{session_id}/ask
GET  /api/alerts/recent?count=20&risk_level=critical&status=needs_review&requires_human_review=true
PATCH /api/alerts/{alert_id}/status
GET  /api/knowledge/documents
GET  /api/knowledge/documents/{source}
POST /api/knowledge/documents
POST /api/knowledge/documents/upload
```

## Project Structure

```text
backend/app/
  analysis/     # cost-control modes, score breakdown, analysis metadata
  agents/       # log parser, decision, orchestration
  api/          # FastAPI routes
  collector/    # sample and WAF log parsers
  context/      # enterprise context retrieval for auto triage
  data/         # local knowledge and threat intelligence
  db/           # SQLAlchemy session, ORM models, database initialization
  intel/        # threat intelligence agent
  llm/          # optional OpenAI-compatible Unknown fallback and report enhancement
  memory/       # Redis-backed event/session memory and optional long-term memory
  models/       # Pydantic event and alert models
  rag/          # structured RAG retrieval, BM25, hybrid retrieval, query rewrite
                # and local knowledge document upload helpers
  embedding/    # optional OpenAI-compatible embedding client
  milvus/       # optional Milvus vector storage helpers
  repositories/ # database persistence repositories
  services/     # Redis event consumer
  storage/      # Redis helpers
  triage/       # auto triage policy and workflow status schemas

frontend/
  src/          # React SOC console

infra/waf/      # WAF image and Nginx template
infra/business-demo/ # local upstream service protected by WAF for demos
docker-compose.prod.yml # single-server deployment profile
scripts/        # demo and utility scripts
tests/          # focused backend tests
```

## Verification

```powershell
python -m compileall backend\app
pytest
cd frontend
npm run build
```

## Optional Milvus Vector Retrieval

By default, SecAgent runs with BM25 retrieval only and does not write long-term analysis memories. To enable Milvus-backed vector retrieval, configure embedding and Milvus settings:

```text
EMBEDDING_ENABLED=true
EMBEDDING_PROVIDER=dashscope
EMBEDDING_MODEL=text-embedding-v4
EMBEDDING_API_KEY=your-key
EMBEDDING_DIMENSION=1024
MILVUS_ENABLED=true
MILVUS_HOST=localhost
MILVUS_PORT=19530
MILVUS_KNOWLEDGE_COLLECTION=secagent_knowledge_chunks
MILVUS_MEMORY_COLLECTION=secagent_analysis_memory
```

Then rebuild the knowledge vector index:

```powershell
python scripts\rebuild_knowledge_vectors.py --recreate
```

If Milvus or embedding is unavailable, `HybridRetriever` automatically falls back to BM25.

Markdown documents can be added from the frontend `Knowledge` page or through `/api/knowledge/documents`. Uploaded documents are written to `backend/app/data/knowledge_base/`. BM25 retrieval becomes available in the current API process after the RAG cache refresh; Milvus vector retrieval still requires rebuilding the vector index with `scripts/rebuild_knowledge_vectors.py --recreate`.

Optional long-term analysis memory can also use Milvus. It stores high-value alert summaries for future similar-event retrieval, while SQLite remains the source of truth for alert status and analyst notes:

```text
LONG_TERM_MEMORY_ENABLED=true
LONG_TERM_MEMORY_SEARCH_ENABLED=true
LONG_TERM_MEMORY_MIN_RISK_LEVEL=high
LONG_TERM_MEMORY_WRITE_AUTO_CLOSED=false
LONG_TERM_MEMORY_REQUIRE_ANALYST_NOTE=false
```

When enabled, `enriched` and `deep` analyses can retrieve similar historical events from `secagent_analysis_memory` and append them to evidence and `report_markdown`. When disabled, below threshold, or when embedding/Milvus is unavailable, analysis still completes and records skipped workflow steps.

## Current Status

The project has completed the MVP stages:

```text
1. Single-event backend analysis
2. Sample log replay
3. Redis Stream event pipeline
4. Real WAF log ingestion
5. RAG security knowledge enrichment
6. Threat intelligence and event memory
7. React SOC dashboard
8. Documentation, tests, and demo packaging
9. Real RAG upgrade with BM25, HybridRetriever, Query Rewrite, citations, and retrieval tests
10. Cost-controlled analysis modes with risk score breakdown and frontend explanation
11. Enterprise context RAG and AutoTriage for business-aware alert routing
12. Alert persistence and status updates for SOC lifecycle closure
13. Single-server deployable WAF reverse-proxy profile with local business-demo upstream
14. Optional LLM analyst report enhancement with cost-control policy and fallback behavior
15. Optional LLM fallback classification for rule-unknown attacks
16. Redis-backed AnalysisState follow-up context and LLM follow-up Q&A
17. Optional Milvus vector retrieval for knowledge-base RAG
18. Optional Milvus long-term analysis memory write path
19. Similar historical event recall from Milvus long-term memory
20. RAG knowledge-base document upload API and frontend Knowledge page
21. Collector-side white-traffic filtering, suspicious `200` preservation, and alert aggregation for SOC noise control
```
