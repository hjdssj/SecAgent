# SecRAG Agent

SecRAG Agent is a SOC-oriented security analysis and response demo system. It connects WAF logs, Redis Streams, rule-based attack detection, local RAG security knowledge, threat intelligence, event memory, and a React SOC console into one runnable pipeline.

## Highlights

- WAF integration with Nginx + ModSecurity + OWASP CRS.
- Redis Stream event pipeline for `security:events` and `security:alerts`.
- Attack detection for SQL Injection, XSS, Path Traversal, Command Injection, and scanners.
- RAG retrieval with structured documents, Query Rewrite, BM25, hybrid retrieval hooks, citations, and scores.
- Enterprise context RAG and AutoTriage for business owner, asset criticality, and review routing.
- Local threat intelligence and Redis-backed source IP memory.
- FastAPI backend and React SOC dashboard.

## Architecture

```text
Attack traffic
  -> Nginx + ModSecurity WAF
  -> WAF audit log
  -> waf_log_collector.py
  -> Redis Stream: security:events
  -> event_consumer.py
  -> LogParserAgent
  -> DecisionAgent
  -> RAGAgent
  -> Query Rewrite + HybridRetriever
  -> ContextAgent
  -> AutoTriagePolicy
  -> ThreatIntelAgent
  -> EventMemory
  -> Redis Stream: security:alerts
  -> FastAPI /api/alerts/recent
  -> React SOC Console
```

## Tech Stack

```text
Backend: FastAPI, Pydantic, Redis
Collector: Python, ModSecurity JSON audit log parser
WAF: Nginx, ModSecurity, OWASP CRS
RAG: structured Markdown knowledge base, Query Rewrite, BM25, HybridRetriever, citation output
Frontend: React, TypeScript, Vite, lucide-react, react-markdown
Infrastructure: Docker Compose
```

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
GET  /api/alerts/recent?count=20
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
  intel/        # threat intelligence agent
  memory/       # Redis-backed event memory
  models/       # Pydantic event and alert models
  rag/          # structured RAG retrieval, BM25, hybrid retrieval, query rewrite
  services/     # Redis event consumer
  storage/      # Redis helpers
  triage/       # auto triage policy and workflow status schemas

frontend/
  src/          # React SOC console

infra/waf/      # WAF image and Nginx template
scripts/        # demo and utility scripts
docs/           # architecture, demo, API, troubleshooting
tests/          # focused backend tests
```

## Verification

```powershell
python -m compileall backend\app
pytest
cd frontend
npm run build
```

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
```
