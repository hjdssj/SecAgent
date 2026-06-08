# Architecture

## Overview

SecRAG Agent is organized around a real-time security event pipeline.

```text
Attack traffic
  -> WAF
  -> Collector
  -> Redis Streams
  -> Agent pipeline
  -> Alert API
  -> SOC Console
```

## Runtime Flow

```text
Nginx + ModSecurity + OWASP CRS
  -> reverse proxy to WAF_PROXY_PASS
  -> data/waf_logs/modsecurity/audit/audit.log
  -> backend/app/collector/waf_log_collector.py
  -> SecurityEvent
  -> Redis Stream: security:events
  -> backend/app/services/event_consumer.py
  -> SecurityAnalysisOrchestrator
  -> SecurityAlert
  -> Redis Stream: security:alerts
  -> DB: alerts
  -> GET /api/alerts/recent
  -> frontend SOC console
```

## Single-Server Deployment

The deployment profile is defined in `docker-compose.prod.yml` and includes:

```text
redis
waf
backend
frontend
collector
consumer
```

The WAF container uses `infra/waf/default.conf` as an environment-rendered Nginx template. `WAF_PROXY_PASS` points to the protected business service, and `/__waf_health` remains available as a lightweight health check.

```text
User traffic
  -> WAF
  -> WAF_PROXY_PASS
  -> WAF audit log
  -> collector --follow
  -> Redis security:events
  -> consumer --follow
  -> DB alerts table
```

Deployment details are documented in `docs/deployment.md`.

## Agent Pipeline

```text
SecurityEvent
  -> LogParserAgent
  -> ParsedSecurityEvent
  -> LLMUnknownAttackClassifier
  -> DecisionAgent
  -> AnalysisPolicy
  -> fast / enriched / deep
  -> RAGAgent
  -> Query Rewrite
  -> HybridRetriever
  -> BM25Retriever
  -> VectorRetriever interface
  -> ThreatIntelAgent
  -> EventMemory
  -> ContextAgent
  -> AutoTriagePolicy
  -> LongTermMemorySearch
  -> LLMReportEnhancer
  -> Context judgment
  -> LongTermMemoryStore write
  -> SecurityAlert
```

## Cost-Control Analysis Modes

```text
fast
  -> LogParserAgent
  -> LLMUnknownAttackClassifier only when attack_type is Unknown and enabled
  -> DecisionAgent
  -> skip RAG, ThreatIntel, and Memory

enriched
  -> LogParserAgent
  -> LLMUnknownAttackClassifier only when attack_type is Unknown and enabled
  -> DecisionAgent
  -> RAGAgent
  -> EventMemory
  -> LongTermMemorySearch when enabled and above threshold
  -> skip ThreatIntel

deep
  -> LogParserAgent
  -> LLMUnknownAttackClassifier only when attack_type is Unknown and enabled
  -> DecisionAgent
  -> RAGAgent
  -> ThreatIntelAgent
  -> EventMemory
  -> LongTermMemorySearch when enabled and above threshold
```

Before decision scoring, `LLMUnknownAttackClassifier` may classify only events whose rule result is `Unknown`. It is disabled by default and requires `LLM_ENABLED=true` plus `LLM_UNKNOWN_CLASSIFIER_ENABLED=true`. A result is accepted only when the model returns a supported attack type and confidence is above `LLM_UNKNOWN_CLASSIFIER_MIN_CONFIDENCE`.

After deterministic analysis, `LLMReportEnhancer` may generate an analyst-facing Markdown report section. Report enhancement is controlled by environment configuration and alert policy; it does not change `attack_type`, `risk_score`, `risk_level`, or `confidence`.

Each alert includes `analysis_mode`, `score_breakdown`, and `analysis_metadata`. This keeps the SOC workflow cost-aware: low-risk events use the fast path, medium-risk events receive local RAG and memory context, and high-risk events trigger the full enrichment path.

## LLM Unknown Fallback

```text
ParsedSecurityEvent attack_type=Unknown
  -> LLMUnknownAttackClassifier
  -> OpenAICompatibleLLMClient
  -> supported attack type / confidence / evidence
  -> DecisionAgent scoring
```

The fallback classifier is intentionally narrow:

```text
only runs for Unknown events
disabled by default
requires LLM_ENABLED=true
requires LLM_UNKNOWN_CLASSIFIER_ENABLED=true
requires provider credentials
accepts only supported attack types
rejects low-confidence results
records failures as evidence without breaking analysis
```

Supported fallback labels:

```text
SQL Injection
XSS
Path Traversal
Command Injection
SSRF
Brute Force
File Upload
Authentication Bypass
Automated Scanner
```

## LLM Report Enhancement

```text
SecurityAlert
  -> LLMCallPolicy
  -> LLMReportPromptBuilder
  -> OpenAICompatibleLLMClient
  -> llm_summary / LLM Markdown section / token metadata
```

The LLM module lives in:

```text
backend/app/llm/
  config.py
  policy.py
  prompt_builder.py
  client.py
  unknown_attack_classifier.py
  report_enhancer.py
  schemas.py
```

Default behavior:

```text
LLM_ENABLED=false
```

When enabled, the policy checks:

```text
LLM_API_KEY or DASHSCOPE_API_KEY
LLM_BASE_URL or DASHSCOPE_BASE_URL
LLM_UNKNOWN_CLASSIFIER_ENABLED
LLM_UNKNOWN_CLASSIFIER_MIN_CONFIDENCE
LLM_ONLY_FOR_REVIEW
LLM_MIN_RISK_LEVEL
requires_human_review
risk_level
```

Failures are recorded in `llm_error` and the deterministic report remains available.

## Redis Streams

```text
security:events      # normalized security events waiting for analysis
security:alerts      # generated security alerts
security:deadletter  # reserved for failed events
```

Memory keys:

```text
memory:ip:{source_ip}
memory:ip:{source_ip}:attack_types
memory:ip:{source_ip}:targets
memory:ip:{source_ip}:alerts
```

Redis is responsible for real-time transport, short-term memory, and cache-style data. Alert lifecycle state is persisted in the relational database.

## Long-Term Memory

SecAgent has an optional Milvus-backed long-term memory layer for high-value analysis results and similar historical event recall.

```text
SecurityAlert + AnalysisState
  -> LongTermMemoryPolicy
  -> LongTermMemoryBuilder
  -> EmbeddingClient
  -> Milvus: secagent_analysis_memory

Current SecurityAlert + AnalysisState
  -> LongTermMemoryPolicy
  -> LongTermMemoryBuilder.search_text()
  -> EmbeddingClient
  -> Milvus: secagent_analysis_memory
  -> similar historical events
  -> evidence / report_markdown
```

This layer is disabled by default:

```text
LONG_TERM_MEMORY_ENABLED=false
LONG_TERM_MEMORY_SEARCH_ENABLED=false
```

When enabled, it writes compact semantic summaries for alerts that pass policy checks. The current policy can skip:

```text
low / medium alerts below LONG_TERM_MEMORY_MIN_RISK_LEVEL
auto-closed alerts when LONG_TERM_MEMORY_WRITE_AUTO_CLOSED=false
alerts without analyst_note when LONG_TERM_MEMORY_REQUIRE_ANALYST_NOTE=true
```

Milvus remains a semantic retrieval store, not the source of truth. SQLite / SQLAlchemy remains responsible for alert status, analyst notes, handler identity, and handled timestamps. If embedding or Milvus is unavailable, the main analysis path continues and records a skipped `long_term_memory` workflow step.

When `LONG_TERM_MEMORY_SEARCH_ENABLED=true`, enriched and deep analyses search for similar historical memories after AutoTriage and before optional LLM report generation. Matched memories are appended to alert evidence and the Markdown report under `长期记忆相似事件`. This does not change attack type, risk score, risk level, or workflow status.

## Alert Persistence

```text
backend/app/db/
  session.py
  models.py
  init_db.py

backend/app/repositories/
  alert_repository.py
```

The default local database is SQLite at `data/secagent.db`. The backend also supports `DATABASE_URL`, so the same repository layer can later point to MySQL or PostgreSQL.

The `alerts` table stores:

```text
alert core fields
RAG and analysis metadata
AutoTriage result
LLM report metadata
workflow status
analyst note
handled_by
handled_at
created_at / updated_at
```

The current lifecycle API is intentionally small:

```text
GET /api/alerts/recent
PATCH /api/alerts/{alert_id}/status
```

## Knowledge Sources

```text
backend/app/data/knowledge_base/
  attack_patterns.md
  mitre_attack.md
  owasp_crs.md
  remediation.md
  cve_examples.md
```

The RAG layer loads local Markdown documents as structured `KnowledgeDocument` and `KnowledgeChunk` objects. `SecurityQueryRewriter` expands parsed attack context with WAF rule IDs, attack features, MITRE terms, and remediation terms. `HybridRetriever` combines BM25 retrieval with optional Milvus vector retrieval. When Milvus or embedding is unavailable, vector retrieval returns no results and BM25 continues to work. Alerts include knowledge citations, retrieval scores, and match reasons.

Optional vector index rebuild:

```powershell
python scripts\rebuild_knowledge_vectors.py --recreate
```

Milvus knowledge collection:

```text
secagent_knowledge_chunks
```

Milvus long-term memory collection:

```text
secagent_analysis_memory
```

## Enterprise Context

```text
backend/app/data/context/
  asset_inventory.md
  service_owners.md
  scanner_whitelist.md
  waf_policy.md
  incident_playbook.md
  change_calendar.md
```

`ContextAgent` retrieves enterprise context for source IP, target path, WAF rule, and attack type. It extracts business owner, asset name, asset criticality, scanner whitelist matches, WAF action, and change-window context.

`AutoTriagePolicy` then assigns workflow fields:

```text
status
automation_decision
triage_reason
requires_human_review
context_references
```

This allows low-risk internal scanner alerts to be auto-triaged while high-risk alerts against critical assets are routed to human review.

## Threat Intelligence

```text
backend/app/data/intel/threat_ip_mock.json
```

The first version uses local mock intelligence to avoid external API instability during demos.
