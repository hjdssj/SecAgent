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
  -> data/waf_logs/modsecurity/audit/audit.log
  -> backend/app/collector/waf_log_collector.py
  -> SecurityEvent
  -> Redis Stream: security:events
  -> backend/app/services/event_consumer.py
  -> SecurityAnalysisOrchestrator
  -> SecurityAlert
  -> Redis Stream: security:alerts
  -> GET /api/alerts/recent
  -> frontend SOC console
```

## Agent Pipeline

```text
SecurityEvent
  -> LogParserAgent
  -> ParsedSecurityEvent
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
  -> Context judgment
  -> SecurityAlert
```

## Cost-Control Analysis Modes

```text
fast
  -> LogParserAgent
  -> DecisionAgent
  -> skip RAG, ThreatIntel, and Memory

enriched
  -> LogParserAgent
  -> DecisionAgent
  -> RAGAgent
  -> EventMemory
  -> skip ThreatIntel

deep
  -> LogParserAgent
  -> DecisionAgent
  -> RAGAgent
  -> ThreatIntelAgent
  -> EventMemory
```

Each alert includes `analysis_mode`, `score_breakdown`, and `analysis_metadata`. This keeps the SOC workflow cost-aware: low-risk events use the fast path, medium-risk events receive local RAG and memory context, and high-risk events trigger the full enrichment path.

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

## Knowledge Sources

```text
backend/app/data/knowledge_base/
  attack_patterns.md
  mitre_attack.md
  owasp_crs.md
  remediation.md
  cve_examples.md
```

The RAG layer loads local Markdown documents as structured `KnowledgeDocument` and `KnowledgeChunk` objects. `SecurityQueryRewriter` expands parsed attack context with WAF rule IDs, attack features, MITRE terms, and remediation terms. `HybridRetriever` currently uses BM25 retrieval and keeps a replaceable vector retrieval interface for future BGE + Milvus integration. Alerts include knowledge citations, retrieval scores, and match reasons.

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
