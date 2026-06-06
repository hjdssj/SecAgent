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
  -> RAGAgent
  -> ThreatIntelAgent
  -> EventMemory
  -> Context judgment
  -> SecurityAlert
```

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

The current RAG layer is a lightweight local retriever. It is intentionally small and stable for demo usage, and can later be replaced with LlamaIndex + Milvus.

## Threat Intelligence

```text
backend/app/data/intel/threat_ip_mock.json
```

The first version uses local mock intelligence to avoid external API instability during demos.
