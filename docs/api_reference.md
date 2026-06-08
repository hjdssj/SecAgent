# API Reference

## GET /api/health

Check backend health.

Response:

```json
{
  "status": "ok",
  "message": "SecRAG-agent-backend"
}
```

## POST /api/analyze

Analyze one normalized security event and persist the generated alert.

Request example:

```json
{
  "source_ip": "45.67.89.10",
  "method": "GET",
  "url": "/login?id=1' OR '1'='1",
  "path": "/login",
  "query": "id=1' OR '1'='1",
  "status": 403,
  "user_agent": "sqlmap/1.7",
  "waf_rule_id": "942100",
  "waf_message": "SQL Injection Attack Detected",
  "raw_log": "demo"
}
```

Response:

```text
SecurityAlert
```

Important fields:

```text
alert_id
session_id
attack_type
risk_score
risk_level
source_ip
target
confidence
evidence
mitre_attack
recommendations
report_markdown
llm_used
llm_skipped_reason
llm_summary
llm_model
llm_provider
llm_latency_ms
llm_prompt_tokens
llm_completion_tokens
llm_total_tokens
llm_error
```

LLM report fields are metadata for optional report enhancement. When `LLM_UNKNOWN_CLASSIFIER_ENABLED=true`, rule-unknown events may be classified by the LLM before scoring; accepted fallback results are visible in `evidence` and `analysis_metadata`.

The `session_id` field points to short-term analysis context stored in Redis. It can be used for follow-up result retrieval.

## GET /api/analysis/{session_id}/result

Read saved short-term analysis context from Redis.

Example:

```text
GET /api/analysis/session-abc123/result
```

Response:

```text
AnalysisState
```

Important fields:

```text
session_id
event
parsed_event
llm_unknown_classification
final_alert
context_result
triage_result
threat_intel_result
memory_summary
findings
workflow_steps
reflections
created_at
```

Errors:

```text
404 - session result does not exist or has expired
```

## POST /api/analysis/{session_id}/ask

Ask a follow-up question about one saved analysis session.

The answer is generated only from the saved `AnalysisState` stored under `security:result:{session_id}`. It does not rerun detection, change alert status, or rewrite risk scoring.

Request example:

```json
{
  "question": "为什么这个告警是 critical？",
  "history": [
    {
      "role": "user",
      "content": "先解释一下关键证据"
    },
    {
      "role": "assistant",
      "content": "关键证据是 WAF 942100 和 SQL 注入 payload。"
    }
  ]
}
```

The `history` field is optional. It allows the frontend Follow-up panel to send recent turns from the current conversation, so the LLM can answer contextual follow-up questions such as “那为什么不是误报？”. The saved `AnalysisState` remains the source of truth.

Response:

```text
AnalysisFollowupResponse
```

Important fields:

```text
session_id
question
answer_markdown
llm_used
llm_model
llm_provider
llm_latency_ms
llm_prompt_tokens
llm_completion_tokens
llm_total_tokens
llm_error
```

Errors:

```text
404 - session result does not exist or has expired
422 - invalid question body
```

## GET /api/alerts/recent

Read recent persisted alerts from the database.

Query:

```text
count - number of alerts, default 20, min 1, max 100
status - optional workflow status filter
risk_level - optional risk level filter: low, medium, high, critical
requires_human_review - optional human review filter
```

Example:

```text
GET /api/alerts/recent?count=20
GET /api/alerts/recent?status=needs_review
GET /api/alerts/recent?risk_level=critical
GET /api/alerts/recent?requires_human_review=true
GET /api/alerts/recent?risk_level=high&status=needs_review&requires_human_review=true
```

Response:

```text
list[SecurityAlert]
```

## PATCH /api/alerts/{alert_id}/status

Update alert workflow status and analyst handling fields.

Request example:

```json
{
  "status": "resolved",
  "analyst_note": "WAF blocked the request and the service owner confirmed no impact.",
  "handled_by": "analyst"
}
```

Response:

```text
SecurityAlert
```

Errors:

```text
404 - alert_id does not exist
422 - invalid status or request body
```

## GET /api/knowledge/documents

List local Markdown documents in the RAG knowledge base.

Response:

```text
list[KnowledgeDocument]
```

Important fields:

```text
doc_id
title
category
source
tags
content
```

## GET /api/knowledge/documents/{source}

Read one local RAG knowledge document by file name.

Example:

```text
GET /api/knowledge/documents/attack_patterns.md
```

Response:

```text
KnowledgeDocument
```

Errors:

```text
404 - knowledge document does not exist
```

## POST /api/knowledge/documents

Save one Markdown document into the local RAG knowledge base from JSON.

Request example:

```json
{
  "filename": "custom_playbook.md",
  "content": "# Custom Playbook\n\n## SQL Injection\n\nUse parameterized queries.",
  "overwrite": false
}
```

Response:

```text
KnowledgeUploadResponse
```

Important fields:

```text
source
doc_id
title
category
tags
chunk_count
overwritten
message
```

Errors:

```text
409 - document already exists and overwrite is false
422 - invalid filename or empty content
```

Operational note:

```text
Uploaded Markdown is written to backend/app/data/knowledge_base/.
BM25 retrieval is available after the current API process refreshes its RAG cache.
Milvus vector retrieval requires running scripts/rebuild_knowledge_vectors.py --recreate.
```

## POST /api/knowledge/documents/upload

Upload one UTF-8 Markdown file into the local RAG knowledge base.

Form fields:

```text
file - uploaded .md file
overwrite - whether an existing document may be replaced
```

Response:

```text
KnowledgeUploadResponse
```

Errors:

```text
409 - document already exists and overwrite is false
422 - file is not .md or is not UTF-8
```
