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
```

## GET /api/alerts/recent

Read recent persisted alerts from the database.

Query:

```text
count - number of alerts, default 20, min 1, max 100
status - optional workflow status filter
requires_human_review - optional human review filter
```

Example:

```text
GET /api/alerts/recent?count=20
GET /api/alerts/recent?status=needs_review
GET /api/alerts/recent?requires_human_review=true
GET /api/alerts/recent?status=needs_review&requires_human_review=true
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
