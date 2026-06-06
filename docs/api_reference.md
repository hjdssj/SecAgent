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

Analyze one normalized security event.

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

Read recent alerts from Redis.

Query:

```text
count - number of alerts, default 20, min 1, max 100
```

Example:

```text
GET /api/alerts/recent?count=20
```

Response:

```text
list[SecurityAlert]
```
