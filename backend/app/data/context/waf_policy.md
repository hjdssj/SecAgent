# WAF Policy

## OWASP CRS 942 SQL Injection

rule_prefix: 942
waf_action: block
attack_type: SQL Injection
keywords: owasp crs 942 sql injection sqli

SQL injection rules in the 942 family are configured in blocking mode for public-facing authentication and search services.

## OWASP CRS 941 XSS

rule_prefix: 941
waf_action: block
attack_type: XSS
keywords: owasp crs 941 xss cross site scripting

XSS rules in the 941 family are configured in blocking mode for public-facing web services.

## OWASP CRS 930 Path Traversal

rule_prefix: 930
waf_action: block
attack_type: Path Traversal
keywords: owasp crs 930 path traversal

Path traversal rules in the 930 family are configured in blocking mode for file download and export endpoints.
