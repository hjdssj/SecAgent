# Incident Playbook

## SQL Injection Review

attack_type: SQL Injection
automation_decision: human_review_required
keywords: sql injection sqli login database authentication

For SQL injection against critical authentication assets, review WAF audit logs, authentication logs, database error logs, and recent source IP behavior before closure.

## XSS Review

attack_type: XSS
automation_decision: observe_only
keywords: xss reflected output encoding csp

For blocked XSS on medium-risk assets, observe repeated source behavior and verify whether the payload was reflected in responses.

## Scanner Noise Review

attack_type: Automated Scanner
automation_decision: auto_close
keywords: scanner whitelist known scanner internal scanner

Known internal scanner alerts can be auto-closed when the target is not critical and the source is whitelisted.
