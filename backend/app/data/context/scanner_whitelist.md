# Scanner Whitelist

## Internal Security Scanner

ip: 10.10.3.8
scanner_name: internal-vulnerability-scanner
business_owner: security-team
asset_criticality: low
keywords: scanner whitelist sqlmap nikto nessus

This IP belongs to the internal security scanning platform. Alerts from this source can usually be auto-triaged when risk is low and the target is not critical.

## Local Demo Traffic

ip: 127.0.0.1
scanner_name: local-demo
business_owner: security-team
asset_criticality: low
keywords: local demo test traffic

This IP is reserved for local demo and test traffic.
