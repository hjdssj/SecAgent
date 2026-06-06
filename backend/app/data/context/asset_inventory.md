# Enterprise Asset Inventory

## Account Center Login

path: /login
asset_name: Account Center Login
business_owner: account-team
asset_criticality: critical
keywords: login authentication account identity sqli sql injection

The /login endpoint belongs to the account center. It is a critical public-facing authentication asset.

## Search Service

path: /search
asset_name: Search Service
business_owner: search-team
asset_criticality: medium
keywords: search query xss reflected input

The /search endpoint exposes public query input and is commonly monitored for reflected XSS.

## File Download Service

path: /download
asset_name: File Download Service
business_owner: platform-team
asset_criticality: high
keywords: download file path traversal directory traversal

The /download endpoint handles file retrieval and must enforce directory boundary checks.
