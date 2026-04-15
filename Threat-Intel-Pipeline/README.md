# Threat Intelligence Pipeline

Walkthrough of the automated IP reputation scoring and OPNsense firewall blocking pipeline built on top of T-POT's honeypot logs.

## Read the walkthrough

[Pipeline-Walkthrough.md](Pipeline-Walkthrough.md)

## What this covers

- OPNsense alias and firewall rule setup for dynamic blocking
- Python script querying T-POT Elasticsearch for attacker IPs
- AbuseIPDB reputation scoring per IP
- Programmatic OPNsense blocklist updates via REST API
- End-to-end proof: test IPs appear in the live firewall alias