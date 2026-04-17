# T-POT Honeypot Threat Intelligence

A production honeypot deployed on Proxmox VE that captures real-world attack traffic from the internet. The project goes beyond just running a honeypot — it includes an automated threat intelligence pipeline that extracts attacker IPs from the ELK stack, scores them against AbuseIPDB, and programmatically pushes high-risk IPs to an OPNsense firewall blocklist via REST API. No manual intervention required.

The pipeline was built in two versions — sync and async — with a measured 76% speed improvement using `asyncio` and `aiohttp`. Live blocking was validated end-to-end using known malicious IPs spoofed from Kali targeting the honeypot sensors.

**762,000+ attack events captured | 115 unique attacker IPs | 3 confirmed malicious IPs auto-blocked**

## Stack

```
T-POT (21 sensors, ELK) → Python pipeline → AbuseIPDB → OPNsense firewall
```

- **Honeypot:** T-POT 24.04.1 Standard on Ubuntu 24.04 (Proxmox VM, 16GB RAM)
- **IDS:** Suricata 8.0.2 — 39 Docker containers across isolated bridge networks
- **Pipeline:** Python (sync + async), Elasticsearch API, AbuseIPDB, OPNsense REST API
- **Infra:** Proxmox VE 9.1.1, OPNsense 25.1

## Documentation

- [T-POT Installation Steps](T-POT-Installation-Steps.md) — Full install on Ubuntu 24.04 with screenshots
- [Automated IP Blocking Pipeline](Automated-IP-Blocking-Pipeline.md) — T-POT + AbuseIPDB + OPNsense automated firewall blocking
- [Live Threat Blocking](Live-Threat-Blocking.md) — End-to-end proof of known malicious IPs being detected and blocked
- [Async Benchmark](Async-Benchmark.md) — Sync vs async performance comparison for AbuseIPDB reputation checks
