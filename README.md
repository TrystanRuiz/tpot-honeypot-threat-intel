# T-POT Honeypot Threat Intelligence

T-POT Standard Edition running on Proxmox VE, exposed to the internet to capture real attack traffic. Built on top of it is a Python pipeline that pulls attacker IPs from Elasticsearch, checks them against AbuseIPDB for reputation scores, and pushes anything high-risk into OPNsense as a firewall block automatically.

The pipeline has a sync version and an async version. The async version using `asyncio` and `aiohttp` runs 76% faster (34s to 8s on 90 IPs). Live blocking was tested end-to-end using known malicious IPs spoofed from Kali hitting the honeypot sensors.

**762,000+ events captured | 115 unique attacker IPs | 3 confirmed malicious IPs auto-blocked**

## Stack

```
T-POT (21 sensors, ELK) -> Python pipeline -> AbuseIPDB -> OPNsense firewall
```

- **Honeypot:** T-POT 24.04.1 Standard on Ubuntu 24.04 (Proxmox VM, 16GB RAM)
- **IDS:** Suricata 8.0.2, 39 Docker containers across isolated bridge networks
- **Pipeline:** Python (sync + async), Elasticsearch API, AbuseIPDB, OPNsense REST API
- **Infra:** Proxmox VE 9.1.1, OPNsense 25.1

## Documentation

- [T-POT Installation Steps](T-POT-Installation-Steps.md) - Full install on Ubuntu 24.04 with screenshots
- [Automated IP Blocking Pipeline](Automated-IP-Blocking-Pipeline.md) - T-POT + AbuseIPDB + OPNsense automated firewall blocking
- [Live Threat Blocking](Live-Threat-Blocking.md) - End-to-end proof of known malicious IPs being detected and blocked
- [Async Benchmark](Async-Benchmark.md) - Sync vs async performance comparison for AbuseIPDB reputation checks
