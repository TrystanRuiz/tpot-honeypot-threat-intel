# Honeypot Threat Intelligence Pipeline

Production honeypot infrastructure deployed on Proxmox VE, capturing real-world attack traffic from the open internet. Built on top of T-POT's 21 honeypot sensors is a Python pipeline that pulls attacker IPs from Elasticsearch, scores them against AbuseIPDB, and automatically pushes high-risk IPs into OPNsense as firewall blocks. Also included is a standalone Cowrie SSH honeypot with Splunk SIEM integration, brute-force simulation, and network hardening documentation.

**762,000+ events captured | 115 unique attacker IPs | 3 confirmed malicious IPs auto-blocked | 76% pipeline speed improvement with async**

---

## Architecture

```
Internet
    │
    ▼
T-POT (21 honeypot sensors, ELK stack, Suricata IDS)
    │
    ▼
Python Pipeline (sync + async)
    │
    ├── AbuseIPDB  (IP reputation scoring)
    │
    └── OPNsense REST API  (automated firewall block lists)


Cowrie SSH Honeypot (standalone lab)
    │
    ├── Splunk Enterprise  (log ingestion and dashboards)
    ├── Hydra from Kali   (brute-force simulation)
    └── UFW + Fail2Ban    (network hardening)
```

---

## Stack

| Layer | Tool | Purpose |
|---|---|---|
| Honeypot Platform | T-POT 24.04.1 Standard | 21 honeypot sensors on Ubuntu 24.04 |
| SSH Honeypot | Cowrie | SSH/Telnet honeypot, credential capture |
| IDS | Suricata 8.0.2 | Intrusion detection across all sensors |
| Log Stack | ELK (Elasticsearch, Logstash, Kibana) | Log ingestion, search, and visualization |
| SIEM | Splunk Enterprise | Cowrie log analysis and dashboards |
| Pipeline | Python (sync + async) | IP extraction, reputation scoring, firewall automation |
| Threat Intel | AbuseIPDB | IP reputation and abuse confidence scoring |
| Firewall | OPNsense 25.1 | Automated firewall block list via REST API |
| Infrastructure | Proxmox VE 9.1.1 | Hypervisor hosting all VMs |
| Network Hardening | UFW + Fail2Ban | Subnet blocking and brute-force rate limiting |
| Attack Simulation | Hydra + Kali Linux | Brute-force testing and end-to-end pipeline validation |

---

## Pipeline Performance

| Version | Time for 90 IPs | Improvement |
|---|---|---|
| Sync | 34 seconds | Baseline |
| Async | 8 seconds | 76% faster |

Live blocking was tested end-to-end using known malicious IPs spoofed from Kali Linux against the honeypot sensors. All 3 confirmed malicious IPs were detected and auto-blocked via OPNsense within the pipeline cycle.

---

## T-POT Documentation

| Doc | Description |
|---|---|
| [T-POT Installation Steps](T-POT-Installation-Steps.md) | Full install on Ubuntu 24.04 with screenshots |
| [Automated IP Blocking Pipeline](Automated-IP-Blocking-Pipeline.md) | T-POT + AbuseIPDB + OPNsense automated firewall blocking |
| [Live Threat Blocking](Live-Threat-Blocking.md) | End-to-end proof of malicious IPs being detected and blocked |
| [Async Benchmark](Async-Benchmark.md) | Sync vs async performance comparison for AbuseIPDB reputation checks |

---

## Cowrie SSH Honeypot Documentation

Standalone Cowrie deployment on Proxmox VE with Splunk SIEM integration. Covers SSH honeypot setup, brute-force attack simulation using Hydra from Kali Linux, Splunk log ingestion, and network hardening with UFW and Fail2Ban. This work informed the credential capture and attack pattern analysis built into the full T-POT pipeline.

| Doc | Description |
|---|---|
| [Cowrie Installation](cowrie/Cowrie-Installation.md) | VM creation, Cowrie setup, iptables port redirect |
| [Splunk Installation](cowrie/Splunk-Installation.md) | Splunk Enterprise setup for Cowrie log ingestion |
| [Brute Force Attack Simulation](cowrie/Brute-Force-Attack-Cowrie.md) | Hydra brute-force attack against the honeypot from Kali |
| [UFW Installation](cowrie/UFW-Installation.md) | UFW firewall rules and subnet blocking |
| [Fail2Ban Installation](cowrie/Fail2Ban-Installation.md) | Fail2Ban setup for automated brute-force rate limiting |
| [Hardening — UFW and Fail2Ban](cowrie/Hardening-Cowrie-UFW-Fail2Ban.md) | Combined network hardening walkthrough |

---

## Key Findings

- 762,000+ attack events captured from 115 unique attacker IPs across multiple countries
- Cowrie SSH sensor logged every username and password pair attempted during brute-force attacks
- AbuseIPDB correctly flagged 3 IPs at 80%+ confidence, which were automatically pushed to OPNsense and blocked
- Async pipeline reduced AbuseIPDB batch check time from 34 seconds to 8 seconds for 90 IPs
- UFW and Fail2Ban successfully rate-limited Hydra brute-force attempts during simulated attack testing

---

## Responsible Use

All attack simulation was performed against self-owned virtual machines in an isolated home lab environment. No external systems were targeted.
