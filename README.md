# T-POT Honeypot Threat Intelligence

Production honeypot deployment capturing real-world attack traffic from the open internet. Built on T-POT Standard Edition with 20+ honeypot sensors and full ELK stack for log aggregation, threat visualization, and attack analysis.

## Architecture

- **Proxmox Host (pve):** Proxmox VE 9.1.1
- **T-POT VM (VM 109):** Ubuntu 24.04.4 LTS, 4 cores, 16 GB RAM, 128 GB disk
- **T-POT Version:** 24.04.1 Standard (Hive)
- **IDS:** Suricata 8.0.2
- **Containers:** 39 Docker containers across isolated bridge networks
- **Sensors:** 21 honeypots covering 50+ TCP/UDP ports (SSH, SMB, HTTP, ICS/SCADA, databases, email, VoIP, medical, and more)
- **Stack:** Elasticsearch, Logstash, Kibana, SpiderFoot, Attack Map

## Documentation

- [T-POT Installation Steps](T-POT-Installation-Steps.md) — Full install on Ubuntu 24.04 with screenshots
- [Automated IP Blocking Pipeline](Automated-IP-Blocking-Pipeline.md) — T-POT + AbuseIPDB + OPNsense automated firewall blocking
