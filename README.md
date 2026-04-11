# T-POT Honeypot Threat Intelligence

Production honeypot deployment capturing real-world attack traffic from the open internet. Built on T-POT Standard Edition with 20+ honeypot sensors and full ELK stack for log aggregation, threat visualization, and attack analysis.

## Table of Contents

- [Deployment](#deployment)
- [Architecture](#architecture)
- [Honeypot Coverage](#honeypot-coverage)
- [Security](#security)
- [Installation Steps](Installation-Steps/T-Pot-Installation.md)

## Deployment

| Component | Detail |
|-----------|--------|
| Host | Proxmox VE 9.1.1 |
| VM | Ubuntu 24.04.4 LTS (cloud-init provisioned) |
| T-POT | 24.04.1 Standard Edition |
| Resources | 4 cores, 16 GB RAM, 128 GB disk |
| IDS | Suricata 8.0.2 |

## Architecture

```
Internet --> Router / Port Forward --> T-POT VM (39 Docker containers)
                                          |
              +---------------------------+---------------------------+
              |                           |                           |
        Honeypot Sensors           Network Analysis         Logging / Visualization
              |                           |                           |
   Cowrie (SSH/Telnet)             Suricata (IDS)           Elasticsearch
   Dionaea (SMB/FTP/SQL)           fatt (fingerprinting)    Logstash
   Conpot (ICS/SCADA)             p0f (OS detection)       Kibana (port 64297)
   Heralding (creds)                                       Attack Map (port 64294)
   Snare/Tanner (HTTP)                                     SpiderFoot (OSINT)
   CiscoASA, Mailoney,
   Wordpot, Elasticpot,
   RedisHoneypot, ADBHoney,
   Medpot, Dicompot,
   SentryPeer, Honeytrap,
   + more
```

## Honeypot Coverage

21 sensors across 50+ TCP/UDP ports emulating real services to attract and log attacks:

- **Remote Access** - SSH, Telnet, VNC, ADB, SOCKS proxy
- **Web** - HTTP, HTTPS, WordPress
- **Email** - SMTP, POP3, IMAP
- **Databases** - MySQL, MSSQL, MongoDB, PostgreSQL, Redis, Elasticsearch
- **File Transfer** - FTP, TFTP, SMB
- **Industrial** - IEC104, IPMI, Kamstrup smart metering, Guardian AST tank gauging
- **Medical** - HL7/FHIR, DICOM imaging
- **Network** - VPN (Cisco ASA), SIP/VoIP, printer (IPP/PJL)
- **Catch-all** - Honeytrap captures connections on any unmatched TCP port

## Security

- SSH on port 64295, key-based authentication only
- Management interfaces (Elasticsearch, Kibana, SpiderFoot, Logstash) bound to localhost
- Web UI and Attack Map behind Nginx with htpasswd
- All honeypot containers isolated in separate Docker bridge networks
- Suricata monitors all traffic with BPF filters excluding management ports
