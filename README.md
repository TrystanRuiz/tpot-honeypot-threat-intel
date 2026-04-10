# T-POT Honeypot Threat Intelligence

Production honeypot deployment capturing real-world attack traffic from the open internet. Built on T-POT Standard Edition running 20+ honeypot sensors with full ELK stack integration for log aggregation, threat visualization, and attack analysis.

## Deployment

| Component | Detail |
|-----------|--------|
| Host | Proxmox VE 9.1.1 |
| VM | Ubuntu 24.04.4 LTS (cloud image, cloud-init provisioned) |
| T-POT Version | 24.04.1 Standard |
| CPU | 4 cores (host passthrough) |
| RAM | 16 GB |
| Disk | 128 GB (thin-provisioned LVM) |
| Network | Bridged (vmbr0), DHCP |
| Kernel | 6.8.0-107-generic |

## Architecture

```
Internet Traffic
       |
   [ Router / Port Forward ]
       |
   [ T-POT VM - 192.168.1.244 ]
       |
       +-- 20+ Honeypot Sensors (Docker containers)
       |       |
       |       +-- Cowrie (SSH/Telnet - ports 22, 23)
       |       +-- Dionaea (SMB, FTP, MSSQL, MySQL, MongoDB - ports 20-21, 42, 135, 445, 1433, 3306, 27017)
       |       +-- Conpot (ICS/SCADA - IPMI 623, IEC104 2404, Kamstrup 1025/50100, Guardian AST 10001)
       |       +-- Heralding (POP3, IMAP, SMTP, SOCKS, PostgreSQL, VNC - ports 110, 143, 465, 993, 995, 1080, 5432, 5900)
       |       +-- Snare/Tanner (HTTP - port 80)
       |       +-- h0neytr4p (HTTPS - port 443)
       |       +-- Mailoney (SMTP - ports 25, 587)
       |       +-- CiscoASA (VPN - port 8443, UDP 5000)
       |       +-- Wordpot (WordPress - port 8080)
       |       +-- Elasticpot (Elasticsearch - port 9200)
       |       +-- RedisHoneypot (Redis - port 6379)
       |       +-- ADBHoney (Android Debug Bridge - port 5555)
       |       +-- IPPHoney (Printer - port 631)
       |       +-- Miniprint (Printer - port 9100)
       |       +-- Medpot (HL7/FHIR medical - port 2575)
       |       +-- Dicompot (DICOM medical - ports 104, 11112)
       |       +-- SentryPeer (SIP/VoIP - port 5060)
       |       +-- HoneyAML (YAML API - port 3000)
       |       +-- Honeytrap (catch-all TCP)
       |
       +-- Network Analysis
       |       +-- Suricata 8.0.2 (IDS/IPS, full packet inspection)
       |       +-- fatt (fingerprinting)
       |       +-- p0f (passive OS detection)
       |
       +-- Logging and Visualization
       |       +-- Elasticsearch (cluster status: green, 37 active shards)
       |       +-- Logstash (log pipeline and ingestion)
       |       +-- Kibana (dashboards and visualization - port 64297)
       |       +-- Attack Map (real-time geolocation of attackers - port 64294)
       |       +-- SpiderFoot (OSINT reconnaissance on attacker IPs)
       |
       +-- Threat Sharing
               +-- EWSPoster (submits attack data to Deutsche Telekom threat feed)
```

## Active Containers

39 containers running in production across isolated Docker bridge networks.

### Honeypot Sensors (21)

| Sensor | Protocol | Port(s) | What it Captures |
|--------|----------|---------|-----------------|
| Cowrie | SSH, Telnet | 22, 23 | Brute-force credentials, shell commands, malware downloads |
| Dionaea | SMB, FTP, TFTP, HTTP, MSSQL, MySQL, MongoDB, MQTT, PPTP | 20-21, 42, 69, 81, 135, 445, 1433, 1723, 1883, 3306, 27017 | Exploit payloads, malware binaries, shellcode |
| Conpot (IEC104) | ICS/SCADA | 161, 2404 | Industrial control system reconnaissance |
| Conpot (IPMI) | IPMI | 623/udp | Server management interface attacks |
| Conpot (Kamstrup) | Smart metering | 1025, 50100 | Energy infrastructure probes |
| Conpot (Guardian AST) | Tank gauging | 10001 | Fuel system targeting |
| Heralding | POP3, IMAP, SMTP, SOCKS, PostgreSQL, VNC | 110, 143, 465, 993, 995, 1080, 5432, 5900 | Credential harvesting across multiple protocols |
| Snare + Tanner | HTTP | 80 | Web application attacks, LFI/RFI, XSS |
| h0neytr4p | HTTPS | 443 | TLS-based web attacks |
| Mailoney | SMTP | 25, 587 | Spam relay attempts, email enumeration |
| CiscoASA | VPN | 8443, 5000/udp | VPN exploitation, Cisco CVE probes |
| Wordpot | WordPress | 8080 | Plugin exploits, wp-admin brute force, enumeration |
| Elasticpot | Elasticsearch | 9200 | Unauthenticated Elasticsearch exploitation |
| RedisHoneypot | Redis | 6379 | Redis command injection, unauthorized access |
| ADBHoney | ADB | 5555 | Android Debug Bridge exploitation |
| IPPHoney | IPP | 631 | Printer protocol attacks |
| Miniprint | PCL/PJL | 9100 | Printer exploitation |
| Medpot | HL7/FHIR | 2575 | Healthcare protocol attacks |
| Dicompot | DICOM | 104, 11112 | Medical imaging system attacks |
| SentryPeer | SIP | 5060 | VoIP fraud, SIP scanning |
| HoneyAML | YAML API | 3000 | API deserialization attacks |
| Honeytrap | TCP (catch-all) | Dynamic | Captures connections to any unassigned TCP port |

### Network Analysis (3)

| Tool | Function |
|------|----------|
| Suricata 8.0.2 | Full packet IDS/IPS with signature-based and anomaly detection |
| fatt | Network fingerprinting (JA3/JA4 TLS, SSH, HTTP fingerprints) |
| p0f | Passive TCP/IP OS fingerprinting of attackers |

### Logging, Visualization, and Intelligence (9)

| Tool | Function | Access |
|------|----------|--------|
| Elasticsearch | Log storage and search engine | localhost:64298 |
| Logstash | Log ingestion pipeline | localhost:64305 |
| Kibana | Dashboards, queries, threat visualization | port 64297 (web) |
| Attack Map | Real-time world map of incoming attacks | port 64294 (web) |
| SpiderFoot | Automated OSINT on attacker IPs | localhost:64303 |
| EWSPoster | Submits honeypot data to DTAG community threat feed | Automatic |
| Map Data | Redis-backed geolocation data for attack map | Internal |
| Map Redis | Redis instance for attack map | Internal |
| Map Web | Web frontend for attack map | Internal |

## Management Ports

| Port | Service |
|------|---------|
| 64295 | SSH (key-based auth only) |
| 64296 | Kibana (localhost only) |
| 64297 | T-POT Web UI / Kibana (HTTPS, password protected) |
| 64298 | Elasticsearch (localhost only) |
| 64299 | Attack Map backend (localhost only) |
| 64303 | SpiderFoot (localhost only) |
| 64305 | Logstash (localhost only) |

## Security

- SSH moved to port 64295, password authentication disabled, key-based only
- Management interfaces (Elasticsearch, Kibana, SpiderFoot, Logstash) bound to localhost
- Web UI (64297) and Attack Map (64294) protected by Nginx with htpasswd authentication
- All honeypot containers run in isolated Docker bridge networks
- Suricata monitors all traffic with BPF filters excluding management ports
- EWSPoster shares anonymized attack data with the DTAG community threat intelligence feed

## Exposed Attack Surface

50+ ports across TCP and UDP designed to attract and log malicious traffic:

**TCP:** 20-23, 25, 42, 69, 80-81, 104, 110, 135, 143, 443, 445, 465, 587, 631, 993, 995, 1025, 1080, 1433, 1723, 1883, 2404, 2575, 3000, 3306, 5060, 5432, 5555, 5900, 6379, 8080, 8443, 9100, 9200, 10001, 11112, 27017, 50100

**UDP:** 69, 161, 623, 5000, 5060

## Tools and Stack

- **T-POT 24.04.1 Standard** by Deutsche Telekom Security
- **Elastic Stack** (Elasticsearch + Logstash + Kibana)
- **Suricata 8.0.2** IDS/IPS
- **Docker** with 39 containers across isolated bridge networks
- **Ubuntu 24.04.4 LTS** on Proxmox VE 9.1.1
- **Cloud-init** for automated VM provisioning
