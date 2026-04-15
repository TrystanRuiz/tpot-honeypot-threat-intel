# Threat Intelligence Pipeline — Automated IP Blocking

This documents the automated threat intelligence pipeline built on top of T-POT's Elasticsearch logs. The pipeline extracts real attacker IPs from honeypot data, scores them against AbuseIPDB's reputation database, and programmatically pushes high-risk IPs into OPNsense as a dynamic firewall blocklist — no manual intervention required.

**Stack:** T-POT ELK (192.168.1.244) → Python script → AbuseIPDB API → OPNsense REST API (192.168.1.100)

---

### 1. OPNsense Alias — tpot_blocklist

Before running the pipeline, a dynamic alias called `tpot_blocklist` was created in OPNsense under **Firewall → Aliases**. This alias is type **Host(s)** and acts as the target the Python script writes IPs into via the OPNsense REST API. The script updates this alias automatically every time it runs — no manual firewall rule editing needed.

The alias description is set to "T-POT threat intel" so it's clearly identifiable. The **Loaded** column shows how many IPs are currently active in the alias.

![OPNsense tpot_blocklist alias](../screenshots/pipeline/01-opnsense-tpot-blocklist-alias.png)

---

### 2. LAN Firewall Rule — Block High-Risk IPs

A firewall rule was created under **Firewall → Rules → LAN** that references the `$tpot_blocklist` alias as the **Source**. Any IP that the pipeline flags as high-risk gets added to the alias and is immediately subject to this drop rule. The rule is generated under **Automation** so it stays clean and separate from manually created rules.

This is the enforcement layer — the alias is the data, the rule is the action.

![OPNsense LAN block rule](../screenshots/pipeline/02-opnsense-lan-block-rule.png)

---

### 3. Alias Diagnostics — Verifying the View

The **Firewall → Diagnostics → Aliases** page lets you inspect what IPs are actually loaded into any alias at runtime. Here the bogons alias is shown to confirm the diagnostics view is working correctly. This same view is used later to verify that the pipeline successfully pushed IPs into `tpot_blocklist`.

![OPNsense alias diagnostics](../screenshots/pipeline/03-opnsense-bogons-diagnostic.png)

---

### 4. Pipeline Running — AbuseIPDB Scoring

The Python script (`scripts/ip_reputation_check.py`) is run against the live T-POT Elasticsearch instance. The script:

1. Queries T-POT's ELK stack at `http://localhost:9200` (tunneled via SSH on port 64295) for the last 7 days of honeypot events
2. Extracts and deduplicates external attacker IPs — **72 unique IPs** found from the logs
3. Filters out private/RFC1918 ranges automatically
4. Sends each IP to **AbuseIPDB** for a reputation score (0–100, where 100 = definitely malicious)
5. Flags any IP scoring **≥ 75** for blocking

The output shows scores per IP in real time. Most IPs score low (0–8) or moderately (50). The pipeline completed in **32.98 seconds** for 72 IPs (~8.46s per IP on the sync version — the async version cuts this down significantly).

```bash
python3 ip_reputation_check.py
```

![Pipeline running with AbuseIPDB scores](../screenshots/pipeline/04-pipeline-running-abuseipdb-scores.png)

---

### 5. Pipeline Report — Blocking Decision

After scoring all 72 IPs, the pipeline prints a **Reputation Report**:

- **Total IPs checked:** 72
- **IPs to BLOCK (score ≥ 75):** 0 in this run (real-world attacker IPs scored below the threshold — confirms the threshold is working and not over-blocking)
- **Errors:** 0

The block list is saved to `block_list.json` locally and the script pushes the result to OPNsense via its REST API. Even when 0 IPs meet the threshold, the API call still fires — confirming the OPNsense integration is wired up end-to-end.

![Pipeline complete report](../screenshots/pipeline/05-pipeline-complete-report.png)

---

### 6. Script Uploaded to GitHub

The complete script (`ip_reputation_check.py`) is published in the `scripts/` directory of this repo. At 438 lines (391 loc, 11.3 KB), it includes:

- Elasticsearch query logic with date filtering
- IP deduplication and RFC1918 range filtering
- AbuseIPDB API integration with rate limit handling
- OPNsense REST API integration for alias updates
- Sync baseline version (this run) + async version built with `asyncio`/`aiohttp` for speed benchmarking

![Script on GitHub](../screenshots/pipeline/06-github-script-uploaded.png)

---

### 7. OPNsense Blocklist Populated — End-to-End Proof

The `tpot_blocklist` alias is inspected in **Firewall → Diagnostics → Aliases** after a test push using known IPs (`1.2.3.4` and `5.6.7.8`). Both IPs appear in the alias — confirming the Python script successfully authenticated to OPNsense's REST API and updated the alias programmatically.

In production, real high-scoring attacker IPs from the T-POT logs replace the test entries. Any traffic sourced from those IPs is dropped by the LAN rule created in step 2.

![OPNsense blocklist populated](../screenshots/pipeline/07-opnsense-blocklist-populated.png)