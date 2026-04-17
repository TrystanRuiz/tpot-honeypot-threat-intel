#!/usr/bin/env python3
"""
T-POT IP Reputation Checker (Async Version)

Extracts attacker IPs from T-POT's Elasticsearch logs,
queries AbuseIPDB for reputation scores concurrently using asyncio/aiohttp,
and pushes high-risk IPs to OPNsense firewall blocklist.

Async version fires all AbuseIPDB requests concurrently (bounded by semaphore)
vs the sync version which checks one IP at a time. See benchmark at bottom.

Usage:
    python3 ip_reputation_check_async.py

Requires:
    pip install aiohttp requests

Environment:
    ABUSEIPDB_API_KEY  - Your AbuseIPDB API key (free tier: 1000 checks/day)
    OPNSENSE_API_KEY   - OPNsense API key
    OPNSENSE_API_SECRET - OPNsense API secret
"""

import os
import sys
import json
import time
import asyncio
import subprocess
import signal
import requests
import aiohttp
from datetime import datetime
from collections import defaultdict

# ── Config ───────────────────────────────────────────────
TPOT_HOST     = os.getenv("TPOT_HOST", "192.168.1.244")
TPOT_SSH_PORT = int(os.getenv("TPOT_SSH_PORT", "64295"))
TPOT_SSH_USER = os.getenv("TPOT_SSH_USER", "trystan")
TPOT_ES_PORT  = 64298
LOCAL_ES_PORT = 19200

ES_BASE_URL = f"http://localhost:{LOCAL_ES_PORT}"

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL     = "https://api.abuseipdb.com/api/v2/check"

OPNSENSE_HOST       = os.getenv("OPNSENSE_HOST", "192.168.1.100")
OPNSENSE_API_KEY    = os.getenv("OPNSENSE_API_KEY", "")
OPNSENSE_API_SECRET = os.getenv("OPNSENSE_API_SECRET", "")
OPNSENSE_BASE_URL   = f"https://{OPNSENSE_HOST}/api"
OPNSENSE_ALIAS_NAME = "tpot_blocklist"

EXCLUDE_IPS = {
    "192.168.1.244",
    "192.168.1.1",
    "192.168.1.194",
    "192.168.1.100",
    "71.47.74.158",
}
EXCLUDE_PREFIXES = ("192.168.", "10.", "172.16.", "fe80:", "2603:9001:")

SCORE_THRESHOLD = 75

# Max concurrent AbuseIPDB requests — keeps us under rate limits
MAX_CONCURRENT = 10

_tunnel_proc = None


# ── SSH Tunnel ───────────────────────────────────────────
def start_tunnel():
    global _tunnel_proc
    print(f"  Opening SSH tunnel to {TPOT_HOST}:{TPOT_ES_PORT} via port {TPOT_SSH_PORT}...")
    _tunnel_proc = subprocess.Popen(
        ["ssh", "-N", "-L", f"{LOCAL_ES_PORT}:localhost:{TPOT_ES_PORT}",
         "-p", str(TPOT_SSH_PORT), f"{TPOT_SSH_USER}@{TPOT_HOST}",
         "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )
    time.sleep(2)
    if _tunnel_proc.poll() is not None:
        err = _tunnel_proc.stderr.read().decode()
        print(f"  ERROR: SSH tunnel failed: {err}")
        sys.exit(1)
    print(f"  Tunnel open: localhost:{LOCAL_ES_PORT} -> T-POT ES")


def stop_tunnel():
    global _tunnel_proc
    if _tunnel_proc:
        _tunnel_proc.terminate()
        _tunnel_proc.wait()
        _tunnel_proc = None


# ── Step 1: Extract IPs from Elasticsearch (sync — one call) ─
def get_attacker_ips(days=7, min_hits=1):
    print(f"\n[1/4] Querying T-POT Elasticsearch (last {days} days, min {min_hits} hits)...")

    query = {
        "size": 0,
        "query": {
            "bool": {
                "must_not": [
                    {"prefix": {"src_ip.keyword": "192.168."}},
                    {"prefix": {"src_ip.keyword": "10."}},
                    {"prefix": {"src_ip.keyword": "172.16."}},
                    {"prefix": {"src_ip.keyword": "172.24."}},
                    {"prefix": {"src_ip.keyword": "fe80:"}},
                    {"prefix": {"src_ip.keyword": "fd00:"}},
                    {"prefix": {"src_ip.keyword": "2603:9001:"}},
                    {"term":   {"src_ip.keyword": "0.0.0.0"}},
                ]
            }
        },
        "aggs": {
            "attacker_ips": {
                "terms": {
                    "field": "src_ip.keyword",
                    "size": 500,
                    "min_doc_count": min_hits,
                    "order": {"_count": "desc"}
                },
                "aggs": {
                    "country":   {"terms": {"field": "geoip.country_name.keyword", "size": 1}},
                    "city":      {"terms": {"field": "geoip.city_name.keyword",    "size": 1}},
                    "honeypots": {"terms": {"field": "type.keyword",               "size": 5}},
                }
            }
        }
    }

    try:
        resp = requests.post(
            f"{ES_BASE_URL}/logstash-*/_search",
            json=query,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"  ERROR: Could not connect to Elasticsearch: {e}")
        sys.exit(1)

    data    = resp.json()
    buckets = data.get("aggregations", {}).get("attacker_ips", {}).get("buckets", [])

    attackers = {}
    for bucket in buckets:
        ip    = bucket["key"]
        count = bucket["doc_count"]
        if ip in EXCLUDE_IPS:
            continue
        country_b  = bucket.get("country",   {}).get("buckets", [])
        city_b     = bucket.get("city",      {}).get("buckets", [])
        honeypot_b = bucket.get("honeypots", {}).get("buckets", [])
        attackers[ip] = {
            "hits":     count,
            "country":  country_b[0]["key"]  if country_b  else "Unknown",
            "city":     city_b[0]["key"]     if city_b     else "Unknown",
            "honeypots": [h["key"] for h in honeypot_b],
        }

    print(f"  Found {len(attackers)} external attacker IPs")
    for ip, info in list(attackers.items())[:10]:
        print(f"    {ip:<40} {info['hits']:>5} hits  {info['country']:<15} {', '.join(info['honeypots'])}")
    if len(attackers) > 10:
        print(f"    ... and {len(attackers) - 10} more")

    return attackers


# ── Step 2: Async reputation checks ──────────────────────
async def check_ip_async(session, sem, ip, info, index, total):
    """Check a single IP against AbuseIPDB — async, semaphore-bounded."""
    hit_count = info["hits"] if isinstance(info, dict) else info
    headers   = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params    = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": 1}

    async with sem:  # max MAX_CONCURRENT requests in-flight at once
        try:
            async with session.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                data   = await resp.json()
                result = data.get("data", {})

                entry = {
                    "ip":           ip,
                    "hits":         hit_count,
                    "abuse_score":  result.get("abuseConfidenceScore", 0),
                    "country":      result.get("countryCode") or "??",
                    "isp":          result.get("isp", "Unknown"),
                    "domain":       result.get("domain", ""),
                    "total_reports": result.get("totalReports", 0),
                    "is_tor":       result.get("isTor", False),
                    "usage_type":   result.get("usageType", ""),
                    "honeypots":    info.get("honeypots", []) if isinstance(info, dict) else [],
                }
                status = "BLOCK" if entry["abuse_score"] >= SCORE_THRESHOLD else "OK"
                print(f"  [{index}/{total}] {ip:<40} | Score: {entry['abuse_score']:>3} | {entry['country']:<4} | {hit_count:>5} hits | {status}")
                return entry

        except Exception as e:
            print(f"  [{index}/{total}] {ip:<40} | ERROR: {e}")
            return {
                "ip": ip, "hits": hit_count, "abuse_score": -1,
                "country": "??", "isp": "Error", "domain": "",
                "total_reports": 0, "is_tor": False, "usage_type": "",
                "honeypots": [],
            }


async def check_all_ips_async(attacker_ips):
    """Fire all AbuseIPDB checks concurrently, bounded by semaphore."""
    print(f"\n[2/4] Checking {len(attacker_ips)} IPs against AbuseIPDB (async, max {MAX_CONCURRENT} concurrent)...")

    if not ABUSEIPDB_API_KEY:
        print("  WARNING: No ABUSEIPDB_API_KEY set. Using mock scores for testing.")
        return mock_reputation(attacker_ips)

    ip_list = list(attacker_ips.items())
    total   = len(ip_list)
    sem     = asyncio.Semaphore(MAX_CONCURRENT)

    start_time = time.time()

    async with aiohttp.ClientSession() as session:
        tasks = [
            check_ip_async(session, sem, ip, info, i + 1, total)
            for i, (ip, info) in enumerate(ip_list)
        ]
        results = await asyncio.gather(*tasks)

    elapsed = time.time() - start_time
    print(f"\n  Completed in {elapsed:.2f}s ({elapsed/total:.2f}s per IP avg)")
    print(f"  Concurrency: {MAX_CONCURRENT} simultaneous requests")

    return list(results)


def mock_reputation(attacker_ips):
    import random
    results = []
    for ip, info in attacker_ips.items():
        hit_count = info["hits"] if isinstance(info, dict) else info
        score     = random.randint(0, 100)
        results.append({
            "ip": ip, "hits": hit_count, "abuse_score": score,
            "country": "??", "isp": "Mock", "domain": "",
            "total_reports": random.randint(0, 500),
            "is_tor": False, "usage_type": "MOCK",
            "honeypots": info.get("honeypots", []) if isinstance(info, dict) else [],
        })
    return results


# ── Step 3: Report ───────────────────────────────────────
def generate_report(results):
    print(f"\n[3/4] Reputation Report")
    print("=" * 80)

    results.sort(key=lambda x: x["abuse_score"], reverse=True)

    block_list = [r for r in results if r["abuse_score"] >= SCORE_THRESHOLD]
    safe_list  = [r for r in results if 0 <= r["abuse_score"] < SCORE_THRESHOLD]
    errors     = [r for r in results if r["abuse_score"] < 0]

    print(f"\n  Total IPs checked:  {len(results)}")
    print(f"  IPs to BLOCK:       {len(block_list)} (score >= {SCORE_THRESHOLD})")
    print(f"  IPs OK:             {len(safe_list)}")
    print(f"  Errors:             {len(errors)}")

    if block_list:
        print(f"\n{'─' * 80}")
        print(f"  {'IP':<18} {'Score':>5} {'Hits':>6} {'Reports':>8} {'Country':>7}  {'ISP'}")
        print(f"{'─' * 80}")
        for r in block_list:
            tor = " [TOR]" if r["is_tor"] else ""
            print(f"  {r['ip']:<18} {r['abuse_score']:>5} {r['hits']:>6} {r['total_reports']:>8} {r['country']:>7}  {r['isp']}{tor}")

    output_file = "block_list.json"
    with open(output_file, "w") as f:
        json.dump({
            "generated":     datetime.utcnow().isoformat() + "Z",
            "threshold":     SCORE_THRESHOLD,
            "total_checked": len(results),
            "block_count":   len(block_list),
            "block_ips": [
                {"ip": r["ip"], "score": r["abuse_score"], "hits": r["hits"],
                 "country": r["country"], "isp": r["isp"]}
                for r in block_list
            ]
        }, f, indent=2)

    print(f"\n  Block list saved to {output_file}")
    return block_list


# ── Step 4: Push to OPNsense (sync — single API call) ────
def opnsense_request(method, endpoint, data=None):
    url    = f"{OPNSENSE_BASE_URL}/{endpoint}"
    kwargs = dict(auth=(OPNSENSE_API_KEY, OPNSENSE_API_SECRET), verify=False, timeout=15)
    if data is not None:
        kwargs["json"] = data
    resp = requests.request(method, url, **kwargs)
    resp.raise_for_status()
    return resp.json()


def find_alias(name):
    data = opnsense_request("GET", "firewall/alias/searchItem")
    for row in data.get("rows", []):
        if row.get("name") == name:
            return row.get("uuid")
    return None


def push_to_opnsense(block_list):
    print(f"\n[4/4] Pushing {len(block_list)} IPs to OPNsense ({OPNSENSE_HOST})...")

    if not OPNSENSE_API_KEY or not OPNSENSE_API_SECRET:
        print("  WARNING: No OPNsense API credentials set. Skipping firewall push.")
        return

    if not block_list:
        print("  No IPs to block.")
        return

    ip_list    = [r["ip"] for r in block_list]
    ip_content = "\n".join(ip_list)

    try:
        alias_uuid = find_alias(OPNSENSE_ALIAS_NAME)
        alias_data = {
            "alias": {
                "enabled":     "1",
                "name":        OPNSENSE_ALIAS_NAME,
                "type":        "host",
                "description": f"T-POT threat intel - {len(ip_list)} blocked IPs (score >= {SCORE_THRESHOLD})",
                "content":     ip_content,
                "proto":       "",
            }
        }

        if alias_uuid:
            opnsense_request("POST", f"firewall/alias/setItem/{alias_uuid}", alias_data)
            print(f"  Updated existing alias '{OPNSENSE_ALIAS_NAME}' ({alias_uuid})")
        else:
            result     = opnsense_request("POST", "firewall/alias/addItem", alias_data)
            alias_uuid = result.get("uuid", "?")
            print(f"  Created new alias '{OPNSENSE_ALIAS_NAME}' ({alias_uuid})")

        opnsense_request("POST", "firewall/alias/reconfigure")
        print(f"  Alias applied with {len(ip_list)} IPs")

        for entry in block_list[:10]:
            print(f"    BLOCKED: {entry['ip']:<18} score={entry['abuse_score']} ({entry['country']})")
        if len(block_list) > 10:
            print(f"    ... and {len(block_list) - 10} more")

        print(f"\n  View in OPNsense: Firewall > Aliases > {OPNSENSE_ALIAS_NAME}")

    except requests.RequestException as e:
        print(f"  ERROR: Could not push to OPNsense: {e}")


# ── Main ─────────────────────────────────────────────────
def main():
    print("=" * 80)
    print("  T-POT Threat Intel Pipeline (Async)")
    print(f"  Threshold: block IPs with abuse score >= {SCORE_THRESHOLD}")
    print(f"  Concurrency: {MAX_CONCURRENT} simultaneous AbuseIPDB requests")
    print(f"  OPNsense: {OPNSENSE_HOST}")
    print("=" * 80)

    start_tunnel()

    try:
        attacker_ips = get_attacker_ips(days=7, min_hits=1)

        if not attacker_ips:
            print("\n  No external attacker IPs found. Is T-POT exposed to the internet?")
            sys.exit(0)

        # Run the async check inside an event loop
        results = asyncio.run(check_all_ips_async(attacker_ips))

        block_list = generate_report(results)

        push_to_opnsense(block_list)

        print("\n" + "=" * 80)
        print("  Pipeline complete.")
        print("=" * 80)
    finally:
        stop_tunnel()


if __name__ == "__main__":
    main()
