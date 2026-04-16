# Async vs Sync Benchmark — AbuseIPDB IP Reputation Checks

> Part of the [Automated IP Blocking Pipeline](Automated-IP-Blocking-Pipeline.md)

After getting the sync version working, I built an async version using `asyncio` and `aiohttp` to see how much faster concurrent requests would be. The sync script checks one IP at a time — it fires a request, waits for the response, then moves to the next. The async version fires up to 10 requests simultaneously and collects results as they come back.

Running both versions back to back against live T-POT data:

| Version | IPs Checked | Time | Per IP |
|---------|-------------|------|--------|
| Sync (`ip_reputation_check.py`) | 89 | 34.58s | 0.38s |
| Async (`ip_reputation_check_async.py`) | 90 | 14.13s | 0.16s |

**~2.5x faster** with 10 concurrent requests. You can also tell from the output — the sync version always prints results in order (1, 2, 3...) while the async version prints them as each request finishes, so the numbers jump around depending on which API response came back first.

![Sync pipeline run](screenshots/async/01-sync-run.png)

![Async pipeline run](screenshots/async/02-async-run.png)

The semaphore cap of 10 concurrent requests keeps it from hammering the AbuseIPDB rate limit. Removing the cap would be faster but risks getting rate limited on the free tier (1000 checks/day).
