#!/usr/bin/env python3
"""
latency_canary.py  --  "injection to searchable" latency for Wazuh and Splunk.

What it does, per canary:
  1. Makes a unique lowercase token, e.g. siemcanary9f3a1c2b7d4e5f60.
  2. Starts  cmd.exe /c echo <token>  on this Windows host. Sysmon logs that as Event ID 1,
     and BOTH the Wazuh agent and the Splunk forwarder collect it.
  3. Immediately polls BOTH platforms' search APIs (about every 100 ms, one thread each)
     until the token is searchable:
        Splunk : REST export endpoint on 127.0.0.1:8089 (needs SPLUNK_TOKEN)
        Wazuh  : indexer search on 127.0.0.1:9200, index wazuh-alerts-*  (needs a custom rule
                 that raises an alert for the token, see rule 100200)
  4. Records the time from step 2 to the poll that first found it.

Clock: everything is measured with ONE monotonic clock in this ONE process, so there is no
clock-sync problem between Windows and WSL2.

Resolution: each reading is an UPPER bound. The true moment the event became searchable is
somewhere between the previous poll and the poll that found it, so the error is about
(poll round trip + sleep interval). The script records the round trip so you can state it.

Secrets: read from environment variables only. Never printed, never written to the CSV.
    SPLUNK_TOKEN, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD

Usage (administrator PowerShell, from the scripts folder):
    py latency_canary.py --n 1 --warmup 0 --out ..\\data\\latency_probe.csv     (probe: 1 canary)
    py latency_canary.py --n 30 --warmup 3 --out ..\\data\\latency_canary.csv   (real run)
    py latency_canary.py --n 30 --warmup 3 --gap 5 --jitter 8 --out ..\\data\\latency_canary.csv   (random spacing)
"""
import argparse
import base64
import csv
import json
import os
import random
import ssl
import statistics
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone

CTX = ssl._create_unverified_context()  # localhost services use self-signed certificates
SPLUNK_URL = "https://127.0.0.1:8089/services/search/jobs/export"
WAZUH_URL = "https://127.0.0.1:9200/wazuh-alerts-*/_search"
CREATE_NO_WINDOW = 0x08000000


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def splunk_found(uid, token, index):
    data = urllib.parse.urlencode({
        "search": 'search index=%s "%s" | head 1' % (index, uid),
        "output_mode": "json",
        "earliest_time": "-15m",
    }).encode()
    req = urllib.request.Request(SPLUNK_URL, data=data,
                                 headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(req, context=CTX, timeout=20) as r:
        body = r.read().decode("utf-8", "replace")
    return '"result"' in body


def wazuh_found(uid, user, pw, field):
    body = json.dumps({"size": 1, "query": {"match": {field: uid}}}).encode()
    cred = base64.b64encode(("%s:%s" % (user, pw)).encode()).decode()
    req = urllib.request.Request(WAZUH_URL, data=body,
                                 headers={"Authorization": "Basic " + cred,
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, context=CTX, timeout=20) as r:
        res = json.loads(r.read().decode("utf-8", "replace"))
    total = res.get("hits", {}).get("total", {})
    value = total.get("value", 0) if isinstance(total, dict) else total
    return value > 0


def poll(name, check, t0_pc, out, timeout_s, interval_s):
    round_trips = []
    deadline = time.perf_counter() + timeout_s
    while time.perf_counter() < deadline:
        a = time.perf_counter_ns()
        try:
            hit = check()
        except Exception as e:  # keep the error text, never secrets
            out[name] = {"status": "ERROR", "error": str(e)[:150], "polls": len(round_trips)}
            return
        b = time.perf_counter_ns()
        round_trips.append((b - a) / 1e6)
        if hit:
            out[name] = {
                "status": "OK",
                "latency_s": (b - t0_pc) / 1e9,
                "polls": len(round_trips),
                "median_rt_ms": statistics.median(round_trips),
            }
            return
        time.sleep(interval_s)
    out[name] = {"status": "TIMEOUT", "polls": len(round_trips),
                 "median_rt_ms": statistics.median(round_trips) if round_trips else ""}


def one_canary(args, creds):
    uid = "siemcanary" + uuid.uuid4().hex[:16]
    out = {}
    t0_wall = utc_now_iso()
    t0_pc = time.perf_counter_ns()
    subprocess.Popen(["cmd.exe", "/c", "echo", uid], creationflags=CREATE_NO_WINDOW,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    threads = [
        threading.Thread(target=poll, args=(
            "splunk", lambda: splunk_found(uid, creds["splunk_token"], args.splunk_index),
            t0_pc, out, args.timeout, args.interval)),
        threading.Thread(target=poll, args=(
            "wazuh", lambda: wazuh_found(uid, creds["wz_user"], creds["wz_pass"], args.wazuh_field),
            t0_pc, out, args.timeout, args.interval)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(args.timeout + 30)
    return uid, t0_wall, out


def pct(sorted_vals, p):
    if not sorted_vals:
        return ""
    k = max(0, min(len(sorted_vals) - 1, int(round(p * (len(sorted_vals) - 1)))))
    return sorted_vals[k]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30, help="measured canaries")
    ap.add_argument("--warmup", type=int, default=3, help="extra canaries at the start, flagged warmup=1")
    ap.add_argument("--gap", type=float, default=8.0, help="seconds to wait between canaries")
    ap.add_argument("--jitter", type=float, default=0.0,
                    help="random extra wait of 0..jitter seconds added to every gap. Use 7 or more so the canaries do not lock onto one fixed phase of the indexer's 5 s refresh cycle")
    ap.add_argument("--interval", type=float, default=0.1, help="sleep between polls (s)")
    ap.add_argument("--timeout", type=float, default=60.0, help="give up per platform after (s)")
    ap.add_argument("--splunk-index", default="main")
    ap.add_argument("--wazuh-field", default="full_log",
                    help="indexer field that contains the event text (try data.win.eventdata.commandLine)")
    ap.add_argument("--out", default=os.path.join("..", "data", "latency_canary.csv"))
    args = ap.parse_args()

    creds = {
        "splunk_token": os.environ.get("SPLUNK_TOKEN", ""),
        "wz_user": os.environ.get("WAZUH_INDEXER_USER", ""),
        "wz_pass": os.environ.get("WAZUH_INDEXER_PASSWORD", ""),
    }
    missing = [k for k, v in creds.items() if not v]
    if missing:
        print("Missing environment variables for: %s. Set SPLUNK_TOKEN, WAZUH_INDEXER_USER, "
              "WAZUH_INDEXER_PASSWORD and reopen the window. Nothing was run." % ", ".join(missing))
        sys.exit(1)

    new_file = not os.path.exists(args.out)
    fields = ["canary_id", "warmup", "gap_before_s", "t0_utc",
              "splunk_status", "splunk_latency_s", "splunk_polls", "splunk_median_rt_ms",
              "wazuh_status", "wazuh_latency_s", "wazuh_polls", "wazuh_median_rt_ms", "note"]
    rows = []
    with open(args.out, "a", newline="", encoding="ascii") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        if new_file:
            w.writeheader()
        total = args.warmup + args.n
        gap_used = ""
        for i in range(total):
            warm = 1 if i < args.warmup else 0
            uid, t0, out = one_canary(args, creds)
            s = out.get("splunk", {})
            z = out.get("wazuh", {})
            row = {
                "canary_id": uid, "warmup": warm, "gap_before_s": gap_used, "t0_utc": t0,
                "splunk_status": s.get("status", ""),
                "splunk_latency_s": ("%.3f" % s["latency_s"]) if "latency_s" in s else "",
                "splunk_polls": s.get("polls", ""),
                "splunk_median_rt_ms": ("%.0f" % s["median_rt_ms"]) if s.get("median_rt_ms", "") != "" else "",
                "wazuh_status": z.get("status", ""),
                "wazuh_latency_s": ("%.3f" % z["latency_s"]) if "latency_s" in z else "",
                "wazuh_polls": z.get("polls", ""),
                "wazuh_median_rt_ms": ("%.0f" % z["median_rt_ms"]) if z.get("median_rt_ms", "") != "" else "",
                "note": (s.get("error", "") + " " + z.get("error", "")).strip(),
            }
            w.writerow(row)
            fh.flush()
            rows.append(row)
            print("[%d/%d]%s splunk=%s %ss | wazuh=%s %ss %s" % (
                i + 1, total, " (warmup)" if warm else "",
                row["splunk_status"], row["splunk_latency_s"],
                row["wazuh_status"], row["wazuh_latency_s"], row["note"]))
            if i < total - 1:
                gap_used = "%.3f" % (args.gap + random.uniform(0, args.jitter))
                time.sleep(float(gap_used))

    print("\nSummary (measured canaries only, warmup excluded):")
    for name in ("splunk", "wazuh"):
        vals = sorted(float(r[name + "_latency_s"]) for r in rows
                      if r["warmup"] == 0 and r[name + "_status"] == "OK")
        bad = sum(1 for r in rows if r["warmup"] == 0 and r[name + "_status"] != "OK")
        if vals:
            print("  %-6s n=%d  median=%.3f s  p95=%.3f s  min=%.3f s  max=%.3f s  not-found=%d" % (
                name, len(vals), statistics.median(vals), pct(vals, 0.95), vals[0], vals[-1], bad))
        else:
            print("  %-6s no successful readings, not-found=%d" % (name, bad))
    print("Each value is an upper bound within about (poll round trip + %.0f ms sleep)." % (args.interval * 1000))


if __name__ == "__main__":
    main()
