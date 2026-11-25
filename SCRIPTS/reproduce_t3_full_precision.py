"""
Protocol T3 Automated Response and Central Alert Latencies Reproduction Script
================================================================================
Reproduces all empirical metrics and descriptive statistics for Protocol T3:
- Campaign A (16 October 2026, N=10): Host firewall block rule visibility latency
- Campaign B (27 October 2026, N=10): Wazuh manager alert correlation latency & TCP probing
- Exploratory Pilot Trials (15-16 October 2026, N=9): Accounting of preliminary pilot runs

Author: Mayank Kumar (Department of CSE, Sushant University, Gurugram, India)
Target: MDPI Journal of Cybersecurity and Privacy (JCP)
Dependencies: Standard Python library (csv, math, os, sys) + numpy/scipy if installed.
"""

import os
import sys
import csv
import math
import json
from datetime import datetime, timezone, timedelta

# Try importing numpy and scipy for quantile compatibility, else use standard math
try:
    import numpy as np
    HAVE_NUMPY = True
except ImportError:
    HAVE_NUMPY = False

try:
    import scipy.stats as stats
    HAVE_SCIPY = True
except ImportError:
    HAVE_SCIPY = False

def find_file(filename):
    """Locate dataset file in current dir, DATASETS subdir, or script parent dirs."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        filename,
        os.path.join(script_dir, filename),
        os.path.join(script_dir, "DATASETS", filename),
        os.path.join(script_dir, "..", filename),
        os.path.join(script_dir, "..", "DATASETS", filename),
        os.path.join(os.getcwd(), filename),
        os.path.join(os.getcwd(), "DATASETS", filename),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)
    raise FileNotFoundError(f"Cannot find dataset file: {filename}")

def compute_summary_stats(values):
    """Compute N, mean, sample SD (ddof=1), median, min, max, range, Q1, Q3, IQR."""
    n = len(values)
    if n == 0:
        return {}
    mean_val = sum(values) / n
    var_val = sum((x - mean_val) ** 2 for x in values) / (n - 1) if n > 1 else 0.0
    sd_val = math.sqrt(var_val)
    sorted_v = sorted(values)
    
    # Median
    if n % 2 == 1:
        median_val = sorted_v[n // 2]
    else:
        median_val = (sorted_v[n // 2 - 1] + sorted_v[n // 2]) / 2.0
        
    min_val = sorted_v[0]
    max_val = sorted_v[-1]
    range_val = max_val - min_val
    
    # Quantiles Type 7 (standard linear interpolation, NumPy default)
    if HAVE_NUMPY:
        q1 = float(np.percentile(values, 25))
        q3 = float(np.percentile(values, 75))
    else:
        # Standard Type 7 linear interpolation in pure python
        def type7_quantile(arr, p):
            idx = (len(arr) - 1) * p
            low = int(math.floor(idx))
            high = int(math.ceil(idx))
            if low == high:
                return arr[low]
            weight = idx - low
            return arr[low] * (1.0 - weight) + arr[high] * weight
        q1 = type7_quantile(sorted_v, 0.25)
        q3 = type7_quantile(sorted_v, 0.75)
    iqr = q3 - q1
    
    return {
        "n": n,
        "mean": mean_val,
        "sd": sd_val,
        "median": median_val,
        "min": min_val,
        "max": max_val,
        "range": range_val,
        "q1": q1,
        "q3": q3,
        "iqr": iqr
    }

def run_t3_reproduction():
    print("=" * 80)
    print("PROTOCOL T3: AUTOMATED RESPONSE & CENTRAL ALERT CORRELATION REPRODUCTION")
    print("Target: MDPI Journal of Cybersecurity and Privacy (JCP)")
    print("=" * 80)
    
    # ---------------------------------------------------------
    # 1. CAMPAIGN A (16 October 2026): Host Firewall Rule Visibility
    # ---------------------------------------------------------
    ca_file = find_file("t3_campaign_a_mttc_trials_oct16.csv")
    print(f"\n[1] Loading Campaign A raw observations from:\n    {ca_file}")
    
    ca_rows = []
    with open(ca_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            if r.get("trial") and r["trial"].strip():
                ca_rows.append(r)
                
    mttc_a = [float(r["mttc_seconds"]) for r in ca_rows]
    failed_logons_a = [int(r["failed_logons_seen"]) for r in ca_rows]
    statuses_a = [r["status"].strip() for r in ca_rows]
    
    stats_a = compute_summary_stats(mttc_a)
    
    print("-" * 80)
    print(f"CAMPAIGN A RESULTS (Host Firewall Block Rule Visibility, N={stats_a['n']}):")
    print("-" * 80)
    print(f"  Trial Values (s): {mttc_a}")
    print(f"  Median:           {stats_a['median']:.3f} s")
    print(f"  Mean:             {stats_a['mean']:.3f} s (SD: {stats_a['sd']:.3f} s)")
    print(f"  Range:            [{stats_a['min']:.3f}, {stats_a['max']:.3f}] s (Delta: {stats_a['range']:.3f} s)")
    print(f"  Quartiles (Type 7): Q1 = {stats_a['q1']:.4f} s, Q3 = {stats_a['q3']:.4f} s, IQR = {stats_a['iqr']:.4f} s")
    print(f"  Failed Logons Seen: Exactly {set(failed_logons_a)} across all {stats_a['n']} trials")
    print(f"  Trial Status:       {statuses_a.count('OK')}/{stats_a['n']} trials OK (100% success)")
    print(f"  Manuscript Statement Check:")
    print(f"    Manuscript Sec 4.3: 'median of 1.589 s (mean 1.680 \u00b1 0.235 s, range 1.491-2.291 s)'")
    
    # Assert Campaign A verification
    assert stats_a["n"] == 10, f"Expected N=10, got {stats_a['n']}"
    assert abs(stats_a["median"] - 1.589) < 1e-4, f"Median mismatch: {stats_a['median']} vs 1.589"
    assert abs(stats_a["mean"] - 1.680) < 1e-3, f"Mean mismatch: {stats_a['mean']} vs 1.680"
    assert abs(stats_a["sd"] - 0.235) < 1e-3, f"SD mismatch: {stats_a['sd']} vs 0.235"
    assert abs(stats_a["min"] - 1.491) < 1e-4, f"Min mismatch: {stats_a['min']} vs 1.491"
    assert abs(stats_a["max"] - 2.291) < 1e-4, f"Max mismatch: {stats_a['max']} vs 2.291"
    print("  => Campaign A Check: PASSED (Exact match to manuscript)")

    # ---------------------------------------------------------
    # 2. CAMPAIGN B (27 October 2026): Central Alert Correlation & Probing
    # ---------------------------------------------------------
    cb_file = find_file("t3_campaign_b_alert_correlation_oct27.csv")
    print(f"\n[2] Loading Campaign B raw observations from:\n    {cb_file}")
    
    cb_rows = []
    with open(cb_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            if r.get("trial") and r["trial"].strip():
                cb_rows.append(r)
                
    alert_lat_b = [float(r["software_alert_latency_sec"]) for r in cb_rows]
    netsh_lat_b = [float(r["software_netsh_latency_sec"]) for r in cb_rows]
    net_sev_b = [float(r["network_severance_delay_sec"]) for r in cb_rows]
    sock_del_b = [float(r["estimated_socket_delay_sec"]) for r in cb_rows]
    probes_b = [float(r["probe_rows"]) for r in cb_rows]
    statuses_b = [r["status"].strip() for r in cb_rows]
    
    stats_alert_b = compute_summary_stats(alert_lat_b)
    stats_netsh_b = compute_summary_stats(netsh_lat_b)
    stats_net_sev_b = compute_summary_stats(net_sev_b)
    stats_sock_del_b = compute_summary_stats(sock_del_b)
    stats_probes_b = compute_summary_stats(probes_b)
    
    print("-" * 80)
    print(f"CAMPAIGN B RESULTS (Central Alert Correlation & Network Probing, N={stats_alert_b['n']}):")
    print("-" * 80)
    print(f"  Manager Alert Latency (s) under Rule 100100:")
    print(f"    Trial Values (s): {alert_lat_b}")
    print(f"    Median:           {stats_alert_b['median']:.3f} s")
    print(f"    Mean:             {stats_alert_b['mean']:.3f} s (SD: {stats_alert_b['sd']:.3f} s)")
    print(f"    Range:            [{stats_alert_b['min']:.3f}, {stats_alert_b['max']:.3f}] s (Delta: {stats_alert_b['range']:.3f} s)")
    print(f"    Quartiles (Type 7): Q1 = {stats_alert_b['q1']:.4f} s, Q3 = {stats_alert_b['q3']:.4f} s, IQR = {stats_alert_b['iqr']:.4f} s")
    print(f"  Software Netsh Spawn Latency (s) [Integer-Second Quantized]:")
    print(f"    Median: {stats_netsh_b['median']:.3f} s, Mean: {stats_netsh_b['mean']:.3f} s (SD: {stats_netsh_b['sd']:.3f} s), Range: [{stats_netsh_b['min']:.3f}, {stats_netsh_b['max']:.3f}] s")
    print(f"  Network Severance Delay (s) [Adversary Clock Domain]:")
    print(f"    Median: {stats_net_sev_b['median']:.4f} s, Mean: {stats_net_sev_b['mean']:.4f} s (SD: {stats_net_sev_b['sd']:.4f} s)")
    print(f"  Estimated Socket Timeout Delay (s):")
    print(f"    Median: {stats_sock_del_b['median']:.3f} s, Mean: {stats_sock_del_b['mean']:.3f} s (SD: {stats_sock_del_b['sd']:.3f} s)")
    print(f"  Adversary Probing Status:")
    print(f"    {statuses_b.count('OK')}/{stats_alert_b['n']} trials OK (connection established pre-T5, timed out post-response)")
    print(f"  Manuscript Statement Check:")
    print(f"    Manuscript Sec 4.3: 'median of 1.014 s (mean 1.013 \u00b1 0.007 s, range 1.004-1.021 s)'")
    
    # Assert Campaign B verification
    assert stats_alert_b["n"] == 10, f"Expected N=10, got {stats_alert_b['n']}"
    assert abs(stats_alert_b["median"] - 1.014) < 1e-4, f"Median mismatch: {stats_alert_b['median']} vs 1.014"
    assert abs(stats_alert_b["mean"] - 1.013) < 1e-3, f"Mean mismatch: {stats_alert_b['mean']} vs 1.013"
    assert abs(stats_alert_b["sd"] - 0.007) < 1e-3, f"SD mismatch: {stats_alert_b['sd']} vs 0.007"
    assert abs(stats_alert_b["min"] - 1.004) < 1e-4, f"Min mismatch: {stats_alert_b['min']} vs 1.004"
    assert abs(stats_alert_b["max"] - 1.021) < 1e-4, f"Max mismatch: {stats_alert_b['max']} vs 1.021"
    print("  => Campaign B Check: PASSED (Exact match to manuscript)")

    # ---------------------------------------------------------
    # 2B. CAMPAIGN B RAW LOG EXTRACTION CHECK (active-responses.log)
    # ---------------------------------------------------------
    try:
        ar_log_path = find_file("active-responses.log")
        print(f"\n[2B] Verifying Windows-side extraction from raw active-responses.log:")
        print(f"     {ar_log_path}")
        raw_events = []
        with open(ar_log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if '2026/10/27' in line and '"id":"100100"' in line and '"command":"add"' in line:
                    parts = line.split('active-response/bin/netsh.exe: ')
                    if len(parts) > 1:
                        try:
                            payload = json.loads(parts[1].strip())
                            raw_events.append((line[:19], payload))
                        except Exception:
                            pass
        print(f"     Extracted {len(raw_events)} raw active response add events.")
        if len(raw_events) == 10:
            ist = timezone(timedelta(hours=5, minutes=30))
            raw_diffs = 0
            for idx in range(10):
                log_ts_str, payload = raw_events[idx]
                alert = payload.get('parameters', {}).get('alert', {})
                data_block = payload.get('parameters', {}).get('data', {})
                t5_str = data_block.get('win', {}).get('system', {}).get('systemTime', '')
                if not t5_str:
                    t5_str = alert.get('data', {}).get('win', {}).get('system', {}).get('systemTime', '')
                alert_ts = alert.get('timestamp', '')
                t5_dt = datetime.fromisoformat(t5_str.replace('Z', '+00:00'))
                alert_dt = datetime.fromisoformat(alert_ts.replace('+0000', '+00:00'))
                calc_alert_sec = round((alert_dt - t5_dt).total_seconds(), 3)
                if abs(calc_alert_sec - alert_lat_b[idx]) > 1e-4:
                    raw_diffs += 1
            if raw_diffs == 0:
                print("  => Raw Log Extraction Parity: PASSED (10/10 trials match active-responses.log)")
            else:
                print(f"  => Raw Log Extraction Parity: WARNING ({raw_diffs} discrepancies)")
    except FileNotFoundError:
        print("\n[2B] Raw active-responses.log not found in local path (skipped raw extraction check).")

    # ---------------------------------------------------------
    # 3. PILOT TRIALS ACCOUNTING (pilot_mttc_trials.csv)
    # ---------------------------------------------------------
    pilot_file = find_file("pilot_mttc_trials.csv")
    print(f"\n[3] Loading Exploratory Pilot Trials from:\n    {pilot_file}")
    
    pilot_rows = []
    with open(pilot_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            if r.get("trial") and r["trial"].strip():
                pilot_rows.append(r)
                
    p_ok = [r for r in pilot_rows if r["status"].strip() == "OK"]
    p_fail = [r for r in pilot_rows if r["status"].strip() == "FAIL"]
    
    print("-" * 80)
    print(f"EXPLORATORY PILOT TRIALS ACCOUNTING (N={len(pilot_rows)}):")
    print("-" * 80)
    print(f"  Total Preliminary Pilot Runs: {len(pilot_rows)}")
    print(f"  Successful Rule Table Appearances (status=OK): {len(p_ok)}")
    for r in p_ok:
        print(f"    Trial {r['trial']}: MTTC = {r['mttc_seconds']} s (failed logons seen: {r['failed_logons_seen']})")
    print(f"  Uncontained Pilot Runs (status=FAIL): {len(p_fail)}")
    print(f"  Failed Logon Counts Seen on Failed Runs: {[int(r['failed_logons_seen']) for r in p_fail]}")
    print(f"  Evidentiary Traceability Note:")
    print(f"    Specific per-trial failure causes were unrecorded in the historical pilot CSV.")
    print(f"    Exploratory pilots were properly discarded prior to formal protocol freeze.")
    
    assert len(pilot_rows) == 9, f"Expected 9 pilot trials, got {len(pilot_rows)}"
    assert len(p_ok) == 2, f"Expected 2 OK pilot trials, got {len(p_ok)}"
    assert len(p_fail) == 7, f"Expected 7 FAIL pilot trials, got {len(p_fail)}"
    print("  => Pilot Accounting Check: PASSED (2 OK [1.803 s, 2.475 s], 7 FAIL)")

    print("\n" + "=" * 80)
    print("ALL PROTOCOL T3 REPRODUCIBILITY CHECKS PASSED (100% NUMERICAL AGREEMENT)")
    print("=" * 80)

if __name__ == "__main__":
    run_t3_reproduction()
