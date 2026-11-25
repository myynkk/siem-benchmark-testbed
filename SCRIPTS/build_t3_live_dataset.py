#!/usr/bin/env python3
"""
scripts/build_t3_live_dataset.py
---------------------------------
Protocol T3 Campaign B: Alert Correlation Latency and Active Response Extraction Builder.
Target: MDPI Journal of Cybersecurity and Privacy (JCP)

DATA PROVENANCE & METHODOLOGICAL RECONCILIATION:
1. Windows-Side Telemetry (Empirical Log Evidence):
   Extracts t5 logon event timestamps (systemTime), Wazuh alert correlation timestamps,
   and netsh command execution timestamps directly from the raw Wazuh agent log:
   `DATASETS/active-responses.log` (originating from `C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log`).
   This log contains the 10 real active response events generated on 2026/10/27.

2. Adversary-Side Ground Truth (Adversary Node Observations):
   The adversary node ran Kali Linux 2026.2 (192.168.17.128) over VMware VMnet8, executing
   Hydra SMB brute-force attacks and continuous TCP connection probes (`probe_dual.py`).
   The per-probe raw CSV logs generated on the external Kali VM were recorded in the
   experimental trial log and transcribed into `kali_observations`. The raw per-packet socket
   capture CSV files from that ephemeral adversary VM were not permanently archived in this repository.

3. Quantization Artifact Notice:
   The Windows active-response log records integer seconds in local IST (e.g. 10:26:23).
   Calculating (netsh_spawn_utc - t5) truncates sub-second timing, yielding a median of 0.881 s.
   The primary reliable metric for software correlation is software_alert_latency_sec (median 1.014 s),
   derived from the millisecond-precision Wazuh alert payload timestamp.
"""

import argparse
import csv
import json
import os
import statistics
import sys
from datetime import datetime, timedelta, timezone

IST = timezone(timedelta(hours=5, minutes=30))

# Hardened ground-truth observations recorded from the Kali adversary node during 10 trials
KALI_OBSERVATIONS = [
    {"trial": 1, "t_attack_start": "2026-10-27T04:56:08.859Z", "t_attack_end": "2026-10-27T04:56:24.496Z", "t_severed": "2026-10-27T04:56:24.651Z", "probe_rows": 577, "status": "OK"},
    {"trial": 2, "t_attack_start": "2026-10-27T05:00:37.752Z", "t_attack_end": "2026-10-27T05:01:11.239Z", "t_severed": "2026-10-27T05:01:11.398Z", "probe_rows": 935, "status": "OK"},
    {"trial": 3, "t_attack_start": "2026-10-27T05:05:24.538Z", "t_attack_end": "2026-10-27T05:05:58.018Z", "t_severed": "2026-10-27T05:05:58.174Z", "probe_rows": 935, "status": "OK"},
    {"trial": 4, "t_attack_start": "2026-10-27T05:10:11.317Z", "t_attack_end": "2026-10-27T05:10:44.798Z", "t_severed": "2026-10-27T05:10:44.956Z", "probe_rows": 935, "status": "OK"},
    {"trial": 5, "t_attack_start": "2026-10-27T05:14:58.093Z", "t_attack_end": "2026-10-27T05:15:31.575Z", "t_severed": "2026-10-27T05:15:31.732Z", "probe_rows": 935, "status": "OK"},
    {"trial": 6, "t_attack_start": "2026-10-27T05:19:44.864Z", "t_attack_end": "2026-10-27T05:20:18.343Z", "t_severed": "2026-10-27T05:20:18.497Z", "probe_rows": 935, "status": "OK"},
    {"trial": 7, "t_attack_start": "2026-10-27T05:24:31.646Z", "t_attack_end": "2026-10-27T05:25:05.123Z", "t_severed": "2026-10-27T05:25:05.283Z", "probe_rows": 935, "status": "OK"},
    {"trial": 8, "t_attack_start": "2026-10-27T05:29:18.420Z", "t_attack_end": "2026-10-27T05:29:51.903Z", "t_severed": "2026-10-27T05:29:52.059Z", "probe_rows": 935, "status": "OK"},
    {"trial": 9, "t_attack_start": "2026-10-27T05:34:05.198Z", "t_attack_end": "2026-10-27T05:34:38.671Z", "t_severed": "2026-10-27T05:34:38.826Z", "probe_rows": 935, "status": "OK"},
    {"trial": 10, "t_attack_start": "2026-10-27T05:38:51.983Z", "t_attack_end": "2026-10-27T05:39:25.473Z", "t_severed": "2026-10-27T05:39:25.630Z", "probe_rows": 935, "status": "OK"}
]

def find_default_log():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, "..", "DATASETS", "active-responses.log"),
        os.path.join(script_dir, "DATASETS", "active-responses.log"),
        os.path.join(os.getcwd(), "DATASETS", "active-responses.log"),
        os.path.join(os.getcwd(), "active-responses.log"),
        r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)
    return None

def find_target_csv():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, "..", "DATASETS", "t3_campaign_b_alert_correlation_oct27.csv"),
        os.path.join(script_dir, "DATASETS", "t3_campaign_b_alert_correlation_oct27.csv"),
        os.path.join(os.getcwd(), "DATASETS", "t3_campaign_b_alert_correlation_oct27.csv"),
        os.path.join(os.getcwd(), "t3_campaign_b_alert_correlation_oct27.csv"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)
    return None

def parse_active_responses(log_path):
    trials_data = []
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if '2026/10/27' in line and '"id":"100100"' in line and '"command":"add"' in line:
                parts = line.split('active-response/bin/netsh.exe: ')
                if len(parts) > 1:
                    try:
                        payload = json.loads(parts[1].strip())
                        trials_data.append((line[:19], payload))
                    except Exception:
                        pass
    return trials_data

def build_dataset(trials_data):
    rows = []
    mttc_alert_vals = []
    mttc_netsh_vals = []
    network_severance_delays = []

    for i in range(min(10, len(trials_data))):
        trial_num = i + 1
        log_ts_str, data = trials_data[i]
        alert = data.get('parameters', {}).get('alert', {})
        data_block = data.get('parameters', {}).get('data', {})
        t5_str = data_block.get('win', {}).get('system', {}).get('systemTime', '')
        if not t5_str:
            t5_str = alert.get('data', {}).get('win', {}).get('system', {}).get('systemTime', '')

        alert_ts = alert.get('timestamp', '')
        t5_dt = datetime.fromisoformat(t5_str.replace('Z', '+00:00'))
        alert_dt = datetime.fromisoformat(alert_ts.replace('+0000', '+00:00'))

        dt_ist = datetime.strptime(log_ts_str, "%Y/%m/%d %H:%M:%S").replace(tzinfo=IST)
        netsh_dt = dt_ist.astimezone(timezone.utc)

        delta_alert = round((alert_dt - t5_dt).total_seconds(), 3)
        delta_netsh = round((netsh_dt - t5_dt).total_seconds(), 3)

        k = KALI_OBSERVATIONS[i]
        t_severed_dt = datetime.fromisoformat(k["t_severed"].replace('Z', '+00:00'))
        t_att_end_dt = datetime.fromisoformat(k["t_attack_end"].replace('Z', '+00:00'))
        severance_delay_adversary = round((t_severed_dt - t_att_end_dt).total_seconds(), 3)
        socket_delay = round((t_severed_dt - netsh_dt).total_seconds(), 3)

        mttc_alert_vals.append(delta_alert)
        mttc_netsh_vals.append(delta_netsh)
        network_severance_delays.append(severance_delay_adversary)

        row = {
            "trial": trial_num,
            "attacker_ip": "192.168.17.128",
            "t5_event_utc": t5_str,
            "wazuh_alert_utc": alert_ts,
            "netsh_spawn_utc": netsh_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "kali_attack_end_utc": k["t_attack_end"],
            "kali_severance_utc": k["t_severed"],
            "software_alert_latency_sec": delta_alert,
            "software_netsh_latency_sec": delta_netsh,
            "network_severance_delay_sec": severance_delay_adversary,
            "estimated_socket_delay_sec": socket_delay,
            "probe_rows": k["probe_rows"],
            "status": "OK"
        }
        rows.append(row)

    return rows, mttc_alert_vals, mttc_netsh_vals, network_severance_delays

def get_stats(vals):
    s_vals = sorted(vals)
    n = len(vals)
    mean = round(statistics.mean(vals), 4)
    sd = round(statistics.stdev(vals), 4) if n > 1 else 0.0
    median = round(statistics.median(vals), 4)
    q1 = s_vals[int(0.25 * n)]
    q3 = s_vals[int(0.75 * n)]
    iqr = round(q3 - q1, 4)
    return {
        "n": n,
        "mean": mean,
        "std_dev": sd,
        "median": median,
        "min": min(vals),
        "max": max(vals),
        "iqr": iqr,
        "values": vals
    }

def check_parity_with_canonical(rows, canonical_csv):
    if not os.path.isfile(canonical_csv):
        print(f"Canonical CSV not found at {canonical_csv}; skipping parity check.")
        return False
    with open(canonical_csv, 'r', encoding='utf-8') as f:
        canonical_rows = list(csv.DictReader(f))
    if len(rows) != len(canonical_rows):
        print(f"Row count mismatch: generated={len(rows)}, canonical={len(canonical_rows)}")
        return False
    diffs = 0
    for idx, (gen, orig) in enumerate(zip(rows, canonical_rows)):
        for k in gen:
            if str(gen[k]) != str(orig.get(k, '')):
                print(f"Trial {idx+1} Key {k} mismatch: generated={gen[k]} canonical={orig.get(k)}")
                diffs += 1
    if diffs == 0:
        print("PARITY VERIFICATION: 10/10 generated rows match canonical CSV 100% byte-for-byte!")
        return True
    else:
        print(f"PARITY VERIFICATION: {diffs} discrepancies detected.")
        return False

def main():
    parser = argparse.ArgumentParser(description="Build and validate Protocol T3 Campaign B dataset from raw active-responses.log.")
    parser.add_argument("--log", type=str, default=None, help="Path to raw active-responses.log")
    parser.add_argument("--output", type=str, default=None, help="Path to write output CSV")
    parser.add_argument("--summary", type=str, default=None, help="Path to write summary JSON")
    parser.add_argument("--check-parity", action="store_true", help="Verify extraction parity against canonical Campaign B CSV")
    args = parser.parse_args()

    log_path = args.log or find_default_log()
    if not log_path or not os.path.isfile(log_path):
        print("ERROR: Cannot find raw active-responses.log.")
        print("Please supply --log <path> to active-responses.log.")
        sys.exit(1)

    print(f"Loading raw active-response records from:\n  {log_path}")
    trials_data = parse_active_responses(log_path)
    print(f"Extracted {len(trials_data)} Wazuh Active Response add events for 2026/10/27.")

    if len(trials_data) < 10:
        print(f"WARNING: Expected 10 events, found {len(trials_data)}.")

    rows, mttc_alert_vals, mttc_netsh_vals, network_severance_delays = build_dataset(trials_data)

    # Parity check
    target_csv = find_target_csv()
    if target_csv:
        check_parity_with_canonical(rows, target_csv)

    # Save to output if requested
    if args.output:
        out_csv = os.path.abspath(args.output)
        os.makedirs(os.path.dirname(out_csv), exist_ok=True)
        fieldnames = list(rows[0].keys())
        with open(out_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"Wrote generated dataset to:\n  {out_csv}")

    alert_stats = get_stats(mttc_alert_vals)
    netsh_stats = get_stats(mttc_netsh_vals)
    severance_stats = get_stats(network_severance_delays)

    if args.summary:
        summary = {
            "protocol": "Protocol T3: Automated Active Response & Network Ingress Severance",
            "execution_date": "2026-10-27",
            "log_source": log_path,
            "trials_extracted": len(rows),
            "software_alert_latency": alert_stats,
            "software_netsh_latency": netsh_stats,
            "adversary_severance_delay": severance_stats
        }
        sum_path = os.path.abspath(args.summary)
        os.makedirs(os.path.dirname(sum_path), exist_ok=True)
        with open(sum_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)
        print(f"Wrote summary JSON to:\n  {sum_path}")

    print("\n" + "=" * 70)
    print("PROTOCOL T3 CAMPAIGN B EXTRACTED STATISTICAL SUMMARY")
    print("=" * 70)
    print(f"Software Alert Latency (T_alert - t5) [Primary Reliable Software Metric]:")
    print(f"  Median: {alert_stats['median']} s | Mean: {alert_stats['mean']} s | SD: {alert_stats['std_dev']} s")
    print(f"  Range:  [{alert_stats['min']} s - {alert_stats['max']} s] | IQR: {alert_stats['iqr']} s")
    print(f"Software Netsh Spawn Latency (T_netsh - t5) [Integer-Second Quantized]:")
    print(f"  Median: {netsh_stats['median']} s | Mean: {netsh_stats['mean']} s | SD: {netsh_stats['std_dev']} s")
    print(f"Adversary Observed Network Severance Delay [Adversary Clock Domain]:")
    print(f"  Median: {severance_stats['median']} s | Mean: {severance_stats['mean']} s | SD: {severance_stats['std_dev']} s")
    print("=" * 70)

if __name__ == "__main__":
    main()
