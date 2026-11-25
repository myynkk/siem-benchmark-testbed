# Data Dictionary and Reproduction Guide
## Supplementary Data Package for MDPI Journal of Cybersecurity and Privacy (JCP)

**Manuscript Title:** Endpoint-Agent Resource Consumption and Native-Workflow Event Availability: A Single-Host Windows 11 Evaluation of Splunk and Wazuh  
**Author:** Mayank Kumar (Department of CSE, Sushant University, Gurugram, India)  
**Package Archive:** `JCP_SUPPLEMENTARY_DATA_PACKAGE.zip`  
**Date:** November 2026  

---

## 1. Package Inventory & Relative File Hierarchy

This supplementary data archive contains 28 files comprising empirical datasets, collection harnesses, execution logs, statistical verification scripts, and XML rule definitions supporting the findings in the manuscript. The T2 reproduction script requires the pinned Python packages listed in `requirements.txt`; those packages are dependencies, not bundled runtime binaries:

```
JCP_SUPPLEMENTARY_DATA_PACKAGE/
│
├── DATASETS/
│   ├── t1_latency_canary_run2.csv                  # Protocol T1: 30 paired canary execution trials (+3 warmup)
│   ├── t2_raw_samples_3579_rows.csv                # Protocol T2: 3,578 raw 1 Hz agent resource samples (10 paired sessions)
│   ├── t2_paired_analysis_10_sessions.csv          # Protocol T2: Session-level aggregated paired metrics (N=10)
│   ├── t2_telemetry_manifest.json                  # Protocol T2: Session manifest with exact burst start/end timestamps
│   ├── t2_execution.log                            # Protocol T2: Timestamped execution log of service restarts and bursts
│   ├── t3_campaign_a_mttc_trials_oct16.csv         # Protocol T3: Campaign A host firewall rule visibility trials (N=10)
│   ├── t3_campaign_b_alert_correlation_oct27.csv   # Protocol T3: Campaign B central alert correlation latency trials (N=10)
│   ├── pilot_mttc_trials.csv                       # Protocol T3: Preliminary exploratory pilot trials (N=9: 2 OK, 7 FAIL)
│   └── active-responses.log                        # Protocol T3 Campaign B: Raw Windows host active-response execution log
│
├── SCRIPTS/
│   ├── reproduce_all_protocols.py                  # Master automated verification script executing T1, T2, and T3 suites
│   ├── reproduce_t1_full_precision.py              # Protocol T1: Stand-alone recomputation script for Table 1 (N=30)
│   ├── reproduce_t2_full_precision.py              # Protocol T2: Stand-alone recomputation script for Table 2 & 3 (N=10)
│   ├── reproduce_t3_full_precision.py              # Protocol T3: Stand-alone recomputation script for Campaign A & B (N=20)
│   ├── read_t3_summary.py                          # Protocol T3: Summary verification script referenced in reconciliation audit
│   ├── build_t3_live_dataset.py                    # Protocol T3 Campaign B: Extracts alert timestamps from active-responses.log payload
│   ├── probe_dual.py                               # Protocol T3 Campaign B: Concurrent TCP/ICMP socket probe executed on Kali node
│   ├── protocol_t2_runner_public.py                # Protocol T2: Test dispatcher & WMI telemetry sampler
│   ├── latency_canary.py                           # Protocol T1: Canary dispatch & dual API polling harness
│   ├── mttc_trial.ps1                              # Protocol T3: Campaign A high-frequency netsh polling loop
│   └── t3_windows_monitor.ps1                      # Protocol T3: Campaign B Windows-side logon & network monitor
│
├── CONFIGURATIONS/
│   ├── local_rules_live_container_20261018.xml      # Wazuh live container rule snapshot (Rule 100200, Level 5)
│   ├── wazuh_local_rules.xml                       # Wazuh manager custom rules file
│   ├── RULE_100200_PROVENANCE.md                   # Provenance log and hash verification of Rule 100200
│   └── docker-compose.yml                          # Container deployment specification for Wazuh manager/indexer
│
├── requirements.txt                                # Analysis environment dependency specifications
│
└── METADATA/
    ├── README_DATA_DICTIONARY.md                   # This document (data schema & reproduction guide)
    ├── requirements.txt                            # Mirrored analysis dependency specifications
    └── SHA256_MANIFEST.txt                         # Cryptographic SHA-256 hashes of archive contents
```

---

## 2. Experimental Datasets and Schema Specifications

### 2.1. Protocol T1: Canary Event Availability Latency (`DATASETS/t1_latency_canary_run2.csv`)
* **Cadence & Scope:** 33 total rows (Row 1: header, Rows 2–4: 3 warmup trials with `warmup=1` [discarded], Rows 5–34: 30 formal paired trials with `warmup=0`). Randomized inter-trial delays range from 5.196 s to 12.878 s (mean 9.530 s) via `--gap 5 --jitter 8`.
* **Columns (13):**
  - `canary_id` (str): Unique 26-character identifier consisting of the fixed `siemcanary` prefix and a 16-hexadecimal high-entropy suffix (e.g., `siemcanaryf06e2da504e541a0`).
  - `warmup` (int): Binary flag (`1` = warmup run [discarded], `0` = formal evaluation trial).
  - `gap_before_s` (float): Actual randomized sleep delay in seconds executed prior to trial dispatch (5.196 to 12.878 s, mean 9.530 s).
  - `t0_utc` (str): ISO-8601 UTC timestamp of canary process creation dispatch on the Windows 11 host ($T_0$).
  - `splunk_status` (str): Query response status for Splunk search export (`OK`).
  - `splunk_latency_s` (float): Elapsed seconds for Splunk discovery ($T_{Splunk} - T_0$). Median: 2.185 s, Mean: 2.228 s (SD: 0.603 s), IQR: 1.107 s.
  - `splunk_polls` (int): Number of polling query cycles executed prior to event discovery. Median: 3.0 cycles.
  - `splunk_median_rt_ms` (float): Round-trip duration in milliseconds for Splunk search REST API polling calls. Median: 640.0 ms.
  - `wazuh_status` (str): Query response status for Wazuh Indexer query (`OK`).
  - `wazuh_latency_s` (float): Elapsed seconds for Wazuh alert discovery ($T_{Wazuh} - T_0$). Median: 7.085 s, Mean: 6.501 s (SD: 2.203 s), IQR: 3.042 s.
  - `wazuh_polls` (int): Number of polling query cycles executed prior to alert discovery. Median: 62.0 cycles.
  - `wazuh_median_rt_ms` (float): Round-trip duration in milliseconds for Wazuh Indexer REST API polling calls. Median: 9.0 ms.
  - `note` (str): Trial operational annotations.
* **Quantile Specification & Cross-References:**
  - Table 1 and Section 4.1 report standard linear interpolation quartiles (R Type 7 / NumPy default): Splunk Q1 = 1.652 s, Q3 = 2.759 s, IQR = 1.107 s; Wazuh Q1 = 4.895 s, Q3 = 7.937 s, IQR = 3.042 s.

### 2.2. Protocol T2: Raw Host Resource Telemetry (`DATASETS/t2_raw_samples_3579_rows.csv`)
* **Cadence & Scope:** 1,789 one-second paired timestamps per agent, yielding 3,578 combined agent observation rows (3,579 lines including header) sampled across 1,789 paired nominal 1 Hz observation epochs across 10 paired sessions. Data is stored in long-form format (one row per agent observation per timestamp).
* **Columns (10):**
  - `t_utc` (str): ISO-8601 UTC sample timestamp (e.g., `2026-10-26T09:19:30.9958388Z`).
  - `session_id` (int): Profiling session index (1 to 10).
  - `phase` (str): Workload operational phase:
    - `idle`: Post-service-restart observation phase (0–60 s) following a 60 s stabilization delay. Wazuh exhibits active startup decay from 2.7694% down to 1.2444% (+1.5250 pp decay, $p < 0.0001$).
    - `burst`: 100-process creation burst injected over ~10 s at ~10 processes/s (60–120 s). Active injection spans $t \in [1.68, 11.68]$ s.
    - `recovery`: Post-burst system recovery phase (120–180 s).
  - `agent` (str): Target endpoint monitoring agent:
    - `splunk_uf`: Splunk Universal Forwarder process group (`splunkd.exe` parent PID 17368 + `splunk-winevtlog.exe` helper PID 20492).
    - `wazuh_agent`: Wazuh Agent process (`wazuh-agent.exe` PID 21380).
  - `pids` (str): Semicolon-delimited list of active Process IDs monitored during the epoch (e.g., `17368;20492`). Strictly invariant across all 3,578 records.
  - `status` (str): Sample validity flag (`VALID`).
  - `ws_mb` (float): Total Working Set in MiB (all resident physical RAM pages, including shared libraries).
  - `priv_ws_mb` (float): Private Working Set in MiB (dedicated physical RAM uniquely committed to the process group).
  - `commit_mb` (float): Commit Size in MiB (guaranteed virtual address space allocation).
  - `cpu_raw_pct` (float): Raw CPU utilization across all active cores.
  - `cpu_norm_pct` (float): Normalized CPU utilization percentage, calculated as `cpu_raw_pct / 16.0` to represent true fractional load across the 16 logical cores.

### 2.3. Protocol T2: Session-Level Telemetry Manifest (`DATASETS/t2_telemetry_manifest.json`)
* **Cadence & Scope:** JSON metadata recording execution parameters and exact burst telemetry across all 10 sessions.
* **Key Fields:**
  - `burst_telemetry`: Per-session dictionary mapping session ID (1 to 10) to `burst_start_utc`, `burst_end_utc`, `duration_sec` ($10.00 \pm 0.03$ s), and process counts (100 / 100 attempted and succeeded).
  - `session_accounting`: Array verifying completion status (`VALID`) for all 10 sessions.

### 2.4. Protocol T2: Paired Session-Level Aggregates (`DATASETS/t2_paired_analysis_10_sessions.csv`)
* **Cadence & Scope:** 30 summary rows (10 sessions $\times$ 3 phases) representing the formal $N=10$ statistical unit of analysis.
* **Columns (10):** `session_id`, `phase`, `splunk_median_ws_mb`, `wazuh_median_ws_mb`, `delta_ws_mb`, `splunk_median_priv_ws_mb`, `wazuh_median_priv_ws_mb`, `delta_priv_ws_mb`, `splunk_median_commit_mb`, `wazuh_median_commit_mb`, `delta_commit_mb`, `splunk_mean_cpu_norm`, `wazuh_mean_cpu_norm`, `delta_cpu_norm`.

### 2.5. Protocol T3: Automated Response & Containment Datasets

#### Campaign A: Host Firewall Block Rule Table Visibility (`DATASETS/t3_campaign_a_mttc_trials_oct16.csv`)
* **Cadence & Scope:** 10 formal evaluation trials conducted on 16 October 2026 measuring latency from the 5th failed authentication event ($T_5$) to local firewall block rule table visibility via high-frequency `netsh` polling (~150–180 ms cadence).
* **Columns (4):**
  - `trial` (int): Trial number (1 to 10).
  - `failed_logons_seen` (int): Number of failed logon events detected on the host (strictly 5 across all trials).
  - `mttc_seconds` (float): Elapsed seconds from $T_5$ to firewall rule appearance. Median: 1.589 s, Mean: 1.680 s (SD: 0.235 s), Range: [1.491, 2.291] s.
  - `status` (str): Trial outcome (`OK`).

#### Campaign B: Central Alert Correlation & Adversary Probing (`DATASETS/t3_campaign_b_alert_correlation_oct27.csv`)
* **Cadence & Scope:** 10 formal trials conducted on 27 October 2026 measuring manager-side alert correlation latency under Rule 100100 and concurrent adversary network probing.
* **Columns (13):**
  - `trial` (int): Trial number (1 to 10).
  - `attacker_ip` (str): IP address of adversary node (`192.168.17.128`).
  - `t5_event_utc` (str): Microsecond-precision ISO-8601 UTC timestamp of the 5th Event ID 4625 from Windows Security log (e.g., `2026-10-27T04:56:21.6146026Z`).
  - `wazuh_alert_utc` (str): Millisecond-precision ISO-8601 UTC timestamp of Wazuh Manager Rule 100100 correlation alert (e.g., `2026-10-27T04:56:22.636+0000`).
  - `netsh_spawn_utc` (str): ISO-8601 UTC timestamp of Windows agent active-response invocation, parsed from local whole-second IST log (e.g., `2026-10-27T04:56:23Z`).
  - `kali_attack_end_utc` (str): UTC timestamp of 5th failed SMB authentication completion on the Kali adversary node.
  - `kali_severance_utc` (str): UTC timestamp of first TCP connection probe dropped/rejected by host firewall.
  - `software_alert_latency_sec` (float): Primary software correlation latency ($T_{Alert} - T_5$). Median: 1.014 s, Mean: 1.013 s (SD: 0.007 s), Range: [1.004, 1.021] s.
  - `software_netsh_latency_sec` (float): Software invocation latency calculated from agent active-response log ($T_{Netsh} - T_5$). Median: 0.881 s (quantization artifact; see Section 2.6).
  - `network_severance_delay_sec` (float): Adversary-observed severance delay relative to attack completion ($T_{Severed} - T_{AttackEnd}$). Median: 0.1565 s, Mean: 0.1567 s.
  - `estimated_socket_delay_sec` (float): Elapsed delay between netsh spawn and probe drop ($T_{Severed} - T_{Netsh}$). Median: 20.117 s.
  - `probe_rows` (int): Total connection probes dispatched during trial (577 for Trial 1, 935 for Trials 2–10).
  - `status` (str): Trial outcome (`OK`).

### 2.6. Campaign B Data Provenance and Quantization Artifact Notice
* **Windows-Side Telemetry Provenance:**
  `t5_event_utc`, `wazuh_alert_utc`, `netsh_spawn_utc`, and `software_alert_latency_sec` are extracted directly by `SCRIPTS/build_t3_live_dataset.py` from the raw active-response log: `DATASETS/active-responses.log` (originating from `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log`). Parity between the raw log and the derived CSV is 100% verified.
* **Adversary-Side Observation Provenance:**
  `kali_attack_end_utc`, `kali_severance_utc`, and `probe_rows` represent ground-truth trial observations recorded on the external Kali Linux adversary node (`192.168.17.128`) during Hydra brute-force execution and concurrent probing via `SCRIPTS/probe_dual.py`. Continuous raw per-second probe CSVs from that ephemeral adversary VM were not permanently preserved in the repository.
* **Log Quantization Artifact (0.881 s vs 1.014 s):**
  The Windows active-response log records integer seconds in local IST without sub-second resolution (e.g. `2026/10/27 10:30:51`). Truncating fractional seconds shifts timestamps backward by up to 500 ms in arithmetic, yielding an artificial median of 0.881 s for `software_netsh_latency_sec`. Therefore, `software_alert_latency_sec` (median 1.014 s), which utilizes millisecond-precision timestamps from the manager alert payload, is the primary reliable software correlation metric reported in the manuscript.

### 2.7. Exploratory Pilot Trials (`DATASETS/pilot_mttc_trials.csv`)
* **Scope:** 9 preliminary exploratory trials conducted prior to formal Campaign A protocol freeze.
* **Accounting:** 2 successful rule table insertions (1.803 s, 2.475 s; 5 failed logons seen); 7 uncontained runs (`status=FAIL`; 5–10 failed logons seen). Specific per-trial failure causes were unrecorded in the historical CSV; exploratory pilots were properly discarded prior to formal protocol freeze.

---

## 3. Step-by-Step Reproduction Instructions

All empirical results, summary tables, and inferential tests reported in the manuscript are completely reproducible from the raw datasets using standalone Python scripts requiring only `numpy` and `scipy` (`pip install -r requirements.txt`):

### 3.1. Recomputing Table 1: Canary Event Availability (Protocol T1)
```bash
python SCRIPTS/reproduce_t1_full_precision.py
```
Outputs verified against Table 1 and Section 4.1:
- Splunk UF Raw Search Latency (N=30): Median 2.185 s, Mean 2.228 s (SD: 0.603 s), IQR 1.107 s [1.652, 2.759] s, Range [1.378, 3.365] s.
- Wazuh Rule 100200 Alert Latency (N=30): Median 7.085 s, Mean 6.501 s (SD: 2.203 s), IQR 3.042 s [4.895, 7.937] s, Range [2.519, 10.254] s.
- Paired Difference (Wazuh - Splunk): Median +4.854 s, Mean +4.273 s (SD: 2.273 s), 95% CI [3.424, 5.122] s, Paired $t(29) = 10.30$ ($p = 3.38 \times 10^{-11}$), Wilcoxon $W+ = 465$ ($p = 1.86 \times 10^{-9}$).
- Polling & Cadence: Splunk median round-trip 640.0 ms (median 3.0 queries); Wazuh median round-trip 9.0 ms (median 62.0 queries); inter-trial delay mean 9.530 s [5.196, 12.878] s.

### 3.2. Recomputing Tables 2 & 3: Multi-Stage Telemetry (Protocol T2)
```bash
python SCRIPTS/reproduce_t2_full_precision.py
```
Outputs verified against Tables 2 & 3 and Section 4.2:
- Private WS Delta (Baseline): +51.603 MiB ($t = 79.26$, Holm $p = 2.17 \times 10^{-13}$, $d_z = 25.07$)
- Private WS Delta (Burst): +51.291 MiB ($t = 80.36$, Holm $p = 2.17 \times 10^{-13}$, $d_z = 25.41$)
- Private WS Delta (Recovery): +52.365 MiB ($t = 78.42$, Holm $p = 2.17 \times 10^{-13}$, $d_z = 24.80$)
- CPU Utilization (Baseline): Wazuh 1.978% vs. Splunk 0.146% (Diff -1.832 pp, $t = -12.72$, Holm $p = 1.40 \times 10^{-6}$, $d_z = -4.02$)
- CPU Utilization (Burst): Wazuh 0.519% vs. Splunk 0.179% (Diff -0.339 pp, $t = -1.45$, unadjusted $p = 0.1810$, Holm $p = 0.3621$, $d_z = -0.46$)
- CPU Utilization (Recovery): Wazuh 0.145% vs. Splunk 0.088% (Diff -0.057 pp, $t = -0.43$, unadjusted $p = 0.6748$, Holm $p = 0.6748$, $d_z = -0.14$)
- Exploratory Sensitivity Checks: Wazuh post-stabilization decay (+1.525 pp, $p = 4.75 \times 10^{-5}$); timestamp-aligned burst window (Splunk 0.205% vs. Wazuh 1.012%, paired difference -0.807 pp, $t = -2.54, p = 0.0318$; Wilcoxon $p = 0.0645$); LOSO jackknife ([51.303, 51.919] MiB); exact permutation tests ($2^{10} = 1,024$).

### 3.3. Recomputing Protocol T3: Automated Containment & Alert Latencies
```bash
python SCRIPTS/reproduce_t3_full_precision.py
# Verify extraction parity against raw Windows active-response log:
python SCRIPTS/build_t3_live_dataset.py --check-parity
```
Outputs verified against Section 4.3:
- Campaign A (N=10, 16 Oct 2026): Firewall block rule visibility latency: Median 1.589 s, Mean 1.680 s (SD: 0.235 s), Range [1.491, 2.291] s (Delta 0.800 s), Q1 1.539 s, Q3 1.737 s, IQR 0.198 s. Exactly 5 failed logons seen on all 10 trials; 100% OK status.
- Campaign B (N=10, 27 Oct 2026): Central manager alert correlation latency under Rule 100100: Median 1.014 s, Mean 1.013 s (SD: 0.007 s), Range [1.004, 1.021] s (Delta 0.017 s). Raw active-responses.log extraction parity is 100% verified.
- Exploratory Pilot Accounting (N=9, 15-16 Oct 2026): 2 successful rule table insertions (1.803 s, 2.475 s; 5 failed logons seen); 7 uncontained runs (status=FAIL; 5–10 failed logons seen).

### 3.4. Master Automated Reproduction Suite
```bash
python SCRIPTS/reproduce_all_protocols.py
```

---

## 4. Testbed Hardware and Environment Specifications

* **Host System:** Physical mobile workstation (Intel Core i7-13620H mobile processor, 10 physical cores [6P+4E], 16 logical threads, 16 GB DDR5-4800 RAM, 1 TB NVMe SSD).
* **Host Operating System:** Microsoft Windows 11 Home 64-bit, 26H2 (Base Kernel OS Build 26300; Revision 26300.9711 active during 16–27 October 2026 trials via Cumulative Update KB5127648; Revision 26300.9818 post-hoc audited via KB5127936 installed 30 October).
* **Endpoint Telemetry:** Microsoft Sysmon v15.22 (SwiftOnSecurity schema, Event ID 1 Process Creation active).
* **Target Forwarders:**
  - Splunk Universal Forwarder v10.6.0.5 (`splunkd.exe` parent PID 17368 + `splunk-winevtlog.exe` helper PID 20492).
  - Wazuh Agent v4.9.0 (`wazuh-agent.exe` PID 21380).
* **Backend Infrastructure:**
  - Splunk Enterprise v10.6.0.5 (Windows Native Service, indexing port 9997, REST API 8089; Windows Registry `{1FB4708D-F265-4BD9-A8FF-7EBB4C9C1569}`, installed 11 October 2026 from `splunk-10.6.0.5-86587d4e3b27-windows-x64.msi`; active throughout all 16–27 October 2026 experimental sessions).
  - Wazuh Manager v4.9.0 (Docker Engine in WSL2, Linux kernel 6.18.33.2-2).
  - Wazuh Indexer / OpenSearch v2.13.0 (Docker container, REST API port 9200).
* **Adversary Node:** Kali Linux Rolling in VMware Workstation Pro on a private VMnet8 NAT subnet (192.168.17.0/24; adversary IP 192.168.17.128 targeting host 192.168.17.1; `ethernet0.connectionType = "nat"` verified in `kali linuxx.vmx`).

---

## 5. Methodological Boundaries & Declarations

1. **Sysmon XML Schema:** The exact XML file deployed during the original October 2026 data collection was not snapshotted in an automated repository commit; it was derived from SwiftOnSecurity defaults.
2. **Splunk Server-Side Ingestion Snapshots:** Server-side `inputs.conf` and `props.conf` snapshots were not archived; forwarder client-side configuration files are preserved.
3. **Adversary Network Socket Captures:** Continuous per-packet TCP/ICMP socket capture CSV files from the external Kali adversary virtual machine were ephemeral; Campaign B network-level metrics are reproduced from the verified trial records.
4. **Generative AI and Writing Assistance (MDPI Compliant Disclosure):** Generative AI tools (Claude 3.5 Sonnet, Gemini 2.5, Antigravity) were utilized for language and readability editing, verification script structure, and formatting assistance. All empirical experimental designs, testbed configurations, workload executions, and raw data collections were conducted independently by the author; no synthetic data was generated by AI.
