# Endpoint-Agent Resource Consumption and Native-Workflow Event Availability: A Single-Host Windows 11 Evaluation of Splunk and Wazuh

Official code, telemetry datasets, configuration manifests, and turnkey statistical reproduction scripts accompanying the research manuscript submitted to the **6th OPJU International Technology Conference (OTCON 6.0) on SMARTICON** (Paper ID: 404).

**Author:** Mayank Kumar (`mayankdagar11@gmail.com`)

**Affiliation:** Department of Computer Science & Engineering, Sushant University, Gurugram, India

---

## Repository Structure

```text
├── CONFIGURATIONS/        # Wazuh Manager XML rules (Rules 100100 & 100200), Docker Compose manifest
├── DATASETS/              # Raw CSV/JSONL empirical logs across Protocols T1, T2, T3 & pilot trials
├── METADATA/              # Data Dictionary, SHA-256 verification manifest, dependency list
├── SCRIPTS/               # Benchmarking harnesses & full-precision statistical verification scripts
└── requirements.txt       # Python environment dependencies
```

---

## Quick Reproduction

To independently verify all reported statistical p-values, confidence intervals, medians, IQRs, and Mean Time to Contain (MTTC) metrics:

```bash
pip install -r requirements.txt
python SCRIPTS/reproduce_all_protocols.py
```

---

## Evaluated Protocols

1. **Protocol T1 (Event Availability & Discovery Latency):**  
   30 paired canary executions measuring REST API indexing/alert availability across Splunk Universal Forwarder (`v10.6.0.5`) and Wazuh Agent (`v4.9.0`).
2. **Protocol T2 (Endpoint Resource Profiling):**  
   10 paired monitoring sessions (3,578 telemetry points at nominal 1 Hz) measuring Private Working Set, Virtual Commit Size, and normalized 16-core CPU utilization across Post-Restart, Burst, and Recovery windows.
3. **Protocol T3 (Automated Active Containment):**  
   20 live trials verifying autonomous Windows Advanced Firewall drop rule enforcement (`netsh.exe`) via Wazuh Active Response upon detecting credential brute-forcing (`MITRE ATT&CK T1110`).
