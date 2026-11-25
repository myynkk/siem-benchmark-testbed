# Provenance & Reconciliation Record: Wazuh Rule 100200

## 1. Executive Summary & Resolution
This document formally resolves the provenance discrepancy between draft references to Rule 100200 (Level 3 with `<match>siemcanary</match>`) versus the primary testbed deployment evidence (Level 5 with `<field name="win.eventdata.commandLine">siemcanary</field>`).

## 2. Primary Evidence on Disk
1. **Container Backup Snapshot:**
   - **Path:** `data_code_deposit_package/configs/dated_rule_evidence/local_rules_live_container_20261018.xml` (copied from `siem-benchmark-testbed/configs/backups/live_container_pre_test/local_rules.xml.bak`).
   - **Lines 34-40:**
     ```xml
     <!-- Latency canary event (research testbed) -->
     <rule id="100200" level="5">
       <if_sid>61603</if_sid>
       <field name="win.eventdata.commandLine">siemcanary</field>
       <description>Latency canary event (research testbed)</description>
       <group>latency_canary,sysmon_event1,</group>
     </rule>
     ```
2. **Authoritative Timestamped Changelog:**
   - **File:** `siem-benchmark-testbed/data/CHANGELOG.md`
   - **Section:** `[2026-10-18 13:49:24 +05:30] Added Wazuh Rule 100200 for Latency Canary Benchmarking`
   - **Entry:**
     - Injected into `/var/ossec/etc/rules/local_rules.xml` inside container `single-node-wazuh.manager-1`
     - Validated with `/var/ossec/bin/wazuh-analysisd -t` (exit code 0)
     - Manager restarted at 13:49:00 +05:30; Agent 001 active at 13:49:24 +05:30.
     - Byte-order mark (BOM) removed via `sed` at 14:06:40 +05:30.

## 3. Discrepancy Cause & Alignment
- **Discrepancy Cause:** During manual transcription of early summary drafts, a preliminary draft snippet with `level="3"` and generic `<match>` tags was inadvertently copied instead of the active production rule definition.
- **Reconciliation:** All repository configuration files (`data_code_deposit_package/configs/wazuh_local_rules.xml` and `final_research_submission_v4/configs/wazuh_local_rules.xml`) and the manuscript appendix (**Listing A3**) are now strictly aligned to the empirical ground-truth Level 5 rule.
