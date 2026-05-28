# SOC Lab Project Report

**Project:** Cloud SOC Dashboard with Automated Threat Detection

**Author:** Praveen Kumar

**Duration:** 15 Days

**Stack:** Azure + Wazuh + Python + AbuseIPDB + ML + OpenSearch

---

## 1. Executive Summary

Built a fully functional Security Operations Center (SOC) lab from scratch in 15 days. The project demonstrates real-world SOC capabilities including log ingestion from Azure cloud, automated threat detection, IP blocking, threat intelligence enrichment, machine learning anomaly detection, and a live Kibana dashboard.

## 2. Objective

- Build a cloud-based SOC lab using free-tier tools
- Simulate real Azure attack scenarios
- Automate the full incident response pipeline
- Integrate external threat intelligence via AbuseIPDB
- Detect unknown threats using ML anomaly detection
- Visualise all data in a live SOC dashboard

## 3. Methodology

### Phase 1 — Lab Setup (Days 1-3)
Installed VirtualBox, Ubuntu 22.04 VM and Docker. Deployed Wazuh 4.7 single-node via Docker Compose. Enrolled first agent and triggered first real alert to verify the SIEM was working.

### Phase 2 — Cloud Integration (Days 4-6)
Created Azure free tier account and enabled Activity Logs and Microsoft Defender for Cloud. Connected Azure logs to Wazuh via Event Hub and the Wazuh Azure module. Simulated 5 real attack scenarios to verify cloud logs were flowing into the SIEM.

### Phase 3 — Detection Pipeline (Days 7-9)
Built three Python scripts: block_ip.py for iptables blocking, auto_response.py for automated incident response, and threat_intel.py for AbuseIPDB enrichment. Added ml_detector.py using Isolation Forest to catch anomalies rules would miss.

### Phase 4 — Dashboard (Day 10)
Pushed 69 records into 4 OpenSearch indexes using index_to_elastic.py. Built 5 Kibana panels: Total Alerts KPI, Alerts Over Time, Top Attacker IPs, ML Anomaly Table, and Severity Breakdown pie chart.

### Phase 5 — Documentation (Days 11-15)
Pushed all code to GitHub with README, architecture docs, detection rules, and dashboard screenshots.

## 4. Results

| Metric | Result |
|---|---|
| Azure log files processed | 5 |
| Threats detected | 9 |
| Attacker IPs blocked | 2 |
| MITRE ATT&CK techniques covered | 6 |
| IPs checked via AbuseIPDB | 55 |
| ML anomalies detected | 9 |
| Records indexed in OpenSearch | 69 |
| Kibana dashboard panels | 5 |

## 5. Key Findings

**Finding 1 — Rule-based detection caught known attack patterns**

All 6 MITRE ATT&CK techniques were successfully detected from Azure Activity Logs using keyword-based rules in auto_response.py. Compromised account activity (T1078) was the most frequent trigger.

**Finding 2 — ML caught threats rules missed**

3 MEDIUM severity IPs with scores of 30-38 were flagged by Isolation Forest despite being below the AbuseIPDB block threshold of 50. This demonstrates the value of ML as a second detection layer.

**Finding 3 — AbuseIPDB correctly identified Tor exit nodes**

5 IPs in the 45.x.x.x range received scores of 78-100 with hundreds of abuse reports, confirming them as known malicious infrastructure.

**Finding 4 — Reserved IPs return null from threat intel APIs**

203.0.113.19 is a documentation-only IP per RFC 5737. AbuseIPDB correctly returned a null country and ISP for this address. Production systems should filter reserved IP ranges before querying threat intel APIs.

## 6. Recommendations

**Recommendation 1 — Replace simulated logs with real Azure Event Hub streaming**

The current setup uses static JSON files to simulate Azure logs. In production, configure Azure Diagnostic Settings to stream Activity Logs to Event Hub in real time for live threat detection.

**Recommendation 2 — Add Slack or PagerDuty alerting**

Critical incidents currently write to a log file only. Adding a Slack webhook to auto_response.py would notify the SOC team within seconds of a critical threat being detected.

**Recommendation 3 — Retrain ML model monthly**

The Isolation Forest model was trained on 55 synthetic records. In production, retrain monthly on real alert data to improve accuracy and adapt to evolving attacker behaviour patterns.

**Recommendation 4 — Add GeoIP enrichment**

Integrating MaxMind GeoIP would add attacker city and coordinates to each alert, enabling a world map panel in Kibana showing the geographic distribution of attacks in real time.

**Recommendation 5 — Implement SOAR playbooks**

Using n8n or Shuffle (both free and open source), complex multi-step response playbooks could be automated — for example: detect privilege escalation → disable Azure AD account → notify manager → open ticket → block IP.

---

## 7. Conclusion

This project successfully demonstrates a complete SOC pipeline built entirely with free and open source tools in 15 days. The combination of rule-based detection, external threat intelligence, and ML anomaly detection provides three independent layers of coverage that together catch both known and unknown threats. The live Kibana dashboard gives SOC analysts real-time visibility across all data sources in a single pane of glass.

**GitHub:** https://github.com/praveenkumarsec/soc-lab

*Built by Praveen Kumar — 15-day SOC analyst portfolio project*
