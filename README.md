# Cloud SOC Dashboard with Azure + Wazuh + ML

A fully functional Security Operations Center (SOC) lab built on Azure cloud.

## Tech Stack
- **Wazuh 4.7** — SIEM
- **Azure Free Tier** — Cloud logs
- **AbuseIPDB** — Threat intelligence
- **Isolation Forest** — ML anomaly detection
- **OpenSearch/Kibana** — SOC dashboard
- **Python 3** — Automation scripts

## Features
- Automated threat detection from Azure logs
- Auto IP blocking via iptables
- AbuseIPDB threat intel enrichment
- ML anomaly detection — 9 threats found
- Live Kibana SOC dashboard

## Results
- 9 threats detected
- 2 IPs blocked
- 69 records indexed in OpenSearch
- MITRE ATT&CK: T1078, T1562, T1548, T1567, T1578, T1110
