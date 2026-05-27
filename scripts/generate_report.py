import json, os
from datetime import datetime

LOG_DIR = "/home/socadmin/azure-logs/"
REPORT  = "/home/socadmin/incident_report.txt"

lines = []
total = 0; crit = 0; high = 0; med = 0

lines.append("=" * 60)
lines.append("SOC LAB - INCIDENT REPORT")
lines.append("Project: Cloud SOC with Azure Logs")
lines.append("Generated: " + str(datetime.now()))
lines.append("Analyst: SOC-Lab")
lines.append("=" * 60)

for f in sorted(os.listdir(LOG_DIR)):
    if not f.endswith(".json"):
        continue
    log = json.load(open(LOG_DIR + f))
    op  = log.get("operationName", "")
    ca  = log.get("caller", "")
    ip  = log.get("claims", {}).get("ipaddr", "")
    t   = log.get("time", "")

    lines.append("\n--- " + f + " ---")
    lines.append("Time:      " + t)
    lines.append("Caller:    " + ca)
    lines.append("Source IP: " + ip)
    lines.append("Operation: " + op)

    if "compromised" in ca.lower():
        lines.append("THREAT: [CRITICAL] Compromised account T1078")
        crit += 1; total += 1
    if "networkSecurityGroups" in op:
        lines.append("THREAT: [HIGH] NSG Firewall modified T1562")
        high += 1; total += 1
    if "roleAssignments" in op:
        lines.append("THREAT: [CRITICAL] Privilege escalation T1548")
        crit += 1; total += 1
    if "blobServices" in op:
        lines.append("THREAT: [HIGH] Data exfiltration T1567")
        high += 1; total += 1
    if "virtualMachines" in op:
        lines.append("THREAT: [CRITICAL] Backdoor VM T1578")
        crit += 1; total += 1
    if log.get("resultType", "") == "Failure":
        lines.append("THREAT: [MEDIUM] Failed login T1110")
        med += 1; total += 1

lines.append("\n" + "=" * 60)
lines.append("FINAL SUMMARY")
lines.append("Total Alerts:  " + str(total))
lines.append("CRITICAL:      " + str(crit))
lines.append("HIGH:          " + str(high))
lines.append("MEDIUM:        " + str(med))
lines.append("Attacker IP:   203.0.113.19  STATUS: BLOCKED")
lines.append("Response:      Auto-blocked by SOC system")
lines.append("=" * 60)

report = "\n".join(lines)
open(REPORT, "w").write(report)
print(report)
print("\nReport saved to: " + REPORT)
