import json, os, subprocess
from datetime import datetime
from threat_intel import check_ip, print_intel_report
LOG_DIR="/home/socadmin/azure-logs/"
INTEL_LOG="/home/socadmin/threat_intel_log.json"
RLOG="/home/socadmin/auto_response_log.txt"
blocked=[]
alerts=[]
intel_records=[]
print("="*55)
print("SOC AUTO-RESPONSE v2.0 + AbuseIPDB")
print("Time: "+str(datetime.now()))
print("="*55)
def block_ip(ip,severity,op):
    if ip in blocked:
        print("Already blocked: "+ip)
        return
    subprocess.run(["sudo","iptables","-A","INPUT","-s",ip,"-j","DROP"],capture_output=True)
    blocked.append(ip)
    open(RLOG,"a").write(str(datetime.now())+" | "+severity+" | BLOCKED "+ip+" | "+op+chr(10))
    print("BLOCKED: "+ip)
for fname in sorted(os.listdir(LOG_DIR)):
    if not fname.endswith(".json"): continue
    log=json.load(open(LOG_DIR+fname))
    ip=log.get("claims",{}).get("ipaddr","")
    op=log.get("operationName","")
    ca=log.get("caller","")
    res=log.get("resultType","")
    print("[Scanning] "+fname)
    threat=False
    severity=""
    if "compromised" in ca.lower(): threat=True;severity="CRITICAL";alerts.append("Compromised: "+ca)
    if "networkSecurityGroups" in op: threat=True;severity="CRITICAL";alerts.append("NSG modified")
    if "roleAssignments" in op: threat=True;severity="CRITICAL";alerts.append("Privilege escalation")
    if "blobServices" in op: threat=True;severity="HIGH";alerts.append("Data exfiltration")
    if "virtualMachines" in op: threat=True;severity="CRITICAL";alerts.append("Backdoor VM")
    if res=="Failure": threat=True;severity="HIGH";alerts.append("Failed login")
    intel=None
    if ip:
        intel=check_ip(ip)
        print_intel_report(intel)
        intel_records.append(intel)
        if intel["verdict"]=="BLOCK" and not threat:
            threat=True;severity="HIGH"
            alerts.append("AbuseIPDB score "+str(intel["score"])+"/100")
import json as _j
open(INTEL_LOG,"w").write(_j.dumps(intel_records,indent=2))
print("="*55)
print("SUMMARY")
print("Threats: "+str(len(alerts)))
print("Blocked: "+str(len(blocked)))
print("Intel:   "+str(len(intel_records)))
for a in alerts: print("  - "+a)
print("Intel log: "+INTEL_LOG)
print("="*55)
