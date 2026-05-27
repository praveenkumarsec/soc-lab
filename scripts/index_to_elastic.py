import json,requests,urllib3,os
from pathlib import Path
from datetime import datetime
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ES="https://localhost:9200"
AUTH=("admin","SecretPassword")
HEADERS={"Content-Type":"application/json"}
print("="*50)
print("ELASTICSEARCH INDEXER")
print("="*50)
def index_doc(index,doc):
    try:
        r=requests.post(ES+"/"+index+"/_doc",headers=HEADERS,json=doc,timeout=5,verify=False,auth=AUTH)
        return r.status_code in [200,201]
    except Exception as e:
        print("  Error: "+str(e))
        return False
def create_index(index):
    mapping={"mappings":{"properties":{"timestamp":{"type":"date"},"score":{"type":"integer"},"ml_score":{"type":"float"},"hour":{"type":"integer"},"total_reports":{"type":"integer"},"ip":{"type":"keyword"},"country":{"type":"keyword"},"verdict":{"type":"keyword"},"severity":{"type":"keyword"}}}}
    requests.put(ES+"/"+index,headers=HEADERS,json=mapping,timeout=5,verify=False,auth=AUTH)
print("[*] Indexing threat intel records...")
create_index("soc-threat-intel")
raw=json.loads(Path("/home/socadmin/threat_intel_log.json").read_text())
count=0
for rec in raw:
    rec["timestamp"]=rec.get("checked_at",datetime.now().isoformat())
    if index_doc("soc-threat-intel",rec): count+=1
print("[+] Indexed "+str(count)+"/"+str(len(raw))+" threat intel records")
print("[*] Indexing ML anomalies...")
create_index("soc-anomalies")
raw2=json.loads(Path("/home/socadmin/anomalies.json").read_text())
count2=0
for rec in raw2:
    rec["timestamp"]=rec.get("detected_at",datetime.now().isoformat())
    rec["severity"]="CRITICAL" if rec["score"]>=75 else "HIGH" if rec["score"]>=50 else "MEDIUM"
    if index_doc("soc-anomalies",rec): count2+=1
print("[+] Indexed "+str(count2)+"/"+str(len(raw2))+" anomaly records")
print("[*] Indexing Azure attack logs...")
create_index("soc-azure-attacks")
log_dir="/home/socadmin/azure-logs/"
count3=0;total3=0
for fname in sorted(os.listdir(log_dir)):
    if not fname.endswith(".json"): continue
    log=json.load(open(log_dir+fname))
    log["timestamp"]=log.get("time",datetime.now().isoformat())
    log["src_ip"]=log.get("claims",{}).get("ipaddr","")
    log["operation"]=log.get("operationName","")
    total3+=1
    if index_doc("soc-azure-attacks",log): count3+=1
print("[+] Indexed "+str(count3)+"/"+str(total3)+" Azure log records")
print("[*] Indexing blocked IPs...")
create_index("soc-blocked-ips")
count4=0
try:
    for line in open("/home/socadmin/blocked_ips.txt").readlines():
        parts=line.strip().split(" | ")
        if len(parts)>=3:
            doc={"timestamp":parts[0],"action":parts[1],"ip":parts[2],"reason":parts[3] if len(parts)>3 else ""}
            if index_doc("soc-blocked-ips",doc): count4+=1
    print("[+] Indexed "+str(count4)+" blocked IP records")
except FileNotFoundError:
    print("[i] blocked_ips.txt not found - skipping")
print(chr(10)+"="*50)
print("INDEXING COMPLETE")
print("Indexes: soc-threat-intel, soc-anomalies, soc-azure-attacks, soc-blocked-ips")
print("="*50)
