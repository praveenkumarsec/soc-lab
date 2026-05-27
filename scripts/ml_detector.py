import json, os
from datetime import datetime
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
INTEL_LOG    = "/home/socadmin/threat_intel_log.json"
ANOMALY_LOG  = "/home/socadmin/anomalies.json"
REPORT_FILE  = "/home/socadmin/ml_report.txt"
CONTAMINATION = 0.15
print("="*55)
print("SOC ML ANOMALY DETECTOR v1.0")
print("Time: "+str(datetime.now()))
print("="*55)
raw = json.loads(Path(INTEL_LOG).read_text())
print("Loaded "+str(len(raw))+" records")
df = pd.DataFrame(raw)
df["score"]         = pd.to_numeric(df["score"],errors="coerce").fillna(0)
df["total_reports"] = pd.to_numeric(df["total_reports"],errors="coerce").fillna(0)
df["checked_at"]    = pd.to_datetime(df["checked_at"],errors="coerce")
df["hour"]          = df["checked_at"].dt.hour.fillna(12)
df["day_of_week"]   = df["checked_at"].dt.dayofweek.fillna(0)
le = LabelEncoder()
df["country_enc"]  = le.fit_transform(df["country"].fillna("UNKNOWN").astype(str))
verdict_map = {"CLEAN":0,"FLAG":1,"BLOCK":2}
df["verdict_enc"]  = df["verdict"].map(verdict_map).fillna(0)
features = ["score","total_reports","hour","day_of_week","country_enc","verdict_enc"]
X = df[features].values
print("Matrix shape: "+str(X.shape))
print("Training Isolation Forest...")
model = IsolationForest(n_estimators=100,contamination=CONTAMINATION,random_state=42)
model.fit(X)
print("Model trained on "+str(len(X))+" samples")
df["anomaly"]       = model.predict(X)
df["anomaly_score"] = model.decision_function(X).round(4)
anomalies = df[df["anomaly"]==-1].copy()
normals   = df[df["anomaly"]==1].copy()
print("Normal:    "+str(len(normals)))
print("Anomalies: "+str(len(anomalies)))
print("="*55)
print("ANOMALIES DETECTED")
print("="*55)
for _,row in anomalies.iterrows():
    print("IP:      "+str(row["ip"]))
    print("Score:   "+str(row["score"])+"/100")
    print("Country: "+str(row["country"]))
    print("Reports: "+str(row["total_reports"]))
    print("Hour:    "+str(int(row["hour"]))+":00")
    print("Verdict: "+str(row["verdict"]))
    print("ML Score:"+str(row["anomaly_score"]))
    sev="CRITICAL" if row["score"]>=75 else "HIGH" if row["score"]>=50 else "MEDIUM"
    print("Severity:"+sev)
    print("-"*30)
anomaly_list=[]
for _,row in anomalies.iterrows():
    anomaly_list.append({
        "ip":str(row["ip"]),
        "score":int(row["score"]),
        "country":str(row["country"]),
        "total_reports":int(row["total_reports"]),
        "hour":int(row["hour"]),
        "verdict":str(row["verdict"]),
        "ml_score":float(row["anomaly_score"]),
        "detected_at":datetime.now().isoformat()
    })
open(ANOMALY_LOG,"w").write(json.dumps(anomaly_list,indent=2))
print("Anomalies saved to: "+ANOMALY_LOG)
report=[]
report.append("="*55)
report.append("SOC ML ANOMALY DETECTION REPORT")
report.append("Generated: "+str(datetime.now()))
report.append("Model: Isolation Forest")
report.append("Total records:  "+str(len(df)))
report.append("Normal:         "+str(len(normals)))
report.append("Anomalies:      "+str(len(anomalies)))
report.append("Detection rate: "+str(round(len(anomalies)/len(df)*100,1))+"%")
open(REPORT_FILE,"w").write(chr(10).join(report))
print("Report saved to: "+REPORT_FILE)
print("="*55)
print("Day 9 Complete! ML anomaly detection working!")
print("="*55)
