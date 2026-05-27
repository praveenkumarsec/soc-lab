import requests, json, os, time
from datetime import datetime
from pathlib import Path

API_KEY    = os.getenv("ABUSEIPDB_KEY", "")
API_URL    = "https://api.abuseipdb.com/api/v2/check"
CACHE_FILE = "/home/socadmin/ip_cache.json"
BLOCK_SCORE = 50
FLAG_SCORE  = 25

def load_cache():
    try:
        return json.loads(Path(CACHE_FILE).read_text())
    except Exception:
        return {}

def save_cache(cache):
    Path(CACHE_FILE).write_text(json.dumps(cache, indent=2))

def check_ip(ip):
    if not ip:
        return _empty_result(ip)
    cache = load_cache()
    if ip in cache:
        entry = cache[ip]
        age = (time.time() - entry.get("checked_at_ts", 0)) / 3600
        if age < 24:
            entry["cached"] = True
            return entry
    if not API_KEY:
        print("  [!] ABUSEIPDB_KEY not set")
        return _empty_result(ip)
    try:
        resp = requests.get(API_URL,
            headers={"Key": API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        verdict = "BLOCK" if score >= BLOCK_SCORE else "FLAG" if score >= FLAG_SCORE else "CLEAN"
        result = {
            "ip": ip, "score": score,
            "country": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "total_reports": data.get("totalReports", 0),
            "last_reported": data.get("lastReportedAt", ""),
            "verdict": verdict, "cached": False,
            "checked_at_ts": time.time(),
            "checked_at": datetime.utcnow().isoformat()
        }
        cache[ip] = result
        save_cache(cache)
        return result
    except requests.exceptions.Timeout:
        print("  [!] AbuseIPDB timeout — treating as CLEAN")
        return _empty_result(ip)
    except requests.exceptions.RequestException as e:
        print("  [!] AbuseIPDB error: " + str(e))
        return _empty_result(ip)

def _empty_result(ip):
    return {"ip": ip, "score": 0, "country": "", "isp": "",
            "total_reports": 0, "last_reported": "",
            "verdict": "CLEAN", "cached": False}

def print_intel_report(result):
    labels = {"BLOCK": "[BLOCK]", "FLAG": "[FLAG]", "CLEAN": "[CLEAN]"}
    tag = " (cached)" if result.get("cached") else ""
    print("  Threat Intel" + tag + ":")
    print("    IP:      " + result["ip"])
    print("    Score:   " + str(result["score"]) + "/100")
    print("    Country: " + str(result["country"] or ""))
    print("    ISP:     " + str(result["isp"] or ""))
    print("    Reports: " + str(result["total_reports"] or 0))
    print("    Verdict: " + labels[result["verdict"]] + " " + result["verdict"])
