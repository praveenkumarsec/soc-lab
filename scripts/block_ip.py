import subprocess, os
from datetime import datetime

BLOCKED = []
LOG = "/home/socadmin/blocked_ips.txt"

print("=" * 50)
print("IP BLOCKER SCRIPT")
print("=" * 50)

def block_ip(ip, reason):
    if ip in BLOCKED:
        print("Already blocked: " + ip)
        return
    cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    result = subprocess.run(cmd, capture_output=True)
    BLOCKED.append(ip)
    msg = str(datetime.now()) + " | BLOCKED | " + ip + " | " + reason
    with open(LOG, "a") as f:
        f.write(msg + "\n")
    print("BLOCKED: " + ip)
    print("Reason:  " + reason)
    print("Logged to: " + LOG)

block_ip("203.0.113.19",  "Compromised account NSG attack")
block_ip("185.220.101.5", "Brute force login attempt")
block_ip("203.0.113.19",  "Already blocked test")

print("\nTotal blocked: " + str(len(BLOCKED)))
print("IPs: " + str(BLOCKED))
print("=" * 50)
