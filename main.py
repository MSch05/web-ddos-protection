#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import ipaddress
import time
from collections import defaultdict
import threading

# =====================
# CONFIG
# =====================
BLOCKLIST_FILE = "blocklist.txt"
IPSET_NAME = "ddos_block"

REQUEST_LIMIT = 30       # requests per second per IP
BLOCK_TIME = 600         # seconds dynamic block
CHECK_INTERVAL = 1.0

NGINX_LOG = "/var/log/nginx/access.log"
APACHE_LOG = "/var/log/apache2/access.log"
BLOCK_LOG_PREFIX = "[DDOS_BLOCK]"

# =====================
# ROOT CHECK
# =====================
if os.geteuid() != 0:
    print("[ERROR] Please run as root")
    exit(1)

# =====================
# WEBLOG DETECTION
# =====================
def detect_webserver():
    if os.path.exists(NGINX_LOG):
        return "nginx", NGINX_LOG
    if os.path.exists(APACHE_LOG):
        return "apache", APACHE_LOG
    return None, None

server, log_file = detect_webserver()
if not server:
    print("[ERROR] No Apache or Nginx log found")
    exit(1)
print("[INFO] Webserver detected:", server)

# =====================
# HELPER
# =====================
def run(cmd):
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# =====================
# IPSET & IPTABLES SETUP
# =====================
def setup_firewall():
    # Create ipset if not exists
    run(["ipset", "create", IPSET_NAME, "hash:net", "family", "inet", "-exist"])
    # Insert iptables logging + drop
    run(["iptables", "-D", "INPUT", "-m", "set", "--match-set", IPSET_NAME, "src", "-j LOG", "--log-prefix", BLOCK_LOG_PREFIX])
    run(["iptables", "-D", "INPUT", "-m", "set", "--match-set", IPSET_NAME, "src", "-j DROP"])
    run(["iptables", "-I", "INPUT", "-m", "set", "--match-set", IPSET_NAME, "src", "-j LOG", "--log-prefix", BLOCK_LOG_PREFIX])
    run(["iptables", "-I", "INPUT", "-m", "set", "--match-set", IPSET_NAME, "src", "-j DROP"])
    print("[INFO] Firewall initialized (ipset + logging)")

# =====================
# LOAD STATIC BLOCKLIST
# =====================
def load_blocklist():
    nets = []
    if not os.path.exists(BLOCKLIST_FILE):
        print("[WARN] blocklist.txt not found")
        return nets
    with open(BLOCKLIST_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
                nets.append(str(net))
            except ValueError:
                print("[WARN] Invalid entry:", line)
    return nets

def apply_blocklist(nets):
    for net in nets:
        if subprocess.run(["ipset", "test", IPSET_NAME, net], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            run(["ipset", "add", IPSET_NAME, net])
            print("[BLOCKLIST] Network blocked:", net)

# =====================
# LIVE BLOCKING
# =====================
dynamic_blocks = {}

def block_ip(ip):
    if ip in dynamic_blocks:
        return
    run(["ipset", "add", IPSET_NAME, ip])
    dynamic_blocks[ip] = time.time()
    print("[LIVE BLOCK] IP:", ip)

def cleanup_blocks():
    now = time.time()
    for ip in list(dynamic_blocks.keys()):
        if now - dynamic_blocks[ip] > BLOCK_TIME:
            run(["ipset", "del", IPSET_NAME, ip])
            del dynamic_blocks[ip]
            print("[UNBLOCK] IP:", ip)

# =====================
# LIVE REQUEST MONITOR
# =====================
def monitor_access_log():
    requests = defaultdict(int)
    last_check = time.time()
    with open(log_file, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.01)
                continue
            ip = line.split()[0]
            requests[ip] += 1
            now = time.time()
            if now - last_check >= CHECK_INTERVAL:
                total = sum(requests.values())
                print(f"[STATS] RPS:{total} ActiveIPs:{len(requests)} Blocked:{len(dynamic_blocks)}")
                for ip_addr, count in requests.items():
                    if count > REQUEST_LIMIT:
                        block_ip(ip_addr)
                requests.clear()
                cleanup_blocks()
                last_check = now

# =====================
# MONITOR BLOCKED IPs FROM KERNEL LOG
# =====================
BLOCK_LOG = "/var/log/kern.log"

def monitor_blocked_log():
    if not os.path.exists(BLOCK_LOG):
        print("[WARN] Kernel log not found for blocked monitoring")
        return
    with open(BLOCK_LOG, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if BLOCK_LOG_PREFIX in line:
                parts = line.split()
                for p in parts:
                    if p.startswith("SRC="):
                        print("[BLOCKED TRY]", p.replace("SRC=", ""))
            time.sleep(0.01)

# =====================
# MAIN
# =====================
print("[INFO] Starting DDoS protection...")

setup_firewall()
nets = load_blocklist()
apply_blocklist(nets)
print("[INFO] Static blocklist applied:", len(nets))

# Threads for live monitoring
thread_access = threading.Thread(target=monitor_access_log, daemon=True)
thread_blocked = threading.Thread(target=monitor_blocked_log, daemon=True)

thread_access.start()
thread_blocked.start()

# Keep main alive
while True:
    time.sleep(1)
