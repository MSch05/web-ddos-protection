# web-ddos-protection

# Web DDoS Protection

Lightweight defensive DDoS / abuse protection for Linux web servers.

This project provides:
- Static IP and network blocking via ipset
- Live request monitoring from Apache or Nginx access logs
- Automatic dynamic blocking on request floods
- Kernel-level firewall blocking (iptables + ipset)
- Live visibility of blocked access attempts

## Features
- Supports Apache2 and Nginx (auto-detection)
- CIDR blocklists (IPv4)
- Dynamic per-IP rate limiting
- Kernel log monitoring for blocked attempts
- Single-file Python implementation
- Designed for self-hosted servers

## How it works
1. Static networks from `blocklist.txt` are loaded into an ipset
2. iptables drops traffic from blocked sources at kernel level
3. Python monitors web server access logs for live traffic
4. IPs exceeding the configured request rate are dynamically blocked
5. Blocked access attempts are visible via kernel log monitoring

## Requirements
- Linux (Debian / Ubuntu recommended)
- Python 3.8+
- iptables
- ipset
- Apache2 or Nginx

## Installation

```bash
sudo apt update
sudo apt install ipset -y
git clone https://github.com/YOURNAME/web-ddos-protection.git
cd web-ddos-protection
sudo python3 main.py
