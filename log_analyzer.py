#!/usr/bin/env python3
"""
SOC Log Analyzer - Simple script to analyze security logs
"""

import os
import re
from collections import defaultdict, Counter

def analyze_auth_logs(file_path):
    """Analyze authentication logs for suspicious activity"""
    print("=== AUTHENTICATION LOG ANALYSIS ===")

    failures = defaultdict(list)
    successes = []

    with open(file_path, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 4:
                timestamp = f"{parts[0]} {parts[1]}"
                status = parts[2]
                user = parts[3]
                ip = parts[4] if len(parts) > 4 else "unknown"

                if status == "FAILURE":
                    failures[ip].append((timestamp, user))
                elif status == "SUCCESS":
                    successes.append((timestamp, user, ip))

    # Report suspicious activity
    for ip, attempts in failures.items():
        if len(attempts) >= 3:
            print(f"🚨 BRUTE FORCE DETECTED: {len(attempts)} failed attempts from IP {ip}")
            for timestamp, user in attempts:
                print(f"   {timestamp}: Failed login for {user}")

    print(f"✅ Successful logins: {len(successes)}")
    print()

def analyze_network_logs(file_path):
    """Analyze network logs for suspicious connections"""
    print("=== NETWORK LOG ANALYSIS ===")

    blocked_ips = set()
    allowed_count = 0

    with open(file_path, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 6:
                action = parts[2]
                protocol = parts[3]
                src_ip = parts[4].split(':')[0]  # Extract IP before port

                if action == "DENY" or action == "BLOCK":
                    blocked_ips.add(src_ip)
                elif action == "ALLOW":
                    allowed_count += 1

    print(f"🚫 Blocked connections from {len(blocked_ips)} unique IPs: {', '.join(blocked_ips)}")
    print(f"✅ Allowed connections: {allowed_count}")
    print()

def analyze_malware_alerts(file_path):
    """Analyze malware alerts"""
    print("=== MALWARE ALERT ANALYSIS ===")

    alerts = []
    with open(file_path, 'r') as f:
        for line in f:
            if "ALERT" in line:
                alerts.append(line.strip())

    print(f"🚨 Total alerts: {len(alerts)}")
    for alert in alerts:
        print(f"   {alert}")
    print()

def main():
    """Main analysis function"""
    log_dir = "SOC_Task2_Sample_Logs"

    if not os.path.exists(log_dir):
        print(f"Log directory {log_dir} not found!")
        return

    print("SOC LOG ANALYSIS REPORT")
    print("=" * 50)

    # Analyze each log file
    auth_file = os.path.join(log_dir, "auth_logs.txt")
    if os.path.exists(auth_file):
        analyze_auth_logs(auth_file)

    network_file = os.path.join(log_dir, "network_logs.txt")
    if os.path.exists(network_file):
        analyze_network_logs(network_file)

    malware_file = os.path.join(log_dir, "malware_alerts.txt")
    if os.path.exists(malware_file):
        analyze_malware_alerts(malware_file)

    print("Analysis complete. See incident_response_report.md for detailed report.")

if __name__ == "__main__":
    main()