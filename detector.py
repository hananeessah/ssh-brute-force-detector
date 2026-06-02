#!/usr/bin/env python3
"""
SSH Brute Force Detector
Detecte les tentatives de brute force SSH dans les logs
"""

import re
import time
from collections import defaultdict
from datetime import datetime, timedelta

class SSHBruteForceDetector:
    def __init__(self, max_attempts=5, time_window_seconds=60):
        self.max_attempts = max_attempts
        self.time_window = timedelta(seconds=time_window_seconds)
        self.attempts = defaultdict(list)
        
    def parse_log_line(self, line):
        patterns = [
            r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)',
            r'Invalid user .* from (\d+\.\d+\.\d+\.\d+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        return None
    
    def clean_old_attempts(self, current_time):
        cutoff = current_time - self.time_window
        for ip in list(self.attempts.keys()):
            self.attempts[ip] = [t for t in self.attempts[ip] if t > cutoff]
            if not self.attempts[ip]:
                del self.attempts[ip]
    
    def add_attempt(self, ip, timestamp):
        self.attempts[ip].append(timestamp)
        self.clean_old_attempts(timestamp)
        return len(self.attempts[ip]) >= self.max_attempts
    
    def analyze_log_file(self, log_path):
        alerts = []
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = self.parse_log_line(line)
                    if ip:
                        if self.add_attempt(ip, datetime.now()):
                            alerts.append({'ip': ip, 'attempts': len(self.attempts[ip])})
        except FileNotFoundError:
            print(f"[!] Fichier non trouve : {log_path}")
        return alerts
    
    def simulate_realtime(self, log_path, interval_seconds=1):
        print(f"[*] Surveillance en temps reel de {log_path}")
        print(f"[*] Seuil : {self.max_attempts} tentatives en {self.time_window.total_seconds()}s")
        print("[*] Ctrl+C pour arreter\n")
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if line:
                        ip = self.parse_log_line(line)
                        if ip and self.add_attempt(ip, datetime.now()):
                            print(f"\n🚨 ALERTE IP: {ip} ({len(self.attempts[ip])} tentatives)")
                    else:
                        time.sleep(interval_seconds)
        except KeyboardInterrupt:
            print("\n[*] Arret de la surveillance")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Detecteur de brute force SSH")
    parser.add_argument("log_file", help="Chemin vers le fichier de log")
    parser.add_argument("--max", type=int, default=5, help="Nombre max de tentatives")
    parser.add_argument("--window", type=int, default=60, help="Fenetre de temps en secondes")
    parser.add_argument("--realtime", action="store_true", help="Mode surveillance temps reel")
    args = parser.parse_args()
    detector = SSHBruteForceDetector(max_attempts=args.max, time_window_seconds=args.window)
    if args.realtime:
        detector.simulate_realtime(args.log_file)
    else:
        alerts = detector.analyze_log_file(args.log_file)
        if alerts:
            print(f"\n🚨 {len(alerts)} alertes detectees :\n")
            for alert in alerts:
                print(f"   IP : {alert['ip']} -> {alert['attempts']} tentatives")
        else:
            print("\n✅ Aucune tentative suspecte detectee")

if __name__ == "__main__":
    main()