#!/usr/bin/env python3
import subprocess
import time
import logging
from collections import defaultdict, deque
import threading
import json
import os

CONFIG = {
    'check_interval': 10,
    'time_window': 60,
    'syn_threshold': 50,
    'conn_threshold': 100,
    'whitelist': ['127.0.0.1', '192.168.1.1'],
    'log_file': '/var/log/firewall_auto_block.log'
}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(CONFIG['log_file']),
        logging.StreamHandler()
    ]
)

class DosDetector:
    def __init__(self):
        self.syn_count = defaultdict(lambda: deque(maxlen=100))
        self.conn_count = defaultdict(lambda: deque(maxlen=100))
        self.blocked_ips = set()
        self.load_blocked_ips()
        
    def load_blocked_ips(self):
        try:
            result = subprocess.run(
                ['iptables', '-L', 'INPUT', '-n', '--line-numbers'],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if 'DROP' in line and '0.0.0.0/0' not in line:
                    parts = line.split()
                    for part in parts:
                        if self.is_valid_ip(part):
                            self.blocked_ips.add(part)
        except Exception as e:
            logging.error(f"Lỗi load blocked IPs: {e}")
    
    def is_valid_ip(self, ip):
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    def get_network_stats(self):
        syn_stats = defaultdict(int)
        conn_stats = defaultdict(int)
        
        try:
            result = subprocess.run(['netstat', '-tn'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'SYN_' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        ip = parts[4].split(':')[0]
                        if self.is_valid_ip(ip) and ip not in CONFIG['whitelist']:
                            syn_stats[ip] += 1
            
            result = subprocess.run(['ss', '-tn'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'ESTAB' in line or 'SYN-' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        ip = parts[4].split(':')[0]
                        if self.is_valid_ip(ip) and ip not in CONFIG['whitelist']:
                            conn_stats[ip] += 1
                            
        except Exception as e:
            logging.error(f"Lỗi get network stats: {e}")
            
        return syn_stats, conn_stats
    
    def update_stats(self, syn_stats, conn_stats):
        current_time = time.time()
        
        for ip, count in syn_stats.items():
            for _ in range(count):
                self.syn_count[ip].append(current_time)
                
        for ip, count in conn_stats.items():
            for _ in range(count):
                self.conn_count[ip].append(current_time)
    
    def clean_old_records(self):
        current_time = time.time()
        cutoff = current_time - CONFIG['time_window']
        
        for ip in list(self.syn_count.keys()):
            while (self.syn_count[ip] and self.syn_count[ip][0] < cutoff):
                self.syn_count[ip].popleft()
            if not self.syn_count[ip]:
                del self.syn_count[ip]
                
        for ip in list(self.conn_count.keys()):
            while (self.conn_count[ip] and self.conn_count[ip][0] < cutoff):
                self.conn_count[ip].popleft()
            if not self.conn_count[ip]:
                del self.conn_count[ip]
    
    def check_for_attacks(self):
        current_time = time.time()
        cutoff = current_time - CONFIG['time_window']
        
        for ip in list(self.syn_count.keys()):
            syn_in_window = sum(1 for ts in self.syn_count[ip] if ts >= cutoff)
            
            if (syn_in_window > CONFIG['syn_threshold'] and ip not in self.blocked_ips):
                self.block_ip(ip, f"SYN flood detected: {syn_in_window} SYN packets")
        
        for ip in list(self.conn_count.keys()):
            conn_in_window = sum(1 for ts in self.conn_count[ip] if ts >= cutoff)
            
            if (conn_in_window > CONFIG['conn_threshold'] and ip not in self.blocked_ips):
                self.block_ip(ip, f"Connection flood detected: {conn_in_window} connections")
    
    def block_ip(self, ip, reason):
        try:
            subprocess.run([
                'iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'
            ], check=True)
            
            self.blocked_ips.add(ip)
            logging.warning(f"Đã chặn IP {ip}: {reason}")
            
            alert_data = {
                'timestamp': time.time(),
                'ip': ip,
                'reason': reason,
                'action': 'BLOCKED'
            }
            self.write_alert(alert_data)
            
        except subprocess.CalledProcessError as e:
            logging.error(f"Lỗi khi chặn IP {ip}: {e}")
    
    def write_alert(self, alert_data):
        try:
            alert_file = '/var/log/firewall_alerts.json'
            alerts = []
            
            if os.path.exists(alert_file):
                with open(alert_file, 'r') as f:
                    try:
                        alerts = json.load(f)
                    except json.JSONDecodeError:
                        alerts = []
            
            alerts.append(alert_data)
            
            if len(alerts) > 100:
                alerts = alerts[-100:]
            
            with open(alert_file, 'w') as f:
                json.dump(alerts, f, indent=2)
                
        except Exception as e:
            logging.error(f"Lỗi ghi alert: {e}")
    
    def run(self):
        logging.info("Bắt đầu giám sát tự động phát hiện DoS/DDoS...")
        
        while True:
            try:
                syn_stats, conn_stats = self.get_network_stats()
                self.update_stats(syn_stats, conn_stats)
                self.clean_old_records()
                self.check_for_attacks()
                
                if len(self.blocked_ips) > 0:
                    logging.info(f"IP đang bị chặn: {len(self.blocked_ips)}")
                
                time.sleep(CONFIG['check_interval'])
                
            except Exception as e:
                logging.error(f"Lỗi trong vòng lặp chính: {e}")
                time.sleep(CONFIG['check_interval'])

def main():
    detector = DosDetector()
    detector.run()

if __name__ == "__main__":
    main()
