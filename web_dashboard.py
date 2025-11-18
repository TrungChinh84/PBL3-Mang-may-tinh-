#!/usr/bin/env python3
"""
Web Dashboard để quản trị firewall
"""

from flask import Flask, render_template, jsonify, request
import subprocess
import json
import os
from datetime import datetime

app = Flask(__name__)

# File lưu trữ alerts
ALERT_FILE = '/var/log/firewall_alerts.json'

class FirewallManager:
    @staticmethod
    def get_iptables_rules():
        """Lấy danh sách rules iptables"""
        try:
            result = subprocess.run(
                ['iptables', '-L', 'INPUT', '-n', '--line-numbers'],
                capture_output=True, text=True
            )
            return result.stdout
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def get_blocked_ips():
        """Lấy danh sách IP đang bị chặn"""
        blocked = []
        try:
            result = subprocess.run(
                ['iptables', '-L', 'INPUT', '-n', '--line-numbers'],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if 'DROP' in line:
                    parts = line.split()
                    for part in parts:
                        if FirewallManager.is_valid_ip(part):
                            blocked.append(part)
            return list(set(blocked))
        except Exception as e:
            return []
    
    @staticmethod
    def is_valid_ip(ip):
        """Kiểm tra IP hợp lệ"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    @staticmethod
    def block_ip(ip):
        """Chặn IP thủ công"""
        try:
            subprocess.run([
                'iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'
            ], check=True)
            return True, f"Đã chặn IP {ip}"
        except subprocess.CalledProcessError as e:
            return False, f"Lỗi khi chặn IP: {e}"
    
    @staticmethod
    def unblock_ip(ip):
        """Gỡ chặn IP"""
        try:
            subprocess.run([
                'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'
            ], check=True)
            return True, f"Đã gỡ chặn IP {ip}"
        except subprocess.CalledProcessError as e:
            return False, f"Lỗi khi gỡ chặn IP: {e}"
    
    @staticmethod
    def get_alerts():
        """Lấy danh sách alerts"""
        try:
            if os.path.exists(ALERT_FILE):
                with open(ALERT_FILE, 'r') as f:
                    alerts = json.load(f)
                # Sắp xếp theo thời gian mới nhất
                alerts.sort(key=lambda x: x['timestamp'], reverse=True)
                return alerts
            return []
        except Exception as e:
            return []

@app.route('/')
def index():
    """Trang chủ dashboard"""
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    """API trạng thái hệ thống"""
    status = {
        'blocked_ips': FirewallManager.get_blocked_ips(),
        'total_blocked': len(FirewallManager.get_blocked_ips()),
        'alerts': FirewallManager.get_alerts()[:10],  # 10 alerts mới nhất
        'timestamp': datetime.now().isoformat()
    }
    return jsonify(status)

@app.route('/api/block_ip', methods=['POST'])
def api_block_ip():
    """API chặn IP"""
    data = request.json
    ip = data.get('ip', '').strip()
    
    if not FirewallManager.is_valid_ip(ip):
        return jsonify({'success': False, 'message': 'IP không hợp lệ'})
    
    success, message = FirewallManager.block_ip(ip)
    return jsonify({'success': success, 'message': message})

@app.route('/api/unblock_ip', methods=['POST'])
def api_unblock_ip():
    """API gỡ chặn IP"""
    data = request.json
    ip = data.get('ip', '').strip()
    
    if not FirewallManager.is_valid_ip(ip):
        return jsonify({'success': False, 'message': 'IP không hợp lệ'})
    
    success, message = FirewallManager.unblock_ip(ip)
    return jsonify({'success': success, 'message': message})

@app.route('/api/rules')
def api_rules():
    """API xem rules iptables"""
    rules = FirewallManager.get_iptables_rules()
    return jsonify({'rules': rules})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
