#!/bin/bash

echo "=== CÀI ĐẶT DEPENDENCIES CHO FIREWALL SYSTEM ==="

# Cập nhật hệ thống
echo "Đang cập nhật hệ thống..."
sudo apt update
sudo apt upgrade -y

# Cài đặt dependencies cơ bản
echo "Đang cài đặt dependencies..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-tk \
    iptables \
    fail2ban \
    net-tools \
    iproute2 \
    ssmtp \
    mailutils

# Cài đặt Python packages
echo "Đang cài đặt Python packages..."
pip3 install matplotlib flask

# Tạo thư mục log
echo "Đang tạo thư mục log..."
sudo mkdir -p /var/log/firewall
sudo touch /var/log/firewall_auto_block.log
sudo touch /var/log/firewall_alerts.json
sudo chmod 666 /var/log/firewall_auto_block.log
sudo chmod 666 /var/log/firewall_alerts.json

# Cấu hình Fail2Ban
echo "Đang cấu hình Fail2Ban..."
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Tạo custom filter cho HTTP flood
sudo tee /etc/fail2ban/filter.d/http-flood.conf > /dev/null <<EOF
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*HTTP.*" (404|503|500)
ignoreregex =
EOF

# Tạo systemd service cho auto-block
echo "Đang tạo systemd service..."
sudo tee /etc/systemd/system/firewall-auto-block.service > /dev/null <<EOF
[Unit]
Description=Firewall Auto Block DoS/DDoS Protection
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/firewall/auto_block.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Khởi động dịch vụ
echo "Đang khởi động dịch vụ..."
sudo systemctl daemon-reload
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

echo "=== CÀI ĐẶT HOÀN TẤT ==="
echo "Các dịch vụ đã được cài đặt:"
echo "✓ Python3 & dependencies"
echo "✓ IPTables"
echo "✓ Fail2Ban"
echo "✓ Systemd service"
echo ""
echo "Khởi chạy GUI: sudo python3 main_gui.py"
