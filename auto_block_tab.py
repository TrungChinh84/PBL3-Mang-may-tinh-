import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import json
import os

class AutoBlockTab:
    def __init__(self, parent):
        self.parent = parent
        self.config_file = "/etc/firewall_auto_block.conf"
        self.service_name = "firewall-auto-block"
        
        self.create_widgets()
        self.load_config()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Trạng Thái Tự Động Chặn")
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.status_var = tk.StringVar(value="Đang kiểm tra...")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)
        
        self.toggle_btn = ttk.Button(status_frame, text="Bật Tự Động", command=self.toggle_auto_block)
        self.toggle_btn.pack(side=tk.RIGHT, padx=5)
        
        # Configuration frame
        config_frame = ttk.LabelFrame(main_frame, text="Cấu Hình Ngưỡng")
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        # SYN Threshold
        ttk.Label(config_frame, text="SYN Threshold (packets/phút):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.syn_threshold = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.syn_threshold, width=10).grid(row=0, column=1, padx=5, pady=2)
        
        # Connection Threshold
        ttk.Label(config_frame, text="Connection Threshold (kết nối/phút):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.conn_threshold = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.conn_threshold, width=10).grid(row=1, column=1, padx=5, pady=2)
        
        # Check Interval
        ttk.Label(config_frame, text="Kiểm tra mỗi (giây):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.check_interval = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.check_interval, width=10).grid(row=2, column=1, padx=5, pady=2)
        
        # Save config button
        ttk.Button(config_frame, text="Lưu Cấu Hình", command=self.save_config).grid(row=3, column=0, columnspan=2, pady=5)
        
        # Whitelist frame
        whitelist_frame = ttk.LabelFrame(main_frame, text="IP Whitelist")
        whitelist_frame.pack(fill=tk.BOTH, expand=True)
        
        # Whitelist listbox
        whitelist_control_frame = ttk.Frame(whitelist_frame)
        whitelist_control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(whitelist_control_frame, text="Thêm IP:").pack(side=tk.LEFT)
        self.new_ip_var = tk.StringVar()
        ttk.Entry(whitelist_control_frame, textvariable=self.new_ip_var, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(whitelist_control_frame, text="Thêm", command=self.add_whitelist_ip).pack(side=tk.LEFT, padx=5)
        
        # Whitelist list
        listbox_frame = ttk.Frame(whitelist_frame)
        listbox_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.whitelist_listbox = tk.Listbox(listbox_frame)
        self.whitelist_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL, command=self.whitelist_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.whitelist_listbox.config(yscrollcommand=scrollbar.set)
        
        # Remove button
        ttk.Button(whitelist_frame, text="Xóa IP Đã Chọn", command=self.remove_whitelist_ip).pack(pady=5)
        
        # Check service status
        self.check_service_status()
    
    def check_service_status(self):
        """Kiểm tra trạng thái service"""
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', self.service_name],
                capture_output=True, text=True
            )
            if result.stdout.strip() == 'active':
                self.status_var.set("ĐANG BẬT - Tự động chặn đang chạy")
                self.toggle_btn.config(text="Tắt Tự Động")
            else:
                self.status_var.set("ĐANG TẮT - Tự động chặn không chạy")
                self.toggle_btn.config(text="Bật Tự Động")
        except Exception as e:
            self.status_var.set(f"Lỗi: {str(e)}")
    
    def toggle_auto_block(self):
        """Bật/tắt tự động chặn"""
        try:
            current_status = self.status_var.get()
            if "ĐANG BẬT" in current_status:
                # Tắt service
                subprocess.run(['systemctl', 'stop', self.service_name], check=True)
                subprocess.run(['systemctl', 'disable', self.service_name], check=True)
                messagebox.showinfo("Thành công", "Đã tắt chế độ tự động chặn")
            else:
                # Bật service
                subprocess.run(['systemctl', 'enable', self.service_name], check=True)
                subprocess.run(['systemctl', 'start', self.service_name], check=True)
                messagebox.showinfo("Thành công", "Đã bật chế độ tự động chặn")
            
            self.check_service_status()
            
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Lỗi", f"Không thể thay đổi trạng thái: {e}")
    
    def load_config(self):
        """Tải cấu hình từ file"""
        default_config = {
            'syn_threshold': '50',
            'conn_threshold': '100',
            'check_interval': '10',
            'whitelist': ['127.0.0.1', '192.168.1.1']
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
            else:
                config = default_config
                self.save_config_file(config)
        except:
            config = default_config
        
        # Áp dụng cấu hình vào GUI
        self.syn_threshold.set(config.get('syn_threshold', '50'))
        self.conn_threshold.set(config.get('conn_threshold', '100'))
        self.check_interval.set(config.get('check_interval', '10'))
        
        # Load whitelist
        self.whitelist_listbox.delete(0, tk.END)
        for ip in config.get('whitelist', []):
            self.whitelist_listbox.insert(tk.END, ip)
    
    def save_config(self):
        """Lưu cấu hình"""
        try:
            # Validate inputs
            syn_val = int(self.syn_threshold.get())
            conn_val = int(self.conn_threshold.get())
            interval_val = int(self.check_interval.get())
            
            if syn_val <= 0 or conn_val <= 0 or interval_val <= 0:
                raise ValueError("Các giá trị phải lớn hơn 0")
            
            # Lấy whitelist từ listbox
            whitelist = list(self.whitelist_listbox.get(0, tk.END))
            
            config = {
                'syn_threshold': str(syn_val),
                'conn_threshold': str(conn_val),
                'check_interval': str(interval_val),
                'whitelist': whitelist
            }
            
            self.save_config_file(config)
            messagebox.showinfo("Thành công", "Đã lưu cấu hình")
            
        except ValueError as e:
            messagebox.showerror("Lỗi", f"Giá trị không hợp lệ: {e}")
    
    def save_config_file(self, config):
        """Lưu cấu hình vào file"""
        # Đảm bảo thư mục tồn tại
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    def add_whitelist_ip(self):
        """Thêm IP vào whitelist"""
        ip = self.new_ip_var.get().strip()
        if not ip:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập IP")
            return
        
        # Validate IP
        if not self.is_valid_ip(ip):
            messagebox.showerror("Lỗi", "IP không hợp lệ")
            return
        
        # Thêm vào listbox nếu chưa tồn tại
        if ip not in self.whitelist_listbox.get(0, tk.END):
            self.whitelist_listbox.insert(tk.END, ip)
            self.new_ip_var.set("")
        else:
            messagebox.showwarning("Cảnh báo", "IP đã tồn tại trong whitelist")
    
    def remove_whitelist_ip(self):
        """Xóa IP khỏi whitelist"""
        selection = self.whitelist_listbox.curselection()
        if not selection:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn IP để xóa")
            return
        
        for index in reversed(selection):
            self.whitelist_listbox.delete(index)
    
    def is_valid_ip(self, ip):
        """Kiểm tra IP hợp lệ"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
