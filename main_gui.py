# main_gui.py
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import os
import sys
import json
from datetime import datetime, timezone

# Import các tab mới (giữ nguyên nếu bạn đã có các file này)
try:
    from auto_block_tab import AutoBlockTab
    from statistics_tab import StatisticsTab
    from fail2ban_tab import Fail2BanTab
except Exception:
    # Nếu bạn đang phát triển, cho phép chạy mà không có các tab kia
    AutoBlockTab = None
    StatisticsTab = None
    Fail2BanTab = None


LOG_JSON = '/var/log/firewall_alerts.json'    # file JSON ghi các alert
LOG_PLAIN = '/var/log/firewall_auto_block.log'  # (tuỳ chọn) file log thuần


class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Firewall Management System - PBL4")
        self.root.geometry("1200x800")

        # Kiểm tra quyền root
        self.check_root_privileges()

        # Các biến UI động
        self.blocked_count_var = tk.StringVar(value="0")
        self.today_alerts_var = tk.StringVar(value="0")
        self.auto_block_status_var = tk.StringVar(value="TẮT")

        # Tạo giao diện
        self.setup_gui()

        # Kiểm tra dependencies
        self.check_dependencies()

        # Bắt đầu vòng polling logs -> cập nhật dashboard
        self.update_dashboard_from_logs()
        # cập nhật mỗi 5s
        self._after_id = self.root.after(5000, self.periodic_update)

    def check_root_privileges(self):
        """Kiểm tra quyền root"""
        if os.geteuid() != 0:
            messagebox.showerror(
                "Lỗi Quyền Truy Cập",
                "Ứng dụng cần chạy với quyền root!\n\n"
                "Hãy chạy: sudo python3 main_gui.py"
            )
            sys.exit(1)

    def check_dependencies(self):
        """Kiểm tra các dependencies cần thiết"""
        missing_deps = []

        # Kiểm tra iptables
        try:
            subprocess.run(['iptables', '--version'], capture_output=True, check=True)
        except:
            missing_deps.append("iptables")

        # Kiểm tra fail2ban
        try:
            subprocess.run(['fail2ban-client', '--version'], capture_output=True, check=True)
        except:
            missing_deps.append("fail2ban")

        # Kiểm tra ss
        try:
            subprocess.run(['ss', '-h'], capture_output=True, check=True)
        except:
            missing_deps.append("iproute2")

        if missing_deps:
            messagebox.showwarning(
                "Thiếu Dependencies",
                f"Các công cụ sau chưa được cài đặt: {', '.join(missing_deps)}\n\n"
                "Một số tính năng có thể không hoạt động."
            )

    def setup_gui(self):
        """Thiết lập giao diện chính"""
        # Tạo notebook (tab controller)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Tạo các tab
        self.setup_dashboard_tab()
        self.setup_firewall_tab()
        self.setup_auto_block_tab()
        self.setup_statistics_tab()
        self.setup_fail2ban_tab()
        self.setup_settings_tab()

        # Status bar
        self.setup_status_bar()

    def setup_dashboard_tab(self):
        """Tab Dashboard tổng quan"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")

        # Header
        header_frame = ttk.Frame(dashboard_frame)
        header_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(
            header_frame,
            text="Firewall Management System",
            font=('Arial', 16, 'bold')
        ).pack(side=tk.LEFT)

        ttk.Button(
            header_frame,
            text="Làm Mới Tất Cả",
            command=self.refresh_all
        ).pack(side=tk.RIGHT)

        # Statistics cards
        stats_frame = ttk.Frame(dashboard_frame)
        stats_frame.pack(fill=tk.X, padx=10, pady=10)

        # Card 1: Tổng số IP bị chặn
        card1 = ttk.LabelFrame(stats_frame, text="IP Bị Chặn")
        card1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        ttk.Label(card1, textvariable=self.blocked_count_var, font=('Arial', 24, 'bold')).pack(pady=20)
        ttk.Label(card1, text="Tổng số IP đang bị chặn").pack(pady=5)

        # Card 2: Cảnh báo hôm nay
        card2 = ttk.LabelFrame(stats_frame, text="Cảnh Báo Hôm Nay")
        card2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        ttk.Label(card2, textvariable=self.today_alerts_var, font=('Arial', 24, 'bold')).pack(pady=20)
        ttk.Label(card2, text="Số cảnh báo trong ngày").pack(pady=5)

        # Card 3: Trạng thái tự động chặn
        card3 = ttk.LabelFrame(stats_frame, text="Tự Động Chặn")
        card3.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        ttk.Label(card3, textvariable=self.auto_block_status_var, font=('Arial', 24, 'bold'), foreground='red').pack(pady=20)
        ttk.Label(card3, text="Trạng thái tự động chặn").pack(pady=5)

        # Recent alerts
        alerts_frame = ttk.LabelFrame(dashboard_frame, text="Cảnh Báo Gần Đây")
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.alerts_text = tk.Text(alerts_frame, height=12)
        alerts_scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_text.yview)
        self.alerts_text.config(yscrollcommand=alerts_scrollbar.set)
        self.alerts_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        alerts_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.alerts_text.insert(tk.END, "Chưa có cảnh báo nào...\n")
        self.alerts_text.config(state=tk.DISABLED)

        # Quick actions
        actions_frame = ttk.LabelFrame(dashboard_frame, text="Hành Động Nhanh")
        actions_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(actions_frame, text="Xem Rules IPTables",
                  command=self.show_iptables_rules).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Kiểm Tra Dịch Vụ",
                  command=self.check_services).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Xem Logs",
                  command=self.view_logs).pack(side=tk.LEFT, padx=5)

    def setup_firewall_tab(self):
        """Tab quản lý firewall cơ bản (giữ nguyên từ code cũ)"""
        firewall_frame = ttk.Frame(self.notebook)
        self.notebook.add(firewall_frame, text="Firewall")

        # ... (giữ nguyên code firewall tab hiện tại của bạn)
        ttk.Label(firewall_frame, text="Firewall Management - Giữ nguyên từ code hiện tại").pack(pady=20)

    def setup_auto_block_tab(self):
        """Tab tự động chặn"""
        auto_block_frame = ttk.Frame(self.notebook)
        self.notebook.add(auto_block_frame, text="Tự Động Chặn")
        if AutoBlockTab:
            self.auto_block_tab = AutoBlockTab(auto_block_frame)
        else:
            ttk.Label(auto_block_frame, text="AutoBlockTab chưa được cài đặt").pack(pady=20)

    def setup_statistics_tab(self):
        """Tab thống kê"""
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="Thống Kê")
        if StatisticsTab:
            self.stats_tab = StatisticsTab(stats_frame)
        else:
            ttk.Label(stats_frame, text="StatisticsTab chưa được cài đặt").pack(pady=20)

    def setup_fail2ban_tab(self):
        """Tab Fail2Ban"""
        fail2ban_frame = ttk.Frame(self.notebook)
        self.notebook.add(fail2ban_frame, text="Fail2Ban")
        if Fail2BanTab:
            self.fail2ban_tab = Fail2BanTab(fail2ban_frame)
        else:
            ttk.Label(fail2ban_frame, text="Fail2BanTab chưa được cài đặt").pack(pady=20)

    def setup_settings_tab(self):
        """Tab cài đặt"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="Cài Đặt")

        # Cấu hình chung
        general_frame = ttk.LabelFrame(settings_frame, text="Cấu Hình Chung")
        general_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(general_frame, text="Địa chỉ Email nhận cảnh báo:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        email_var = tk.StringVar(value="admin@example.com")
        ttk.Entry(general_frame, textvariable=email_var, width=30).grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(general_frame, text="Log Level:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        log_level = ttk.Combobox(general_frame, values=['DEBUG', 'INFO', 'WARNING', 'ERROR'], state='readonly')
        log_level.set('INFO')
        log_level.grid(row=1, column=1, padx=5, pady=2)

        # Tự động khởi động
        startup_frame = ttk.LabelFrame(settings_frame, text="Tự Động Khởi Động")
        startup_frame.pack(fill=tk.X, padx=10, pady=10)

        self.auto_start_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            startup_frame,
            text="Tự động khởi động dịch vụ khi bật máy",
            variable=self.auto_start_var
        ).pack(anchor=tk.W, padx=5, pady=2)

        # Nút lưu cài đặt
        ttk.Button(settings_frame, text="Lưu Cài Đặt", command=self.save_settings).pack(pady=10)

    def setup_status_bar(self):
        """Thanh trạng thái"""
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_var = tk.StringVar(value="Sẵn sàng")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)

        ttk.Label(status_frame, text="PBL4 - Linux Firewall System").pack(side=tk.RIGHT, padx=5)

    def refresh_all(self):
        """Làm mới tất cả tab"""
        self.status_var.set("Đang làm mới dữ liệu...")
        # Làm mới từng tab
        if hasattr(self, 'auto_block_tab') and hasattr(self.auto_block_tab, 'check_service_status'):
            try:
                self.auto_block_tab.check_service_status()
            except Exception:
                pass

        if hasattr(self, 'stats_tab') and hasattr(self.stats_tab, 'refresh_data'):
            try:
                self.stats_tab.refresh_data()
            except Exception:
                pass

        if hasattr(self, 'fail2ban_tab') and hasattr(self.fail2ban_tab, 'refresh_status'):
            try:
                self.fail2ban_tab.refresh_status()
            except Exception:
                pass

        # Cập nhật dashboard từ log ngay
        self.update_dashboard_from_logs()

        self.status_var.set("Đã làm mới dữ liệu")
        messagebox.showinfo("Thành công", "Đã làm mới tất cả dữ liệu")

    def show_iptables_rules(self):
        """Hiển thị rules iptables"""
        try:
            result = subprocess.run(
                ['iptables', '-L', '-n', '-v'],
                capture_output=True, text=True
            )

            # Tạo cửa sổ mới để hiển thị rules
            rules_window = tk.Toplevel(self.root)
            rules_window.title("IPTables Rules")
            rules_window.geometry("800x600")

            text_widget = tk.Text(rules_window, wrap=tk.NONE)
            scrollbar_y = ttk.Scrollbar(rules_window, orient=tk.VERTICAL, command=text_widget.yview)
            scrollbar_x = ttk.Scrollbar(rules_window, orient=tk.HORIZONTAL, command=text_widget.xview)

            text_widget.config(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

            text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
            scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)

            text_widget.insert(tk.END, result.stdout)
            text_widget.config(state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể lấy rules: {e}")

    def check_services(self):
        """Kiểm tra trạng thái các dịch vụ"""
        services = {
            'firewall-auto-block': 'Tự động chặn',
            'fail2ban': 'Fail2Ban',
            'iptables': 'IPTables'
        }

        status_text = "KIỂM TRA DỊCH VỤ:\n\n"

        for service, name in services.items():
            try:
                if service == 'iptables':
                    # Đơn giản kiểm tra iptables
                    subprocess.run(['iptables', '-L'], capture_output=True, check=True)
                    status = "Đang chạy"
                else:
                    result = subprocess.run(
                        ['systemctl', 'is-active', service],
                        capture_output=True, text=True
                    )
                    status = "Đang chạy" if result.stdout.strip() == 'active' else "Dừng"

                status_text += f"• {name}: {status}\n"

            except:
                status_text += f"• {name}: Lỗi\n"

        messagebox.showinfo("Trạng Thái Dịch Vụ", status_text)

    def view_logs(self):
        """Xem logs hệ thống"""
        log_window = tk.Toplevel(self.root)
        log_window.title("System Logs")
        log_window.geometry("800x600")

        notebook = ttk.Notebook(log_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Tab firewall logs
        firewall_frame = ttk.Frame(notebook)
        notebook.add(firewall_frame, text="Firewall Logs")

        firewall_text = tk.Text(firewall_frame)
        firewall_scrollbar = ttk.Scrollbar(firewall_frame, orient=tk.VERTICAL, command=firewall_text.yview)
        firewall_text.config(yscrollcommand=firewall_scrollbar.set)

        firewall_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        firewall_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        try:
            # Đọc log firewall
            log_files = [
                LOG_PLAIN,
                LOG_JSON
            ]

            for log_file in log_files:
                if os.path.exists(log_file):
                    with open(log_file, 'r') as f:
                        firewall_text.insert(tk.END, f"=== {log_file} ===\n")
                        firewall_text.insert(tk.END, f.read())
                        firewall_text.insert(tk.END, "\n\n")
        except Exception as e:
            firewall_text.insert(tk.END, f"Lỗi đọc log: {e}")

        firewall_text.config(state=tk.DISABLED)

    def save_settings(self):
        """Lưu cài đặt"""
        messagebox.showinfo("Thành công", "Đã lưu cài đặt")
        self.status_var.set("Đã lưu cài đặt hệ thống")

    # ---------- Log parsing & dashboard update ----------
    def load_alerts(self):
        """Đọc file JSON log và trả về danh sách alert (mỗi alert là dict).
        File dự kiến là 1 JSON array: [ {...}, {...}, ... ]"""
        if not os.path.exists(LOG_JSON):
            return []

        try:
            with open(LOG_JSON, 'r') as f:
                data = f.read().strip()
                if not data:
                    return []
                # Một số file có thể ghi nhiều object lên từng dòng (ndjson) hoặc là 1 array.
                try:
                    alerts = json.loads(data)
                    # nếu file là object đơn lẻ, bọc thành list
                    if isinstance(alerts, dict):
                        return [alerts]
                    if isinstance(alerts, list):
                        return alerts
                    return []
                except json.JSONDecodeError:
                    # thử parse từng dòng json (ndjson)
                    alerts = []
                    for line in data.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            alerts.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
                    return alerts
        except Exception as e:
            # không raise, chỉ trả rỗng để GUI vẫn chạy
            print("Lỗi đọc log JSON:", e)
            return []

    def update_dashboard_from_logs(self):
        """Cập nhật các số liệu trên dashboard dựa trên file log"""
        alerts = self.load_alerts()
        if not alerts:
            # Reset về 0 / thông báo
            self.blocked_count_var.set("0")
            self.today_alerts_var.set("0")
            # giữ nguyên trạng thái auto block (không biết)
            if self.auto_block_status_var.get() not in ("BẬT", "TẮT"):
                self.auto_block_status_var.set("TẮT")
            # cập nhật text
            self.alerts_text.config(state=tk.NORMAL)
            self.alerts_text.delete(1.0, tk.END)
            self.alerts_text.insert(tk.END, "Chưa có cảnh báo nào...\n")
            self.alerts_text.config(state=tk.DISABLED)
            return

        # đếm unique IP bị BLOCKED
        blocked_ips = set()
        today_count = 0
        recent_lines = []

        now = datetime.now(timezone.utc)
        # midnight UTC của hôm nay để tính (nếu bạn muốn theo local time, sửa .utc -> local)
        midnight = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)

        for entry in alerts:
            # dự kiến entry chứa: timestamp, ip, reason, action
            ts = entry.get('timestamp')
            ip = entry.get('ip') or entry.get('src_ip') or entry.get('source')
            action = entry.get('action', '').upper() if entry.get('action') else ''
            reason = entry.get('reason', '')

            # timestamp có thể là epoch float/int hoặc chuỗi ISO
            entry_dt = None
            if ts:
                try:
                    entry_dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
                except Exception:
                    try:
                        entry_dt = datetime.fromisoformat(str(ts))
                    except Exception:
                        entry_dt = None

            if action == 'BLOCKED' and ip:
                blocked_ips.add(ip)

            if entry_dt:
                if entry_dt >= midnight:
                    today_count += 1
            else:
                # nếu không parse được timestamp, vẫn cộng như 1 cảnh báo
                today_count += 1

            # format recent line
            time_str = entry_dt.astimezone().strftime('%Y-%m-%d %H:%M:%S') if entry_dt else str(ts)
            recent_lines.append(f"{time_str} - {ip or 'unknown'} - {action} - {reason}")

        # sắp xếp recent theo thời gian mới nhất lên trên nếu có timestamp
        # try to sort by timestamp descending
        def _get_ts(e):
            try:
                # assume e original entry contains timestamp
                return float(e.get('timestamp') or 0)
            except Exception:
                return 0

        alerts_sorted = sorted(alerts, key=lambda x: _get_ts(x), reverse=True)
        recent_lines = []
        for entry in alerts_sorted[:50]:  # chỉ lấy 50 cảnh báo gần nhất
            ts = entry.get('timestamp')
            ip = entry.get('ip') or entry.get('src_ip') or entry.get('source')
            action = entry.get('action', '')
            reason = entry.get('reason', '')
            try:
                time_str = datetime.fromtimestamp(float(ts), tz=timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                time_str = str(ts)
            recent_lines.append(f"{time_str} - {ip or 'unknown'} - {action} - {reason}")

        # Update UI
        self.blocked_count_var.set(str(len(blocked_ips)))
        self.today_alerts_var.set(str(today_count))
        # Nếu trong alerts có action 'BLOCKED' -> auto bật
        self.auto_block_status_var.set("BẬT" if any((entry.get('action','').upper()=='BLOCKED') for entry in alerts) else "TẮT")

        # Update recent text widget
        self.alerts_text.config(state=tk.NORMAL)
        self.alerts_text.delete(1.0, tk.END)
        for line in recent_lines:
            self.alerts_text.insert(tk.END, line + "\n")
        self.alerts_text.config(state=tk.DISABLED)

    def periodic_update(self):
        """Hàm gọi định kỳ để refresh dashboard"""
        try:
            self.update_dashboard_from_logs()
        except Exception as e:
            print("Lỗi periodic_update:", e)
        # triệu hồi lại sau 5s
        self._after_id = self.root.after(5000, self.periodic_update)

    def on_close(self):
        """Hủy after khi đóng"""
        try:
            if hasattr(self, '_after_id') and self._after_id:
                self.root.after_cancel(self._after_id)
        except Exception:
            pass
        self.root.destroy()


def main():
    root = tk.Tk()
    app = FirewallGUI(root)
    # bind đóng cửa sổ
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()

