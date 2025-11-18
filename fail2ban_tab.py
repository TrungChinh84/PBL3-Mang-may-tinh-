# fail2ban_tab.py
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess

class Fail2BanTab:
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Top: status + buttons
        top_frame = ttk.Frame(self.frame)
        top_frame.pack(fill=tk.X, padx=8, pady=6)

        self.status_label = ttk.Label(top_frame, text="Trạng Thái Fail2Ban: --")
        self.status_label.pack(side=tk.LEFT, padx=(0,10))

        btn_frame = ttk.Frame(top_frame)
        btn_frame.pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="Khởi Động", command=self.start_fail2ban).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Dừng", command=self.stop_fail2ban).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Khởi Động Lại", command=self.restart_fail2ban).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Làm Mới", command=self.refresh).pack(side=tk.LEFT, padx=4)

        # Middle: jails treeview
        jail_frame = ttk.LabelFrame(self.frame, text="Trạng Thái Jails")
        jail_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        self.jail_tree = ttk.Treeview(jail_frame, columns=("jail","status","filter","banned"), show='headings', height=6)
        self.jail_tree.heading("jail", text="Jail")
        self.jail_tree.heading("status", text="Trạng Thái")
        self.jail_tree.heading("filter", text="Filter")
        self.jail_tree.heading("banned", text="Số IP Bị Ban")
        self.jail_tree.column("jail", width=150)
        self.jail_tree.column("status", width=150)
        self.jail_tree.column("filter", width=200)
        self.jail_tree.column("banned", width=100, anchor=tk.CENTER)
        self.jail_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        self.jail_tree.bind("<<TreeviewSelect>>", self.on_jail_selected)

        jail_scroll = ttk.Scrollbar(jail_frame, orient=tk.VERTICAL, command=self.jail_tree.yview)
        self.jail_tree.configure(yscroll=jail_scroll.set)
        jail_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Bottom: banned IPs for selected jail
        banned_frame = ttk.LabelFrame(self.frame, text="IP Đang Bị Ban")
        banned_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        self.banned_tree = ttk.Treeview(banned_frame, columns=("ip","time","count"), show='headings', height=8)
        self.banned_tree.heading("ip", text="IP")
        self.banned_tree.heading("time", text="Thời Gian")
        self.banned_tree.heading("count", text="Số Lần Vi Phạm")
        self.banned_tree.column("ip", width=180)
        self.banned_tree.column("time", width=180)
        self.banned_tree.column("count", width=100, anchor=tk.CENTER)
        self.banned_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        banned_scroll = ttk.Scrollbar(banned_frame, orient=tk.VERTICAL, command=self.banned_tree.yview)
        self.banned_tree.configure(yscroll=banned_scroll.set)
        banned_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Buttons under banned list
        action_frame = ttk.Frame(self.frame)
        action_frame.pack(fill=tk.X, padx=8, pady=6)
        ttk.Button(action_frame, text="Làm Mới", command=self.refresh).pack(side=tk.LEFT, padx=4)
        ttk.Button(action_frame, text="Gỡ Ban IP", command=self.unban_selected).pack(side=tk.LEFT, padx=4)
        ttk.Button(action_frame, text="Gỡ Ban Tất Cả", command=self.unban_all).pack(side=tk.LEFT, padx=4)

        # initial load
        self.refresh()

    # ------- helper: run fail2ban-client safely -------
    def _run_fb(self, args):
        try:
            out = subprocess.check_output(['fail2ban-client'] + args, stderr=subprocess.STDOUT, text=True)
            return out
        except subprocess.CalledProcessError as e:
            return e.output or ""
        except FileNotFoundError:
            return ""

    # ------- control fail2ban service -------
    def start_fail2ban(self):
        subprocess.run(['systemctl', 'start', 'fail2ban'])
        self.refresh()

    def stop_fail2ban(self):
        subprocess.run(['systemctl', 'stop', 'fail2ban'])
        self.refresh()

    def restart_fail2ban(self):
        subprocess.run(['systemctl', 'restart', 'fail2ban'])
        self.refresh()

    # ------- parse & UI update -------
    def refresh(self):
        # update status
        try:
            s = subprocess.check_output(['systemctl', 'is-active', 'fail2ban'], text=True).strip()
            if s == 'active':
                self.status_label.config(text="ĐANG CHẠY - Fail2ban hoạt động bình thường")
            else:
                self.status_label.config(text=f"Dừng: {s}")
        except Exception:
            self.status_label.config(text="Không thể kiểm tra trạng thái fail2ban")

        # clear trees
        for i in self.jail_tree.get_children():
            self.jail_tree.delete(i)
        for i in self.banned_tree.get_children():
            self.banned_tree.delete(i)

        # get jails
        jails_out = self._run_fb(['status'])
        # parse jail list from "Jail list:   a, b, c"
        jails = []
        for line in jails_out.splitlines():
            if 'Jail list' in line:
                try:
                    # everything after ':' comma separated
                    jlist = line.split(':',1)[1].strip()
                    jails = [j.strip() for j in jlist.split(',') if j.strip()]
                except Exception:
                    jails = []
                break

        # for each jail get status and number banned
        for jail in jails:
            info = self._run_fb(['status', jail])
            # default values
            status_text = "OK"
            filter_desc = ""
            banned_count = 0

            for l in info.splitlines():
                l = l.strip()
                if l.startswith("Currently banned:"):
                    try:
                        banned_count = int(l.split(':',1)[1].strip())
                    except:
                        banned_count = 0
                # optionally parse filter or other fields if present

            self.jail_tree.insert('', tk.END, values=(jail, status_text, filter_desc, str(banned_count)))

    def on_jail_selected(self, event):
        sel = self.jail_tree.selection()
        if not sel:
            return
        jail = self.jail_tree.item(sel[0])['values'][0]
        self.load_banned_for_jail(jail)

    def load_banned_for_jail(self, jail):
        # clear banned tree
        for i in self.banned_tree.get_children():
            self.banned_tree.delete(i)

        info = self._run_fb(['status', jail])
        # look for "Banned IP list: 1.2.3.4 5.6.7.8"
        banned_ips = []
        for l in info.splitlines():
            l = l.strip()
            if l.startswith("Banned IP list:"):
                ips = l.split(':',1)[1].strip()
                if ips:
                    banned_ips = [ip for ip in ips.split() if ip.strip()]
                break

        # if fail2ban supports "get <jail> banned" newer interface, you can use it
        # populate tree: we'll not have per-ip time/count by default from fail2ban-client status
        for ip in banned_ips:
            self.banned_tree.insert('', tk.END, values=(ip, "-", "-"))

    # ------- unban functions -------
    def unban_selected(self):
        sel = self.banned_tree.selection()
        if not sel:
            messagebox.showinfo("Thông báo", "Chưa chọn IP để gỡ ban")
            return
        ips = [self.banned_tree.item(i)['values'][0] for i in sel]
        # get current selected jail
        jsel = self.jail_tree.selection()
        if not jsel:
            messagebox.showerror("Lỗi", "Chưa chọn jail")
            return
        jail = self.jail_tree.item(jsel[0])['values'][0]

        confirm = messagebox.askyesno("Xác nhận", f"Gỡ ban những IP sau khỏi jail '{jail}'?\n\n" + "\n".join(ips))
        if not confirm:
            return

        for ip in ips:
            try:
                subprocess.run(['fail2ban-client', 'set', jail, 'unbanip', ip], check=False)
            except Exception as e:
                print("unban error", e)
        self.refresh()

    def unban_all(self):
        jsel = self.jail_tree.selection()
        if not jsel:
            messagebox.showerror("Lỗi", "Chưa chọn jail")
            return
        jail = self.jail_tree.item(jsel[0])['values'][0]
        confirm = messagebox.askyesno("Xác nhận", f"Gỡ ban tất cả IP trong jail '{jail}'?")
        if not confirm:
            return
        # get banned list then unban each
        info = self._run_fb(['status', jail])
        banned_ips = []
        for l in info.splitlines():
            l = l.strip()
            if l.startswith("Banned IP list:"):
                ips = l.split(':',1)[1].strip()
                if ips:
                    banned_ips = [ip for ip in ips.split() if ip.strip()]
                break
        for ip in banned_ips:
            try:
                subprocess.run(['fail2ban-client', 'set', jail, 'unbanip', ip], check=False)
            except Exception:
                pass
        self.refresh()

