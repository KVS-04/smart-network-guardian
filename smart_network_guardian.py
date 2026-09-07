# smart_guardian_app_monitor_v2.py
"""
Smart Network Guardian - App Monitor Version v2

Features:
- Main menu with new "Monitor Selected Application" screen
- App monitor screen now has "Clear Alerts" and "Export Data" buttons
- New screen uses psutil to find and monitor a single app's network ports
- Rounded button and UI element style
- "Pop-out" feature for Devices, Alerts, and Graph
- All previous features (network scan, file watch) remain in "Start Using"
"""
import sys
import os
import sqlite3
import json
import time
import threading
import queue
import random
from datetime import datetime
from collections import defaultdict, deque, Counter

try:
    import psutil
except ImportError:
    print("Error: 'psutil' library not found. Please install it: pip install psutil")
    sys.exit(1)

# UI & plotting
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QTextEdit, QLabel, 
    QFileDialog, QHeaderView, QFrame, QTabWidget, QGroupBox, QProgressBar,
    QStackedWidget, QComboBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt5.QtGui import QColor, QFont, QIcon
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt
from matplotlib.figure import Figure

# Networking & sniffing
from scapy.all import ARP, Ether, srp, sniff, conf, get_if_addr
import subprocess
import platform

try:
    import nmap
    HAS_NMAP = True
except Exception:
    HAS_NMAP = False

import socket
from mac_vendor_lookup import MacLookup

mac_lookup = MacLookup()
try:
    mac_lookup.update_vendors()
except:
    print("[!] Could not update MAC vendor database")

# File monitoring
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ML / anomaly
from sklearn.ensemble import IsolationForest
import numpy as np

DB_PATH = "sng_logs.db"
WATCH_DIRECTORIES = [os.path.expanduser("~/Documents")]
IP_BLACKLIST = {"10.138.235.196"}

# =========================
# Styling Constants
# =========================
DARK_THEME = """
QMainWindow {
    background-color: #1e1e2e;
}
QWidget {
    background-color: #1e1e2e;
    color: #cdd6f4;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 10pt;
}
QGroupBox {
    border: 2px solid #313244;
    border-radius: 8px; 
    margin-top: 12px;
    padding-top: 15px;
    font-weight: bold;
    color: #89b4fa;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 15px;
    padding: 0 5px;
}
QPushButton {
    background-color: #45475a;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 8px; 
    padding: 10px 15px;
    font-weight: bold;
    font-family: 'Consolas', 'Courier New', monospace;
    min-width: 100px;
}
QPushButton:hover {
    background-color: #585b70;
    border: 1px solid #89b4fa; /* Blue glow */
}
QPushButton:pressed {
    background-color: #313244;
    border: 1px solid #cdd6f4;
}
QPushButton#primary {
    background-color: #89b4fa;
    color: #1e1e2e;
    border: 1px solid #89b4fa;
}
QPushButton#primary:hover {
    background-color: #9ac2f5;
    border: 1px solid #a6e3a1; /* Green glow */
}
QPushButton#danger {
    background-color: #f38ba8;
    color: #1e1e2e;
    border: 1px solid #f38ba8;
}
QPushButton#danger:hover {
    background-color: #f5a6bb;
    border: 1px solid #fab387; /* Orange glow */
}
QPushButton#success {
    background-color: #a6e3a1;
    color: #1e1e2e;
    border: 1px solid #a6e3a1;
}
QPushButton#success:hover {
    background-color: #bbf2b7;
    border: 1px solid #89b4fa; /* Blue glow */
}

/* === MENU & BACK BUTTON STYLES === */
QPushButton#menu {
    padding: 20px;
    font-size: 14pt;
    min-width: 300px;
}
QPushButton#back {
    background-color: #313244;
    color: #89b4fa;
    min-width: 80px;
    max-width: 80px;
    padding: 5px;
    font-weight: bold;
    border: 1px solid #45475a;
}
QPushButton#back:hover {
    background-color: #45475a;
    border: 1px solid #89b4fa;
}
QPushButton#pop_out {
    font-family: 'Segoe UI', Arial, sans-serif;
    font-weight: bold;
    font-size: 9pt;
    min-width: 100px;
    max-width: 100px;
    padding: 5px;
    color: #cdd6f4;
    background-color: #313244;
    border: 1px solid #45475a;
}
QPushButton#pop_out:hover {
    background-color: #45475a;
    border: 1px solid #89b4fa;
}
/* === END NEW STYLES === */

QTableWidget {
    background-color: #181825;
    alternate-background-color: #1e1e2e;
    gridline-color: #313244;
    border: 1px solid #313244;
    border-radius: 8px;
    selection-background-color: #45475a;
}
QTableWidget::item {
    padding: 8px;
}
QHeaderView::section {
    background-color: #313244;
    color: #cdd6f4;
    padding: 10px;
    border: none;
    font-weight: bold;
    border-radius: 0px; /* Keep headers sharp */
}
QTextEdit {
    background-color: #181825;
    border: 1px solid #313244;
    border-radius: 8px;
    padding: 10px;
    color: #cdd6f4;
    font-family: 'Consolas', 'Courier New', monospace;
}
QTabWidget::pane {
    border: 1px solid #313244;
    border-radius: 8px;
    background-color: #1e1e2e;
}
QTabBar::tab {
    background-color: #313244;
    color: #cdd6f4;
    padding: 10px 20px;
    margin-right: 2px;
    border-top-left-radius: 8px; 
    border-top-right-radius: 8px; 
    font-family: 'Consolas', 'Courier New', monospace;
}
QTabBar::tab:selected {
    background-color: #45475a;
}
QTabBar::tab:hover {
    background-color: #585b70;
}
QLabel {
    color: #cdd6f4;
}
QLabel#header {
    font-size: 14pt;
    font-weight: bold;
    color: #89b4fa;
    padding: 5px;
}
QLabel#stat {
    font-size: 24pt;
    font-weight: bold;
    color: #a6e3a1;
}
QLabel#statLabel {
    font-size: 9pt;
    color: #6c7086;
}
QLabel#title {
    font-size: 24pt;
    font-weight: bold;
    color: #89b4fa;
    padding-bottom: 10px;
}
QLabel#content {
    font-size: 12pt;
    color: #cdd6f4;
    line-height: 1.5;
}
QFrame#content_frame {
    background-color: #313244;
    border: 1px solid #45475a;
    border-radius: 8px;
    padding: 20px;
}
QProgressBar {
    border: 1px solid #313244;
    border-radius: 8px; 
    background-color: #181825;
    text-align: center;
    color: #cdd6f4;
}
QProgressBar::chunk {
    background-color: #89b4fa;
    border-radius: 8px; 
}
/* === NEW QCOMBOBOX STYLE === */
QComboBox {
    background-color: #313244;
    border: 1px solid #45475a;
    border-radius: 8px;
    padding: 8px 10px;
    color: #cdd6f4;
    font-family: 'Consolas', 'Courier New', monospace;
}
QComboBox QAbstractItemView {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    selection-background-color: #585b70;
}
QComboBox::drop-down {
    border: none;
    background-color: #45475a;
    border-top-right-radius: 8px;
    border-bottom-right-radius: 8px;
    width: 20px;
}
QComboBox::down-arrow {
    image: url(data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='16' height='16' fill='white'><path d='M7.247 11.14 2.451 5.658C1.885 5.013 2.345 4 3.204 4h9.592a1 1 0 0 1 .753 1.659l-4.796 5.48a1 1 0 0 1-1.506 0z'/></svg>);
}
"""

# =========================
# Database utilities
# =========================
def adapt_datetime(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S")

sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter('TIMESTAMP', lambda x: datetime.strptime(x.decode('utf-8'), "%Y-%m-%d %H:%M:%S"))

def init_db():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS devices (
                 ip TEXT PRIMARY KEY, mac TEXT, hostname TEXT, vendor TEXT, 
                 last_seen TIMESTAMP, threat TEXT, details TEXT
             )''')
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, ts TIMESTAMP, 
                 level TEXT, src TEXT, dst TEXT, msg TEXT
             )''')
    conn.commit()
    conn.close()

def log_device(dev):
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    c = conn.cursor()
    c.execute('''INSERT OR REPLACE INTO devices (ip,mac,hostname,vendor,last_seen,threat,details)
                 VALUES (?,?,?,?,?,?,?)''',
             (dev['ip'], dev.get('mac',''), dev.get('hostname',''), dev.get('vendor',''),
              datetime.now(), dev.get('threat','Unknown'), json.dumps(dev.get('details',{}))))
    conn.commit()
    conn.close()

def log_alert(level, src, dst, msg):
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    c = conn.cursor()
    c.execute('INSERT INTO alerts (ts,level,src,dst,msg) VALUES (?,?,?,?,?)',
             (datetime.now(), level, src, dst, msg))
    conn.commit()
    conn.close()


# =========================
# Device discovery
# =========================
def arp_scan(timeout=2, iface=None):
    try:
        local_ip = get_if_addr(conf.iface) if iface is None else get_if_addr(iface)
        parts = local_ip.split('.')
        net = '.'.join(parts[:3]) + '.0/24'
        print(f"[+] ARP scanning {net} on interface {conf.iface}")
        
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp = ARP(pdst=net)
        
        ans, unans = srp(ether/arp, timeout=timeout, verbose=0, iface=conf.iface)
        
        devices = []
        for s, r in ans:
            devices.append({'ip': r.psrc, 'mac': r.hwsrc})
            print(f"[+] Found device: {r.psrc} ({r.hwsrc})")
        
        print(f"[+] Total devices discovered: {len(devices)}")
        return devices
    except Exception as e:
        print(f"[!] ARP scan error: {e}")
        import traceback
        traceback.print_exc()
        return []

def nmap_scan_host(ip):
    if not HAS_NMAP:
        return {}
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-T4 -sS -Pn --top-ports 100')
        host = nm[ip]
        open_ports = []
        services = {}
        if 'tcp' in host:
            for p in host['tcp']:
                state = host['tcp'][p]['state']
                if state == 'open':
                    open_ports.append(p)
                    services[p] = host['tcp'][p].get('name','')
        return {'open_ports': open_ports, 'services': services}
    except Exception as e:
        print("nmap scan error:", e)
        return {}

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        pass
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output(["nbtstat", "-A", ip], text=True)
            for line in output.splitlines():
                if "UNIQUE" in line and "<00>" in line:
                    parts = line.split()
                    if len(parts) >= 1:
                        return parts[0]
        except:
            pass
    return "Unknown"

def get_vendor(mac):
    try:
        return mac_lookup.lookup(mac)
    except:
        return "Unknown"

def compute_threat_score(device_info, traffic_stats):
    score = 0
    open_ports = device_info.get('details', {}).get('open_ports', [])
    if len(open_ports) >= 10:
        score += 3
    elif len(open_ports) >= 3:
        score += 1
    suspicious = {22,23,3389,445,5900}
    if any(p in suspicious for p in open_ports):
        score += 2
    if device_info.get('ip') in IP_BLACKLIST:
        score += 4
    if traffic_stats.get('spike', False):
        score += 2
    if score >= 5:
        return "High"
    elif score >= 2:
        return "Medium"
    else:
        return "Low"


# =========================
# THREAD: Port Monitor
# =========================
class PortMonitorThread(threading.Thread):
    def __init__(self, app_name, target_ports_set):
        super().__init__(daemon=True)
        self.app_name = app_name
        self.target_ports_set = target_ports_set 
        self.running = True

    def run(self):
        print(f"[*] Starting port monitor for: {self.app_name}")
        while self.running:
            new_ports = set()
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.info['name'] == self.app_name:
                        try:
                            connections = proc.connections(kind='inet')
                            for conn in connections:
                                new_ports.add(conn.laddr.port)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
            except Exception as e:
                print(f"[!] Error in PortMonitorThread: {e}")
            
            self.target_ports_set.clear()
            self.target_ports_set.update(new_ports)
            
            time.sleep(5)
        print(f"[*] Stopping port monitor for: {self.app_name}")

    def stop(self):
        self.running = False

# =========================
# THREAD: SnifferThread
# =========================
class SnifferThread(threading.Thread):
    def __init__(self, packet_queue, mode='network', target_ports_set=None, iface=None):
        super().__init__(daemon=True)
        self.iface = iface or conf.iface
        self.packet_queue = packet_queue
        self.running = threading.Event()
        self.running.set()
        
        self.mode = mode
        self.target_ports_set = target_ports_set
        
    def run(self):
        print(f"[*] Packet sniffing started on {self.iface} (Mode: {self.mode})")
        sniff(prn=self.handle_pkt, store=0, iface=self.iface, stop_filter=self.should_stop)
    
    def handle_pkt(self, pkt):
        if self.mode == 'application':
            if self.target_ports_set is None:
                return
            if not (pkt.haslayer('TCP') or pkt.haslayer('UDP')):
                return
            if pkt.sport not in self.target_ports_set and pkt.dport not in self.target_ports_set:
                return

        info = {
            'ts': time.time(),
            'src': pkt.sprintf("%IP.src%") if pkt.haslayer('IP') else None,
            'dst': pkt.sprintf("%IP.dst%") if pkt.haslayer('IP') else None,
            'len': len(pkt),
            'proto': pkt.lastlayer().name if pkt.lastlayer() else ''
        }
        self.packet_queue.put(info)
    
    def should_stop(self, pkt):
        return not self.running.is_set()
    
    def stop(self):
        self.running.clear()

# =========================
# THREAD: AnomalyDetector
# =========================
class AnomalyDetector(threading.Thread):
    def __init__(self, packet_queue, alert_callback=None):
        super().__init__(daemon=True)
        self.q = packet_queue
        self.alert = alert_callback or (lambda *a, **k: None)
        self.running = True
        self.flow_counts = Counter()
        self.pkt_history = deque(maxlen=1000)
        self.outbound_bytes = defaultdict(int)
    
    def run(self):
        while self.running:
            try:
                info = self.q.get(timeout=1)
            except queue.Empty:
                continue
            now = info['ts']
            src = info['src']
            dst = info['dst']
            size = info['len'] or 0
            self.pkt_history.append((now, src, dst, size))
            
            if src and dst:
                key = (src, dst)
                self.flow_counts[key] += 1
                if src and src.startswith(('10.', '172.', '192.')):
                    if dst and not dst.startswith(('10.', '172.', '192.')):
                        self.outbound_bytes[src] += size
            
            if len(self.pkt_history) >= 200:
                per_src = Counter()
                for _, s, d, _ in list(self.pkt_history)[-200:]:
                    per_src[s] += 1
                if not per_src: 
                    continue
                top_src, top_count = per_src.most_common(1)[0]
                if top_count > 100:
                    msg = f"High rate of connections from {top_src} ({top_count}/200 pkts)"
                    self.alert("High", top_src, None, msg)
                    log_alert("High", top_src, None, msg)
                    self.pkt_history.clear()
            
            for host, b in list(self.outbound_bytes.items()):
                if b > 5_000_000:
                    msg = f"Large outbound transfer from {host} (~{b} bytes)"
                    self.alert("High", host, None, msg)
                    log_alert("High", host, None, msg)
                    self.outbound_bytes[host] = 0
    
    def stop(self):
        self.running = False

# =========================
# THREAD: File monitoring
# =========================
class MassModifyHandler(FileSystemEventHandler):
    def __init__(self, alert_callback):
        super().__init__()
        self.alert = alert_callback
        self.recent_mods = deque()
        self.lock = threading.Lock()
    
    def on_modified(self, event):
        if event.is_directory:
            return
        ts = time.time()
        with self.lock:
            self.recent_mods.append(ts)
            cutoff = ts - 60
            while self.recent_mods and self.recent_mods[0] < cutoff:
                self.recent_mods.popleft()
            if len(self.recent_mods) > 30:
                msg = f"Mass file modifications detected ({len(self.recent_mods)} files/60s)"
                self.alert("High", "Local", None, msg)
                log_alert("High", "Local", None, msg)
                self.recent_mods.clear()

def start_watchdog(dirs, alert_cb):
    observer = Observer()
    handler = MassModifyHandler(alert_cb)
    for d in dirs:
        if os.path.exists(d):
            print(f"[+] Starting file watch on: {d}")
            observer.schedule(handler, d, recursive=True)
        else:
            print(f"[!] Directory not found, cannot watch: {d}")
    observer.start()
    return observer

# =========================
# GUI Component: TrafficCanvas
# =========================
class ModernTrafficCanvas(FigureCanvas):
    def __init__(self, parent=None):
        plt.style.use('dark_background')
        self.fig = Figure(figsize=(8, 5), facecolor='#181825')
        self.ax = self.fig.add_subplot(111)
        super().__init__(self.fig)
        
        self.times = deque(maxlen=60)
        self.values = deque(maxlen=60)
        
        self.ax.set_facecolor('#181825')
        self.ax.set_title("Network Traffic (Packets/sec)", color='#89b4fa', fontsize=12, fontweight='bold')
        self.line, = self.ax.plot([], [], color='#89b4fa', linewidth=2)
        self.ax.fill_between([], [], alpha=0.3, color='#89b4fa')
        self.ax.set_ylim(0, 100)
        self.ax.set_xlim(0, 60)
        self.ax.set_xlabel("Seconds Ago", color='#cdd6f4')
        self.ax.set_ylabel("Packets", color='#cdd6f4')
        self.ax.tick_params(colors='#6c7086')
        self.ax.grid(True, alpha=0.2, color='#313244')
        self.ax.spines['top'].set_visible(False)
        self.ax.spines['right'].set_visible(False)
        self.ax.spines['left'].set_color('#313244')
        self.ax.spines['bottom'].set_color('#313244')
        self.fig.tight_layout()
        self.draw()
    
    def update_plot(self, value):
        self.values.append(value)
        self.times.append(time.time())
        y = list(self.values)
        x = list(range(len(y)))
        
        self.ax.clear()
        self.ax.set_facecolor('#181825')
        self.ax.set_title("Network Traffic (Packets/sec)", color='#89b4fa', fontsize=12, fontweight='bold')
        
        if y:
            self.ax.plot(x[::-1], y[::-1], color='#89b4fa', linewidth=2)
            self.ax.fill_between(x[::-1], y[::-1], alpha=0.3, color='#89b4fa')
            max_y = max(y) if y else 10
            self.ax.set_ylim(0, max(10, max_y * 1.1))
        
        self.ax.set_xlim(0, 60)
        self.ax.set_xlabel("Seconds Ago", color='#cdd6f4')
        self.ax.set_ylabel("Packets", color='#cdd6f4')
        self.ax.tick_params(colors='#6c7086')
        self.ax.grid(True, alpha=0.2, color='#313244')
        self.ax.spines['top'].set_visible(False)
        self.ax.spines['right'].set_visible(False)
        self.ax.spines['left'].set_color('#313244')
        self.ax.spines['bottom'].set_color('#313244')
        self.fig.tight_layout()
        self.draw_idle()

# =========================
# GUI Component: StatCard
# =========================
class StatCard(QFrame):
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.StyledPanel)
        self.setStyleSheet("""
            StatCard {
                background-color: #313244;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        self.label = QLabel(title)
        self.label.setObjectName("statLabel")
        self.label.setAlignment(Qt.AlignCenter)
        
        self.value = QLabel("0")
        self.value.setObjectName("stat")
        self.value.setAlignment(Qt.AlignCenter)
        
        layout.addWidget(self.value)
        layout.addWidget(self.label)
        layout.setSpacing(5)
    
    def set_value(self, val, color="#a6e3a1"):
        self.value.setText(str(val))
        self.value.setStyleSheet(f"color: {color};")


# ===================================================================
# === WIDGET: Main Network Guardian App (Full Feature)
# ===================================================================
class GuardianApp(QWidget): 
    status_message = pyqtSignal(str, int)
    back_pressed = pyqtSignal()
    
    def __init__(self):
        super().__init__()
        
        main_layout = QVBoxLayout(self)
        
        header = self.create_header()
        main_layout.addWidget(header)
        
        stats_row = self.create_stats_row()
        main_layout.addLayout(stats_row)
        
        controls = self.create_control_panel()
        main_layout.addWidget(controls)
        
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(6)
        self.device_table.setHorizontalHeaderLabels([
            "IP Address", "MAC Address", "Hostname", "Vendor", "Threat Level", "Last Seen"
        ])
        self.device_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.device_table.setAlternatingRowColors(True)
        self.device_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.device_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        self.alerts_text = QTextEdit()
        self.alerts_text.setReadOnly(True)

        self.traffic_canvas = ModernTrafficCanvas()

        self.network_info = QTextEdit()
        self.network_info.setReadOnly(True)
        self.network_info.setMaximumHeight(150)
        
        self.device_pop_window = QMainWindow(self, Qt.Window)
        self.alert_pop_window = QMainWindow(self, Qt.Window)
        self.graph_pop_window = QMainWindow(self, Qt.Window)
        
        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_devices_tab(), "🖥 Devices")
        self.tabs.addTab(self.create_monitoring_tab(), "📊 Monitoring")
        self.tabs.addTab(self.create_alerts_tab(), "⚠ Alerts")
        main_layout.addWidget(self.tabs)
        
        self.devices = {}
        self.packet_queue = queue.Queue()
        self.sniffer = None
        self.detector = None
        self.sniffing = False
        self.alert_count = 0
        self.high_threat_count = 0
        self.watching = True 
        
        self.stats_timer = QTimer(self)
        self.stats_timer.timeout.connect(self.update_stats)
        self.stats_timer.start(1000)
        
        self.watcher = start_watchdog(WATCH_DIRECTORIES, self.on_alert)
        self.update_network_info()
    
    def create_header(self):
        header = QFrame()
        header.setStyleSheet("background-color: #313244; border-radius: 10px; padding: 10px 15px;")
        layout = QHBoxLayout()
        header.setLayout(layout)
        
        self.back_btn = QPushButton("« BACK")
        self.back_btn.setObjectName("back")
        self.back_btn.clicked.connect(self.go_back)
        layout.addWidget(self.back_btn)
        layout.addSpacing(20)
        
        title = QLabel("🛡 Full Network Guardian")
        title.setObjectName("header")
        title.setStyleSheet("font-size: 16pt; color: #89b4fa;")
        layout.addWidget(title)
        
        layout.addStretch()
        
        self.status_label = QLabel("● Online")
        self.status_on_color = "#a6e3a1" 
        self.status_label.setStyleSheet(f"font-size: 11pt; font-weight: bold; color: {self.status_on_color};")
        layout.addWidget(self.status_label)
        
        return header
    
    def create_stats_row(self):
        layout = QHBoxLayout()
        layout.setSpacing(15)
        
        self.device_card = StatCard("Total Devices")
        self.threat_card = StatCard("High Threats")
        self.alert_card = StatCard("Active Alerts")
        self.traffic_card = StatCard("Packets/sec")
        
        self.threat_card.set_value(0, "#f38ba8")
        self.alert_card.set_value(0, "#fab387")
        self.traffic_card.set_value(0, "#89b4fa")
        
        layout.addWidget(self.device_card)
        layout.addWidget(self.threat_card)
        layout.addWidget(self.alert_card)
        layout.addWidget(self.traffic_card)
        
        return layout
    
    def create_control_panel(self):
        group = QGroupBox("Control Panel")
        layout = QHBoxLayout()
        group.setLayout(layout)
        
        self.scan_btn = QPushButton("🔍 SCAN NETWORK")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.clicked.connect(self.scan_network)
        
        self.sniff_btn = QPushButton("▶ START MONITOR")
        self.sniff_btn.setObjectName("success")
        self.sniff_btn.clicked.connect(self.toggle_sniff)
        
        self.export_btn = QPushButton("💾 EXPORT DATA")
        self.export_btn.clicked.connect(self.export_alerts)
        
        self.clear_btn = QPushButton("🗑 CLEAR ALERTS")
        self.clear_btn.setObjectName("danger")
        self.clear_btn.clicked.connect(self.clear_alerts)
        
        self.watch_btn = QPushButton("⏸ DISABLE FILE WATCH")
        self.watch_btn.setObjectName("danger")
        self.watch_btn.clicked.connect(self.toggle_watchdog)

        self.select_folder_btn = QPushButton("📁 SELECT FOLDER")
        self.select_folder_btn.clicked.connect(self.select_watch_folders)
        
        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        self.scan_progress.setTextVisible(True)
        
        layout.addWidget(self.scan_btn)
        layout.addWidget(self.sniff_btn)
        layout.addSpacing(20)
        layout.addWidget(self.watch_btn)
        layout.addWidget(self.select_folder_btn)
        layout.addSpacing(20)
        layout.addWidget(self.export_btn)
        layout.addWidget(self.clear_btn)
        layout.addStretch()
        layout.addWidget(self.scan_progress)
        
        return group
    
    def create_devices_tab(self):
        widget = QWidget()
        self.devices_tab_layout = QVBoxLayout(widget)
        
        btn_layout = QHBoxLayout()
        self.pop_out_devices_btn = QPushButton("POP OUT ⇱")
        self.pop_out_devices_btn.setObjectName("pop_out")
        self.pop_out_devices_btn.clicked.connect(self.pop_out_devices)
        btn_layout.addStretch()
        btn_layout.addWidget(self.pop_out_devices_btn)
        
        self.devices_tab_layout.addLayout(btn_layout)
        self.devices_tab_layout.addWidget(self.device_table)
        
        return widget
    
    def create_monitoring_tab(self):
        widget = QWidget()
        self.monitoring_tab_layout = QVBoxLayout(widget)
        
        graph_group = QGroupBox("Live Traffic")
        self.graph_group_layout = QVBoxLayout()
        
        btn_layout = QHBoxLayout()
        self.pop_out_graph_btn = QPushButton("POP OUT ⇱")
        self.pop_out_graph_btn.setObjectName("pop_out")
        self.pop_out_graph_btn.clicked.connect(self.pop_out_graph)
        btn_layout.addStretch()
        btn_layout.addWidget(self.pop_out_graph_btn)
        
        self.graph_group_layout.addLayout(btn_layout)
        self.graph_group_layout.addWidget(self.traffic_canvas)
        graph_group.setLayout(self.graph_group_layout)
        
        info_group = QGroupBox("System Information")
        info_layout = QVBoxLayout()
        info_group.setLayout(info_layout)
        info_layout.addWidget(self.network_info)
        
        self.monitoring_tab_layout.addWidget(graph_group)
        self.monitoring_tab_layout.addWidget(info_group)
        
        return widget
    
    def create_alerts_tab(self):
        widget = QWidget()
        self.alerts_tab_layout = QVBoxLayout(widget)
        
        btn_layout = QHBoxLayout()
        self.pop_out_alerts_btn = QPushButton("POP OUT ⇱")
        self.pop_out_alerts_btn.setObjectName("pop_out")
        self.pop_out_alerts_btn.clicked.connect(self.pop_out_alerts)
        btn_layout.addStretch()
        btn_layout.addWidget(self.pop_out_alerts_btn)
        
        self.alerts_tab_layout.addLayout(btn_layout)
        self.alerts_tab_layout.addWidget(self.alerts_text)
        
        return widget

    def pop_out_devices(self):
        self.pop_out_devices_btn.setEnabled(False)
        widget = self.device_table
        self.devices_tab_layout.removeWidget(widget)
        
        self.device_pop_window.setCentralWidget(widget)
        self.device_pop_window.setWindowTitle("Devices - Smart Network Guardian")
        self.device_pop_window.setGeometry(150, 150, 1000, 600)
        self.device_pop_window.closeEvent = self.pop_in_devices
        self.device_pop_window.show()

    def pop_in_devices(self, event):
        widget = self.device_pop_window.takeCentralWidget()
        self.devices_tab_layout.addWidget(widget)
        self.pop_out_devices_btn.setEnabled(True)
        event.accept()

    def pop_out_alerts(self):
        self.pop_out_alerts_btn.setEnabled(False)
        widget = self.alerts_text
        self.alerts_tab_layout.removeWidget(widget)
        
        self.alert_pop_window.setCentralWidget(widget)
        self.alert_pop_window.setWindowTitle("Alerts - Smart Network Guardian")
        self.alert_pop_window.setGeometry(160, 160, 800, 600)
        self.alert_pop_window.closeEvent = self.pop_in_alerts
        self.alert_pop_window.show()

    def pop_in_alerts(self, event):
        widget = self.alert_pop_window.takeCentralWidget()
        self.alerts_tab_layout.addWidget(widget)
        self.pop_out_alerts_btn.setEnabled(True)
        event.accept()

    def pop_out_graph(self):
        self.pop_out_graph_btn.setEnabled(False)
        widget = self.traffic_canvas
        self.graph_group_layout.removeWidget(widget)
        
        self.graph_pop_window.setCentralWidget(widget)
        self.graph_pop_window.setWindowTitle("Live Traffic - Smart Network Guardian")
        self.graph_pop_window.setGeometry(170, 170, 800, 500)
        self.graph_pop_window.closeEvent = self.pop_in_graph
        self.graph_pop_window.show()

    def pop_in_graph(self, event):
        widget = self.graph_pop_window.takeCentralWidget()
        self.graph_group_layout.addWidget(widget) 
        self.pop_out_graph_btn.setEnabled(True)
        event.accept()

    def update_network_info(self):
        try:
            local_ip = get_if_addr(conf.iface)
            iface = conf.iface
            
            watch_status = "Active" if self.watching else "Disabled"
            watch_color = "#a6e3a1" if self.watching else "#f38ba8"
            
            info = f"""
<div style='color: #cdd6f4; font-family: Consolas;'>
<b style='color: #89b4fa;'>Network Interface :</b> {iface}<br>
<b style='color: #89b4fa;'>Local IP          :</b> {local_ip}<br>
<b style='color: #89b4fa;'>Network Monitor   :</b> {"Active" if self.sniffing else "Inactive"}<br>
<b style='color: #89b4fa;'>File Watch Status :</b> <span style='color: {watch_color};'>{watch_status}</span><br>
<b style='color: #89b4fa;'>Protected Folders :</b> {len(WATCH_DIRECTORIES)}
</div>
"""
            self.network_info.setHtml(info)
        except Exception as e:
            self.network_info.setPlainText(f"Error getting network info: {e}")
    
    def scan_network(self):
        self.scan_btn.setEnabled(False)
        self.scan_progress.setVisible(True)
        self.scan_progress.setValue(0)
        self.status_message.emit("Scanning network...", 0)
        threading.Thread(target=self._scan_thread, daemon=True).start()
    
    def _scan_thread(self):
        devices = []
        try:
            self.scan_progress.setValue(20)
            devices = arp_scan()
            if len(devices) == 0:
                print("[!] No devices found. Check network interface and permissions.")
            total = len(devices) if devices else 1
            for idx, d in enumerate(devices):
                details = {}
                if HAS_NMAP:
                    try:
                        details = nmap_scan_host(d['ip'])
                    except Exception as e:
                        print(f"[!] Nmap scan failed for {d['ip']}: {e}")
                dinfo = {
                    'ip': d['ip'],
                    'mac': d['mac'],
                    'hostname': resolve_hostname(d['ip']),
                    'vendor': get_vendor(d['mac']),
                    'details': details
                }
                tstats = {'spike': False}
                t = compute_threat_score({'ip': d['ip'], 'details': details}, tstats)
                dinfo['threat'] = t
                self.devices[d['ip']] = dinfo
                log_device(dinfo)
                progress = 20 + int((idx + 1) / total * 80)
                self.scan_progress.setValue(progress)
        except Exception as e:
            print(f"[!] ARP scan failed: {e}")
            import traceback
            traceback.print_exc()
        QtCore.QMetaObject.invokeMethod(self, "refresh_device_table", QtCore.Qt.QueuedConnection)
        QtCore.QMetaObject.invokeMethod(self, "scan_complete", QtCore.Qt.QueuedConnection)
    
    @QtCore.pyqtSlot()
    def scan_complete(self):
        self.scan_btn.setEnabled(True)
        self.scan_progress.setVisible(False)
        msg = f"Scan complete - {len(self.devices)} devices found"
        print(f"[+] {msg}")
        self.status_message.emit(msg, 5000)
    
    @QtCore.pyqtSlot()
    def refresh_device_table(self):
        self.device_table.setRowCount(0)
        high_threats = 0
        for ip, d in sorted(self.devices.items()):
            r = self.device_table.rowCount()
            self.device_table.insertRow(r)
            self.device_table.setItem(r, 0, QTableWidgetItem(ip))
            self.device_table.setItem(r, 1, QTableWidgetItem(d.get('mac', '')))
            self.device_table.setItem(r, 2, QTableWidgetItem(d.get('hostname', 'Unknown')))
            self.device_table.setItem(r, 3, QTableWidgetItem(d.get('vendor', 'Unknown')))
            threat = d.get('threat', 'Unknown')
            threat_item = QTableWidgetItem(threat)
            if threat == "High":
                threat_item.setForeground(QColor("#f38ba8"))
                threat_item.setBackground(QColor("#3d2832"))
                high_threats += 1
            elif threat == "Medium":
                threat_item.setForeground(QColor("#fab387"))
                threat_item.setBackground(QColor("#3d3328"))
            else:
                threat_item.setForeground(QColor("#a6e3a1"))
                threat_item.setBackground(QColor("#283d32"))
            threat_item.setFont(QFont("Segoe UI", 10, QFont.Bold))
            self.device_table.setItem(r, 4, threat_item)
            self.device_table.setItem(r, 5, QTableWidgetItem(datetime.now().strftime("%H:%M:%S")))
        self.device_table.resizeColumnsToContents()
        self.device_card.set_value(len(self.devices))
        self.threat_card.set_value(high_threats, "#f38ba8")
        self.high_threat_count = high_threats
    
    def toggle_sniff(self):
        if not self.sniffing:
            self.start_sniff()
            self.sniff_btn.setText("⏸ STOP MONITOR")
            self.sniff_btn.setObjectName("danger")
            self.sniff_btn.setStyleSheet(DARK_THEME) 
            self.status_message.emit("Network monitoring active", 0)
        else:
            self.stop_sniff()
            self.sniff_btn.setText("▶ START MONITOR")
            self.sniff_btn.setObjectName("success")
            self.sniff_btn.setStyleSheet(DARK_THEME) 
            self.status_message.emit("Network monitoring stopped", 5000)
        self.update_network_info()
    
    def start_sniff(self):
        self.sniffer = SnifferThread(self.packet_queue, mode='network')
        self.detector = AnomalyDetector(self.packet_queue, alert_callback=self.on_alert)
        self.sniffer.start()
        self.detector.start()
        self.sniffing = True
    
    def stop_sniff(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
        if self.detector:
            self.detector.stop()
            self.detector = None
        self.sniffing = False

    def toggle_watchdog(self):
        if self.watching:
            try:
                if self.watcher:
                    self.watcher.stop()
                    self.watcher.join(1)
                    self.watcher = None
                self.status_message.emit("File monitoring disabled.", 3000)
            except Exception as e:
                print("Error stopping watchdog:", e)
            self.watch_btn.setText("▶ ENABLE FILE WATCH")
            self.watch_btn.setObjectName("success")
            self.watch_btn.setStyleSheet(DARK_THEME)
            self.watching = False
        else:
            try:
                self.watcher = start_watchdog(WATCH_DIRECTORIES, self.on_alert)
                self.status_message.emit(f"File monitoring enabled for {len(WATCH_DIRECTORIES)} folder(s).", 3000)
            except Exception as e:
                print("Error starting watchdog:", e)
            self.watch_btn.setText("⏸ DISABLE FILE WATCH")
            self.watch_btn.setObjectName("danger")
            self.watch_btn.setStyleSheet(DARK_THEME)
            self.watching = True
        
        self.update_network_info()

    def select_watch_folders(self):
        global WATCH_DIRECTORIES
        dir_path = QFileDialog.getExistingDirectory(self, "Select a Folder to Monitor")
        
        if dir_path:
            WATCH_DIRECTORIES = [dir_path]
            
            if self.watching and self.watcher:
                self.watcher.stop()
                self.watcher.join(1)
                self.watcher = start_watchdog(WATCH_DIRECTORIES, self.on_alert)
            
            self.status_message.emit(f"Updated monitoring folder to: {dir_path}", 5000)
            self.update_network_info()
    
    def on_alert(self, level, src, dst, msg):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        color_map = {"High": "#f38ba8", "Medium": "#fab387", "Low": "#a6e3a1"}
        color = color_map.get(level, "#cdd6f4")
        html_line = f"""
        <div style='margin: 8px 0; padding: 10px; background-color: #313244; border-radius: 8px; border-left: 4px solid {color};'>
            <span style='color: {color}; font-weight: bold;'>[{level.upper()}]</span>
            <span style='color: #6c7086;'> {ts}</span><br>
            <span style='color: #cdd6f4;'><b>SRC:</b> {src or 'N/A'} | <b>DST:</b> {dst or 'N/A'}</span><br>
            <span style='color: #a6adc8;'>&gt; {msg}</span>
        </div>
        """
        QtCore.QMetaObject.invokeMethod(self.alerts_text, "insertHtml", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, html_line))
        QtCore.QMetaObject.invokeMethod(self.alerts_text.verticalScrollBar(), "setValue", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(int, self.alerts_text.verticalScrollBar().maximum()))
        log_alert(level, src or "", dst or "", msg)
        self.alert_count += 1
        self.alert_card.set_value(self.alert_count, "#fab387")
        if level == "High":
            self.status_message.emit(f"⚠ HIGH THREAT DETECTED: {msg}", 10000)
    
    def clear_alerts(self):
        reply = QtWidgets.QMessageBox.question(self, 'Clear Alerts', 'Are you sure...?', QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No)
        if reply == QtWidgets.QMessageBox.Yes:
            self.alerts_text.clear()
            self.alert_count = 0
            self.alert_card.set_value(0, "#fab387")
            self.status_message.emit("Alerts cleared", 3000)
    
    def update_stats(self):
        pps = 0
        if hasattr(self, 'detector') and self.detector:
            pps = len(getattr(self.detector, 'pkt_history', []))
        
        self.traffic_canvas.update_plot(pps)
        self.traffic_card.set_value(pps, "#89b4fa")
    
    def export_alerts(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Alerts", "alerts.csv", "CSV Files (*.csv)")
        if path:
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                rows = c.execute("SELECT ts,level,src,dst,msg FROM alerts ORDER BY ts DESC").fetchall()
                conn.close()
                with open(path, "w", encoding="utf-8") as f:
                    f.write("Timestamp,Level,Source,Destination,Message\n")
                    for r in rows:
                        f.write(','.join('"%s"' % str(x).replace('"', '""') for x in r) + "\n")
                QtWidgets.QMessageBox.information(self, "Export Successful", f"Exported {len(rows)} alerts to:\n{path}")
                self.status_message.emit(f"Exported {len(rows)} alerts", 5000)
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Export Failed", f"Failed to export alerts:\n{str(e)}")
    
    def go_back(self):
        self.stop_sniff()
        self.sniff_btn.setText("▶ START MONITOR")
        self.sniff_btn.setObjectName("success")
        self.sniff_btn.setStyleSheet(DARK_THEME)
        self.back_pressed.emit()

    def shutdown(self):
        print("[!] Shutting down all 'GuardianApp' threads...")
        self.stop_sniff()
        if self.watcher:
            self.watcher.stop()
            self.watcher.join(1)
            self.watcher = None
        print("[!] 'GuardianApp' shutdown complete.")

# ===================================================================
# === WIDGET: Application-Specific Monitor (MODIFIED)
# ===================================================================
class AppMonitorWidget(QWidget):
    status_message = pyqtSignal(str, int)
    back_pressed = pyqtSignal()
    
    def __init__(self):
        super().__init__()
        
        main_layout = QVBoxLayout(self)
        
        # --- Top Control Bar ---
        control_layout = QHBoxLayout()
        self.back_btn = QPushButton("« BACK")
        self.back_btn.setObjectName("back")
        self.back_btn.clicked.connect(self.go_back)
        
        title = QLabel("🛡 Application Monitor")
        title.setObjectName("header")
        title.setStyleSheet("font-size: 16pt; color: #89b4fa; padding-left: 20px;")
        
        control_layout.addWidget(self.back_btn)
        control_layout.addWidget(title)
        control_layout.addStretch()
        
        main_layout.addLayout(control_layout)

        # --- Main Content ---
        content_layout = QHBoxLayout()
        main_layout.addLayout(content_layout)

        # --- Left Panel (Controls) ---
        left_panel = QVBoxLayout()
        left_panel.setSpacing(15)
        
        control_group = QGroupBox("Monitor Control")
        control_group_layout = QVBoxLayout(control_group)
        
        app_label = QLabel("Select Application to Monitor:")
        self.app_combo = QComboBox()
        self.app_combo.setPlaceholderText("Click 'Refresh List' to populate")
        
        self.refresh_btn = QPushButton("🔄 REFRESH LIST")
        self.refresh_btn.setObjectName("primary")
        self.refresh_btn.clicked.connect(self.populate_app_list)
        
        self.monitor_btn = QPushButton("▶ START MONITOR")
        self.monitor_btn.setObjectName("success")
        self.monitor_btn.clicked.connect(self.toggle_monitor)
        
        # === NEW BUTTONS ===
        self.clear_btn = QPushButton("🗑 CLEAR ALERTS")
        self.clear_btn.setObjectName("danger")
        self.clear_btn.clicked.connect(self.clear_alerts)

        self.export_btn = QPushButton("💾 EXPORT DATA")
        self.export_btn.clicked.connect(self.export_alerts)
        # ===================

        control_group_layout.addWidget(app_label)
        control_group_layout.addWidget(self.app_combo)
        control_group_layout.addWidget(self.refresh_btn)
        control_group_layout.addSpacing(20)
        control_group_layout.addWidget(self.monitor_btn)
        control_group_layout.addSpacing(20) # Spacer
        control_group_layout.addWidget(self.clear_btn)
        control_group_layout.addWidget(self.export_btn)
        
        left_panel.addWidget(control_group)
        left_panel.addStretch()
        
        # --- Right Panel (Graph & Alerts) ---
        right_panel = QVBoxLayout()
        
        self.traffic_canvas = ModernTrafficCanvas()
        self.alerts_text = QTextEdit()
        self.alerts_text.setReadOnly(True)

        right_panel.addWidget(self.traffic_canvas, 1) 
        right_panel.addWidget(self.alerts_text, 1)   

        content_layout.addLayout(left_panel, 1)   
        content_layout.addLayout(right_panel, 2)  
        
        # --- Internal State ---
        self.packet_queue = queue.Queue()
        self.target_ports = set() 
        self.monitoring = False
        
        self.sniffer = None
        self.detector = None
        self.port_monitor_thread = None
        
        self.stats_timer = QTimer(self)
        self.stats_timer.timeout.connect(self.update_stats)

    def populate_app_list(self):
        self.status_message.emit("Scanning for running applications...", 0)
        self.app_combo.clear()
        app_names = set()
        try:
            for proc in psutil.process_iter(['name']):
                try:
                    app_names.add(proc.info['name'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"[!] Error populating app list: {e}")
            
        sorted_apps = sorted(list(app_names), key=str.lower)
        self.app_combo.addItems(sorted_apps)
        self.status_message.emit(f"Found {len(sorted_apps)} running applications.", 3000)

    def toggle_monitor(self):
        if not self.monitoring:
            if self.app_combo.count() == 0 or not self.app_combo.currentText():
                self.status_message.emit("Please refresh list and select an application first.", 3000)
                return
            
            app_name = self.app_combo.currentText()
            self.start_all_threads(app_name)
            
            self.monitor_btn.setText("⏸ STOP MONITOR")
            self.monitor_btn.setObjectName("danger")
            self.monitor_btn.setStyleSheet(DARK_THEME)
            self.app_combo.setEnabled(False)
            self.refresh_btn.setEnabled(False)
            self.status_message.emit(f"Monitoring application: {app_name}", 0)
        else:
            self.stop_all_threads()
            self.monitor_btn.setText("▶ START MONITOR")
            self.monitor_btn.setObjectName("success")
            self.monitor_btn.setStyleSheet(DARK_THEME)
            self.app_combo.setEnabled(True)
            self.refresh_btn.setEnabled(True)
            self.status_message.emit("Application monitoring stopped.", 3000)
            
    def start_all_threads(self, app_name):
        self.packet_queue = queue.Queue()
        self.target_ports.clear()
        
        self.port_monitor_thread = PortMonitorThread(app_name, self.target_ports)
        self.sniffer = SnifferThread(self.packet_queue, mode='application', target_ports_set=self.target_ports)
        self.detector = AnomalyDetector(self.packet_queue, alert_callback=self.on_alert)
        
        self.port_monitor_thread.start()
        self.sniffer.start()
        self.detector.start()
        self.stats_timer.start(1000)
        self.monitoring = True

    def stop_all_threads(self):
        if self.port_monitor_thread:
            self.port_monitor_thread.stop()
            self.port_monitor_thread = None
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
        if self.detector:
            self.detector.stop()
            self.detector = None
        
        self.stats_timer.stop()
        self.monitoring = False

    def on_alert(self, level, src, dst, msg):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        color_map = {"High": "#f38ba8", "Medium": "#fab387", "Low": "#a6e3a1"}
        color = color_map.get(level, "#cdd6f4")
        html_line = f"""
        <div style='margin: 8px 0; padding: 10px; background-color: #313244; border-radius: 8px; border-left: 4px solid {color};'>
            <span style='color: {color}; font-weight: bold;'>[{level.upper()}]</span>
            <span style='color: #6c7086;'> {ts}</span><br>
            <span style='color: #cdd6f4;'><b>SRC:</b> {src or 'N/A'} | <b>DST:</b> {dst or 'N/A'}</span><br>
            <span style='color: #a6adc8;'>&gt; {msg}</span>
        </div>
        """
        QtCore.QMetaObject.invokeMethod(self.alerts_text, "insertHtml", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, html_line))
        QtCore.QMetaObject.invokeMethod(self.alerts_text.verticalScrollBar(), "setValue", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(int, self.alerts_text.verticalScrollBar().maximum()))
        
        # Log to database
        log_alert(level, src or "", dst or "", msg)

        if level == "High":
            self.status_message.emit(f"⚠ HIGH THREAT (from {self.app_combo.currentText()}): {msg}", 10000)

    # === NEW METHOD ===
    def clear_alerts(self):
        reply = QtWidgets.QMessageBox.question(
            self, 'Clear Alerts',
            'Are you sure you want to clear all alerts from this display?',
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No
        )
        
        if reply == QtWidgets.QMessageBox.Yes:
            self.alerts_text.clear()
            self.status_message.emit("Alerts cleared", 3000)

    # === NEW METHOD ===
    def export_alerts(self):
        # This exports ALL alerts from the main DB, including from the
        # full network monitor. This is consistent with the other export button.
        path, _ = QFileDialog.getSaveFileName(
            self, "Export All Alerts", "sng_all_alerts.csv", "CSV Files (*.csv)"
        )
        if path:
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                rows = c.execute(
                    "SELECT ts,level,src,dst,msg FROM alerts ORDER BY ts DESC"
                ).fetchall()
                conn.close()
                
                with open(path, "w", encoding="utf-8") as f:
                    f.write("Timestamp,Level,Source,Destination,Message\n")
                    for r in rows:
                        f.write(','.join('"%s"' % str(x).replace('"', '""') for x in r) + "\n")
                
                QtWidgets.QMessageBox.information(
                    self, "Export Successful",
                    f"Exported {len(rows)} alerts to:\n{path}"
                )
                self.status_message.emit(f"Exported {len(rows)} alerts", 5000)
            except Exception as e:
                QtWidgets.QMessageBox.critical(
                    self, "Export Failed",
                    f"Failed to export alerts:\n{str(e)}"
                )

    def update_stats(self):
        pps = 0
        if hasattr(self, 'detector') and self.detector:
            pps = len(getattr(self.detector, 'pkt_history', []))
        self.traffic_canvas.update_plot(pps)

    def go_back(self):
        self.stop_all_threads()
        self.back_pressed.emit()
    
    def shutdown(self):
        print("[!] Shutting down all 'AppMonitorWidget' threads...")
        self.stop_all_threads()
        print("[!] 'AppMonitorWidget' shutdown complete.")

# ===================================================================
# === WIDGET: Main Menu Screen
# ===================================================================
class MainMenuWidget(QWidget):
    start_pressed = pyqtSignal()
    app_monitor_pressed = pyqtSignal()
    how_to_use_pressed = pyqtSignal()
    properties_pressed = pyqtSignal()
    about_pressed = pyqtSignal()

    def __init__(self):
        super().__init__()
        
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(20)
        
        title = QLabel("🛡\nSmart Network Guardian")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Consolas", 32, QFont.Bold))
        title.setStyleSheet("color: #89b4fa; padding-bottom: 30px;")
        
        self.start_btn = QPushButton("START FULL NETWORK MONITOR")
        self.start_btn.setObjectName("primary")
        self.start_btn.setProperty("class", "menu")
        self.start_btn.clicked.connect(self.start_pressed.emit)
        
        self.app_monitor_btn = QPushButton("MONITOR SELECTED APPLICATION")
        self.app_monitor_btn.setObjectName("menu")
        self.app_monitor_btn.clicked.connect(self.app_monitor_pressed.emit)

        self.how_to_use_btn = QPushButton("HOW TO USE")
        self.how_to_use_btn.setObjectName("menu")
        self.how_to_use_btn.clicked.connect(self.how_to_use_pressed.emit)
        
        self.properties_btn = QPushButton("PROPERTIES")
        self.properties_btn.setObjectName("menu")
        self.properties_btn.clicked.connect(self.properties_pressed.emit)

        self.about_btn = QPushButton("ABOUT US")
        self.about_btn.setObjectName("menu")
        self.about_btn.clicked.connect(self.about_pressed.emit)

        layout.addWidget(title)
        layout.addWidget(self.start_btn)
        layout.addWidget(self.app_monitor_btn)
        layout.addWidget(self.how_to_use_btn)
        layout.addWidget(self.properties_btn)
        layout.addWidget(self.about_btn)

# ===================================================================
# === WIDGET: A generic content page template
# ===================================================================
class ContentPageWidget(QWidget):
    back_pressed = pyqtSignal()
    
    def __init__(self, title_text, content_html):
        super().__init__()
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        top_layout = QHBoxLayout()
        self.back_btn = QPushButton("« BACK")
        self.back_btn.setObjectName("back")
        self.back_btn.clicked.connect(self.back_pressed.emit)
        top_layout.addWidget(self.back_btn)
        top_layout.addStretch()
        
        content_layout = QVBoxLayout()
        content_layout.setAlignment(Qt.AlignTop)
        content_layout.setContentsMargins(40, 20, 40, 40)
        
        title_label = QLabel(title_text)
        title_label.setObjectName("title")
        title_label.setWordWrap(True)
        
        content_label = QLabel(content_html)
        content_label.setObjectName("content")
        content_label.setWordWrap(True)
        content_label.setOpenExternalLinks(True)
        content_label.setTextFormat(Qt.RichText)

        content_layout.addWidget(title_label)
        content_layout.addWidget(content_label)
        
        content_frame = QFrame()
        content_frame.setObjectName("content_frame")
        content_frame.setLayout(content_layout)
        
        main_layout.addLayout(top_layout)
        main_layout.addWidget(content_frame)
        main_layout.addStretch()

# ===================================================================
# === WIDGET: The Main Application Container
# ===================================================================
class AppContainer(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Smart Network Guardian")
        self.setGeometry(100, 100, 1400, 800)
        self.setStyleSheet(DARK_THEME)
        
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)
        
        self.main_menu = MainMenuWidget()
        self.guardian_app = GuardianApp()
        self.app_monitor_widget = AppMonitorWidget()
        
        # --- Define Content for Pages ---
        about_content = """
        <p><b>Smart Network Guardian (SNG)</b> is a prototype security tool built with Python and PyQt5.</p>
        <p>Its purpose is to provide a simple, all-in-one dashboard for monitoring local network activity and file system changes, helping to identify suspicious behavior in real-time.</p>
        <br/>
        <p><b>Core Features:</b></p>
        <ul>
            <li><b>Full Network Monitoring:</b> Uses ARP scans and packet sniffing to find and monitor all devices on your network.</li>
            <li><b>Application Monitoring:</b> Uses <b>psutil</b> to find and monitor the specific network traffic of a single application.</li>
            <li><b>File Integrity Monitoring:</b> Watches key folders for mass-modification events, a common sign of ransomware.</li>
            <li><b>Threat Scoring:</b> A simple heuristic to flag devices with many open ports or suspicious services.</li>
        </ul>
        <br/>
        <p><i><b>Disclaimer:</b> This is an educational prototype and not a replacement for a professional firewall or antivirus solution.</i></p>
        """
        
        how_to_use_content = """
        <p>Running this application requires <b>administrator privileges</b> to capture network packets.</p>
        <br/>
        <p><b>Mode 1: Full Network Monitor</b> (Main "Start Using" page)</p>
        <ol>
            <li><b>Scan Network:</b> Click <b>'SCAN NETWORK'</b> to find all devices on your local network.</li>
            <li><b>Start Monitor:</b> Click <b>'START MONITOR'</b> to begin monitoring all network traffic and file system changes.</li>
            <li><b>Review Alerts:</b> Any suspicious activity (network-wide spikes, mass file changes) will appear in the <b>'Alerts'</b> tab.</li>
        </ol>
        <br/>
        <p><b>Mode 2: Application Monitor</b></p>
        <ol>
            <li><b>Refresh List:</b> Click <b>'REFRESH LIST'</b> to find all currently running applications.</li>
            <li><b>Select App:</b> Choose an application (e.g., 'chrome.exe') from the dropdown menu.</li>
            <li><b>Start Monitor:</b> Click <b>'START MONITOR'</b> to begin monitoring *only* the network traffic from that specific app.</li>
            <li><b>Review Alerts:</b> Any suspicious spikes *from that app* will appear in the log.</li>
        </ol>
        """

        properties_content = f"""
        <p>This application runs on Python and relies on several key open-source libraries.</p>
        <br/>
        <p><b>Core Dependencies:</b></p>
        <ul>
            <li><b>Python:</b> 3.x</li>
            <li><b>PyQt5:</b> For the graphical user interface.</li>
            <li><b>Scapy:</b> For packet sniffing and ARP scans.</li>
            <li><b>psutil:</b> For process and application-port monitoring.</li>
            <li><b>watchdog:</b> For file system monitoring.</li>
            <li><b>matplotlib:</b> For the live traffic graph.</li>
            <li><b>python-nmap (Optional):</b> For detailed port scanning.</li>
            <li><b>mac-vendor-lookup:</b> For identifying device manufacturers.</li>
        </ul>
        <br/>
        <p><b>Database:</b></a
        <p>All alerts and device information are logged to a local SQLite database file named <b>{DB_PATH}</b>, located in the same directory as the script.</p>
        """

        self.about_page = ContentPageWidget("About Us", about_content)
        self.how_to_use_page = ContentPageWidget("How to Use", how_to_use_content)
        self.properties_page = ContentPageWidget("Properties", properties_content)

        self.stack.addWidget(self.main_menu)         # Index 0
        self.stack.addWidget(self.guardian_app)      # Index 1
        self.stack.addWidget(self.about_page)        # Index 2
        self.stack.addWidget(self.how_to_use_page)   # Index 3
        self.stack.addWidget(self.properties_page)   # Index 4
        self.stack.addWidget(self.app_monitor_widget)# Index 5

        # --- Connect Signals ---
        
        self.main_menu.start_pressed.connect(lambda: self.stack.setCurrentIndex(1))
        self.main_menu.app_monitor_pressed.connect(self.start_app_monitor)
        self.main_menu.about_pressed.connect(lambda: self.stack.setCurrentIndex(2))
        self.main_menu.how_to_use_pressed.connect(lambda: self.stack.setCurrentIndex(3))
        self.main_menu.properties_pressed.connect(lambda: self.stack.setCurrentIndex(4))
        
        self.guardian_app.back_pressed.connect(self.go_to_menu)
        self.app_monitor_widget.back_pressed.connect(self.go_to_menu)
        self.about_page.back_pressed.connect(self.go_to_menu)
        self.how_to_use_page.back_pressed.connect(self.go_to_menu)
        self.properties_page.back_pressed.connect(self.go_to_menu)

        self.guardian_app.status_message.connect(self.update_status_bar)
        self.app_monitor_widget.status_message.connect(self.update_status_bar)

        self.statusBar().setStyleSheet("background-color: #181825; color: #cdd6f4;")
        self.update_status_bar("Ready", 5000)

    def go_to_menu(self):
        self.stack.setCurrentIndex(0)
        self.update_status_bar("Ready", 5000)

    def start_app_monitor(self):
        self.app_monitor_widget.populate_app_list()
        self.stack.setCurrentIndex(5)
        self.update_status_bar("Select an application to monitor.", 0)

    def update_status_bar(self, msg, timeout):
        self.statusBar().showMessage(msg, timeout)

    def closeEvent(self, event):
        reply = QtWidgets.QMessageBox.question(
            self, 'Exit Smart Network Guardian',
            'Are you sure you want to exit?\nAll monitoring will stop.',
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No
        )
        
        if reply == QtWidgets.QMessageBox.Yes:
            self.guardian_app.shutdown()
            self.app_monitor_widget.shutdown()
            event.accept()
        else:
            event.ignore()

# =========================
# Main Entry Point
# =========================
def main():
    init_db()
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    win = AppContainer()
    win.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()