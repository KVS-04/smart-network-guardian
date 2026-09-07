import threading
import time
import queue
from collections import deque, Counter, defaultdict
from scapy.all import sniff, conf
import psutil
from backend.database import log_alert

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
                for proc in psutil.process_iter(['name']):
                    if proc.info['name'] == self.app_name:
                        try:
                            connections = proc.connections(kind='inet')
                            for conn in connections:
                                new_ports.add(conn.laddr.port)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
            except Exception as e:
                print(f"[!] Error in PortMonitorThread: {e}")
            
            # Modify thread-safely or assume single reader/writer logic
            self.target_ports_set.clear()
            self.target_ports_set.update(new_ports)
            
            time.sleep(5)
        print(f"[*] Stopping port monitor for: {self.app_name}")

    def stop(self):
        self.running = False


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
                if per_src: 
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
