import threading
import time
import queue
from collections import deque, Counter, defaultdict
from scapy.all import sniff, conf
import psutil
from backend.database import log_alert, get_devices
from backend.config import get_config_val

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
        try:
            sniff(prn=self.handle_pkt, store=0, iface=self.iface, stop_filter=self.should_stop)
        except RuntimeError as e:
            if "winpcap is not installed" in str(e).lower() or "npcap" in str(e).lower():
                print("[!] Npcap is missing. Cannot sniff packets.")
                log_alert("High", "Local", "System", "Npcap is required on Windows for packet sniffing. Please install it.")
            else:
                print(f"[!] Sniffer crashed: {e}")
                log_alert("High", "Local", "System", f"Sniffer crashed: {e}")
            self.running.clear()
    
    def handle_pkt(self, pkt):
        if self.mode == 'application':
            if self.target_ports_set is None:
                return
            if not (pkt.haslayer('TCP') or pkt.haslayer('UDP')):
                return
            if pkt.sport not in self.target_ports_set and pkt.dport not in self.target_ports_set:
                return

        src_ip = None
        dst_ip = None
        if pkt.haslayer('IP'):
            src_ip = pkt['IP'].src
            dst_ip = pkt['IP'].dst
        elif pkt.haslayer('ARP'):
            src_ip = pkt['ARP'].psrc
            dst_ip = pkt['ARP'].pdst
        elif pkt.haslayer('IPv6'):
            src_ip = pkt['IPv6'].src
            dst_ip = pkt['IPv6'].dst
            
        sport = None
        dport = None
        if pkt.haslayer('TCP'):
            sport = pkt['TCP'].sport
            dport = pkt['TCP'].dport
        elif pkt.haslayer('UDP'):
            sport = pkt['UDP'].sport
            dport = pkt['UDP'].dport

        info = {
            'ts': time.time(),
            'src': src_ip or (pkt.src if hasattr(pkt, 'src') else 'Unknown'),
            'dst': dst_ip or (pkt.dst if hasattr(pkt, 'dst') else 'Unknown'),
            'sport': sport,
            'dport': dport,
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
            
            self.pkt_history.append(info)
            
            src = info['src']
            dst = info['dst']
            size = info['len'] or 0
            
            if src and dst:
                key = (src, dst)
                self.flow_counts[key] += 1
                if src and src.startswith(('10.', '172.', '192.')):
                    if dst and not dst.startswith(('10.', '172.', '192.')):
                        self.outbound_bytes[src] += size
            
            if len(self.pkt_history) >= 200:
                per_src = Counter()
                for pkt_info in list(self.pkt_history):
                    if pkt_info['src'] is not None:
                        per_src[pkt_info['src']] += 1
                
                if per_src: 
                    top_src, top_count = per_src.most_common(1)[0]
                    pps_thresh = get_config_val("pps_threshold")
                    if top_count > pps_thresh:
                        display_src = top_src
                        if ":" in top_src: # If it's a MAC address
                            devices = get_devices()
                            for d in devices:
                                if d.get('mac', '').lower() == top_src.lower() and d.get('ip'):
                                    display_src = f"{d.get('ip')} ({top_src})"
                                    break
                        
                        # Try to find the app responsible
                        app_name = "Unknown App"
                        local_ips = ['127.0.0.1', '0.0.0.0', '::1', '::']
                        # Add common local prefixes
                        local_ips.extend([info['src'] for info in self.pkt_history if str(info['src']).startswith(('192.168.', '10.', '172.'))])
                        local_ips = set(local_ips)
                        
                        target_ports = set()
                        for pkt_info in list(self.pkt_history):
                            if pkt_info['src'] == top_src and pkt_info['sport']:
                                target_ports.add(pkt_info['sport'])
                            elif pkt_info['dst'] == top_src and pkt_info['dport']:
                                target_ports.add(pkt_info['dport'])
                                
                        if target_ports:
                            try:
                                for conn in psutil.net_connections(kind='inet'):
                                    if conn.laddr.port in target_ports:
                                        try:
                                            proc = psutil.Process(conn.pid)
                                            app_name = proc.name()
                                            break
                                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                                            pass
                            except Exception:
                                pass
                                
                        msg = f"High rate of connections from {display_src} [App: {app_name}] ({top_count}/{len(self.pkt_history)} pkts)"
                        self.alert("High", display_src, None, msg)
                        log_alert("High", display_src, None, msg)
                        self.pkt_history.clear()
            
            for host, b in list(self.outbound_bytes.items()):
                if b > 5_000_000:
                    msg = f"Large outbound transfer from {host} (~{b} bytes)"
                    self.alert("High", host, None, msg)
                    log_alert("High", host, None, msg)
                    self.outbound_bytes[host] = 0

    def stop(self):
        self.running = False
