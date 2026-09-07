import socket
import platform
import subprocess
from scapy.all import ARP, Ether, srp, conf, get_if_addr
from mac_vendor_lookup import MacLookup

try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False

mac_lookup = MacLookup()
try:
    mac_lookup.update_vendors()
except Exception as e:
    print(f"[!] Could not update MAC vendor database: {e}")

IP_BLACKLIST = {"10.138.235.196"}

def arp_scan(timeout=2, iface=None):
    try:
        current_iface = iface or conf.iface
        local_ip = get_if_addr(current_iface)
        parts = local_ip.split('.')
        net = '.'.join(parts[:3]) + '.0/24'
        print(f"[+] ARP scanning {net} on interface {current_iface}")
        
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp = ARP(pdst=net)
        
        ans, unans = srp(ether/arp, timeout=timeout, verbose=0, iface=current_iface)
        
        devices = []
        for s, r in ans:
            devices.append({'ip': r.psrc, 'mac': r.hwsrc})
        return devices
    except RuntimeError as e:
        if "winpcap is not installed" in str(e).lower() or "npcap" in str(e).lower():
            print("[!] Npcap is missing. Cannot perform ARP scan.")
            return [{'ip': 'Error', 'mac': 'Missing Npcap', 'hostname': 'Install Npcap on Windows', 'vendor': 'N/A'}]
        print(f"[!] ARP scan error: {e}")
        return []
    except Exception as e:
        print(f"[!] ARP scan error: {e}")
        return []

def nmap_scan_host(ip):
    if not HAS_NMAP:
        return {}
    try:
        nm = nmap.PortScanner()
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
            output = subprocess.check_output(["nbtstat", "-A", ip], text=True, stderr=subprocess.DEVNULL)
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

def compute_threat_score(device_info, traffic_stats=None):
    if traffic_stats is None:
        traffic_stats = {}
    score = 0
    reasons = []
    
    if 'details' not in device_info:
        device_info['details'] = {}
        
    open_ports = device_info.get('details', {}).get('open_ports', [])
    if len(open_ports) >= 10:
        score += 3
        reasons.append(f"High number of open ports ({len(open_ports)})")
    elif len(open_ports) >= 3:
        score += 1
        reasons.append(f"Multiple open ports ({len(open_ports)})")
        
    suspicious = {22,23,3389,445,5900}
    found_suspicious = [p for p in open_ports if p in suspicious]
    if found_suspicious:
        score += 2
        reasons.append(f"Suspicious ports open: {found_suspicious}")
        device_info['details']['suspicious_ports'] = found_suspicious
    else:
        device_info['details']['suspicious_ports'] = []
        
    if device_info.get('ip') in IP_BLACKLIST:
        score += 4
        reasons.append("IP found in local blacklist")
        device_info['details']['is_blacklisted'] = True
    else:
        device_info['details']['is_blacklisted'] = False
        
    if traffic_stats.get('spike', False):
        score += 2
        reasons.append("Anomalous traffic spike detected")
        device_info['details']['traffic_spike'] = True
    else:
        device_info['details']['traffic_spike'] = False
        
    device_info['details']['threat_reasons'] = reasons
    
    if score >= 5:
        return "High"
    elif score >= 2:
        return "Medium"
    else:
        return "Low"
