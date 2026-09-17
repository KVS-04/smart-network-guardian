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

IP_BLACKLIST = {"10.138.235.196", "10.214.142.196"}

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

from backend.config import get_config_val

def nmap_scan_host(ip):
    if not HAS_NMAP:
        return {}
    try:
        nmap_path = get_config_val("nmap_path")
        if nmap_path:
            nm = nmap.PortScanner(nmap_search_path=[nmap_path, 'nmap', '/usr/bin/nmap', '/usr/local/bin/nmap', '/sw/bin/nmap', '/opt/local/bin/nmap'])
        else:
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

import concurrent.futures

def _resolve_hostname_internal(ip):
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
        try:
            output = subprocess.check_output(["ping", "-a", "-n", "1", "-w", "200", ip], text=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                if line.startswith("Pinging") and "[" in line:
                    parts = line.split()
                    if len(parts) > 1 and parts[1] != ip:
                        return parts[1]
        except:
            pass
    return "Unknown"

def resolve_hostname(ip):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(_resolve_hostname_internal, ip)
        try:
            return future.result(timeout=0.5)
        except concurrent.futures.TimeoutError:
            return "Unknown"

def get_vendor(mac):
    # Check if MAC is randomized (locally administered)
    # The second character of the first octet will be 2, 6, a, A, e, or E
    if len(mac) >= 2 and mac[1] in '26aAeE':
        return "Randomized MAC"
    
    try:
        return mac_lookup.lookup(mac)
    except:
        pass
    
    try:
        # Fallback to Scapy's offline built-in MAC vendor database
        from scapy.all import conf
        manuf = conf.manufdb._get_manuf(mac)
        if manuf:
            return manuf
    except:
        pass
        
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
        
    ports_str = get_config_val("suspicious_ports") or "22, 23, 445, 3389, 5900"
    suspicious = set()
    for p in ports_str.replace(" ", "").split(","):
        if p.isdigit():
            suspicious.add(int(p))
            
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
