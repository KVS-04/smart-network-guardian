from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import threading
import queue
import time
import os
import asyncio

from backend.database import init_db, get_alerts, get_devices, log_device
from backend.scanner import arp_scan, nmap_scan_host, resolve_hostname, get_vendor, compute_threat_score, HAS_NMAP
from backend.sniffer import SnifferThread, AnomalyDetector, PortMonitorThread
from backend.monitor import start_watchdog

app = FastAPI(title="Smart Network Guardian API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global State
packet_queue = queue.Queue()
sniffer_thread = None
detector_thread = None
port_monitor_thread = None
watchdog_observer = None
target_ports = set()
active_websockets = []
main_loop = None
is_scanning = False
scan_progress = 0

def notify_clients(message: dict):
    for ws in active_websockets:
        # In a real app we'd use async broadcst, for this prototype we'll let a background task handle it or just send it directly if possible
        pass # To be handled correctly in async loop

async def broadcast_alert(level, src, dst, msg):
    alert_data = {"type": "alert", "data": {"level": level, "src": src, "dst": dst, "msg": msg}}
    for ws in active_websockets:
        try:
            await ws.send_json(alert_data)
        except:
            pass

def on_alert_sync(level, src, dst, msg):
    if main_loop and main_loop.is_running():
        asyncio.run_coroutine_threadsafe(broadcast_alert(level, src, dst, msg), main_loop)

@app.on_event("startup")
def startup_event():
    global main_loop
    main_loop = asyncio.get_running_loop()
    init_db()

@app.get("/api/status")
def get_status():
    return {
        "sniffing": sniffer_thread is not None and sniffer_thread.running.is_set(),
        "monitoring": watchdog_observer is not None,
        "nmap_available": HAS_NMAP,
        "scanning": is_scanning,
        "scan_progress": scan_progress
    }

@app.post("/api/scan")
def scan_network(background_tasks: BackgroundTasks):
    def run_scan():
        global is_scanning, scan_progress
        try:
            scan_progress = 5  # ARP scan starting
            devices = arp_scan()
            scan_progress = 20  # ARP scan complete
            
            total = len(devices)
            for i, d in enumerate(devices):
                details = {}
                if HAS_NMAP:
                    details = nmap_scan_host(d['ip'])
                
                dinfo = {
                    'ip': d['ip'],
                    'mac': d['mac'],
                    'hostname': resolve_hostname(d['ip']),
                    'vendor': get_vendor(d['mac']),
                    'details': details
                }
                dinfo['threat'] = compute_threat_score(dinfo)
                log_device(dinfo)
                
                # Update progress
                if total > 0:
                    scan_progress = 20 + int((i + 1) / total * 80)
                    
            scan_progress = 100
        finally:
            is_scanning = False

    global is_scanning, scan_progress
    if not is_scanning:
        is_scanning = True
        scan_progress = 0
        background_tasks.add_task(run_scan)
        return {"message": "Scan started in background"}
    return {"message": "Scan already in progress"}

@app.get("/api/devices")
def fetch_devices():
    return {"devices": get_devices()}

@app.get("/api/alerts")
def fetch_alerts():
    return {"alerts": get_alerts()}

@app.post("/api/sniff/start")
def start_sniffing():
    global sniffer_thread, detector_thread
    if sniffer_thread is None:
        sniffer_thread = SnifferThread(packet_queue, mode='network')
        detector_thread = AnomalyDetector(packet_queue, alert_callback=on_alert_sync)
        sniffer_thread.start()
        detector_thread.start()
        return {"status": "started"}
    return {"status": "already running"}

@app.post("/api/sniff/stop")
def stop_sniffing():
    global sniffer_thread, detector_thread
    if sniffer_thread:
        sniffer_thread.stop()
        sniffer_thread = None
    if detector_thread:
        detector_thread.stop()
        detector_thread = None
    return {"status": "stopped"}

watchdog_folder = os.path.expanduser("~/Documents")

class FolderRequest(BaseModel):
    folder: str

@app.post("/api/watchdog/select_folder")
def select_watchdog_folder(req: FolderRequest):
    global watchdog_folder
    import os
    if os.path.isdir(req.folder):
        watchdog_folder = req.folder
        return {"status": "success", "folder": watchdog_folder}
    else:
        return {"status": "error", "message": "Invalid directory path"}

@app.post("/api/watchdog/start")
def start_watching():
    global watchdog_observer
    if watchdog_observer is None:
        dirs = [watchdog_folder]
        watchdog_observer = start_watchdog(dirs, on_alert_sync)
        return {"status": "started", "folder": watchdog_folder}
    return {"status": "already running", "folder": watchdog_folder}

@app.post("/api/watchdog/stop")
def stop_watching():
    global watchdog_observer
    if watchdog_observer:
        watchdog_observer.stop()
        watchdog_observer.join(1)
        watchdog_observer = None
    return {"status": "stopped"}

import psutil

@app.get("/api/apps")
def get_apps():
    app_names = set()
    for proc in psutil.process_iter(['name']):
        try:
            app_names.add(proc.info['name'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return {"apps": sorted(list(app_names), key=str.lower)}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_websockets.append(websocket)
    try:
        while True:
            # Send stats every second
            pps = 0
            if detector_thread:
                pps = len(getattr(detector_thread, 'pkt_history', []))
            
            await websocket.send_json({"type": "stats", "data": {"pps": pps}})
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        active_websockets.remove(websocket)
    except Exception:
        if websocket in active_websockets:
            active_websockets.remove(websocket)

# Mount frontend
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
