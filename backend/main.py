from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks
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
        "nmap_available": HAS_NMAP
    }

@app.post("/api/scan")
def scan_network(background_tasks: BackgroundTasks):
    def run_scan():
        devices = arp_scan()
        for d in devices:
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
    
    background_tasks.add_task(run_scan)
    return {"message": "Scan started in background"}

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

@app.post("/api/watchdog/start")
def start_watching():
    global watchdog_observer
    if watchdog_observer is None:
        # Default watch dir for now
        dirs = [os.path.expanduser("~/Documents")]
        watchdog_observer = start_watchdog(dirs, on_alert_sync)
        return {"status": "started"}
    return {"status": "already running"}

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
