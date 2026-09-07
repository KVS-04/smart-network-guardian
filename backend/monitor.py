import os
import time
import threading
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from backend.database import log_alert

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
