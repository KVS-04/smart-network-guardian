import sqlite3
import json
from datetime import datetime
import os

DB_PATH = "sng_logs.db"

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

def get_alerts(limit=50):
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    c = conn.cursor()
    rows = c.execute("SELECT ts,level,src,dst,msg FROM alerts ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [{"ts": adapt_datetime(r[0]) if isinstance(r[0], datetime) else r[0], "level": r[1], "src": r[2], "dst": r[3], "msg": r[4]} for r in rows]

def get_devices():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    c = conn.cursor()
    rows = c.execute("SELECT ip, mac, hostname, vendor, last_seen, threat, details FROM devices").fetchall()
    conn.close()
    
    devices = []
    for r in rows:
        devices.append({
            "ip": r[0],
            "mac": r[1],
            "hostname": r[2],
            "vendor": r[3],
            "last_seen": adapt_datetime(r[4]) if isinstance(r[4], datetime) else r[4],
            "threat": r[5],
            "details": json.loads(r[6]) if r[6] else {}
        })
    return devices
