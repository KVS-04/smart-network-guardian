import json
import os

CONFIG_FILE = "sng_config.json"

DEFAULT_CONFIG = {
    "nmap_path": "",
    "pps_threshold": 100,
    "theme": "default",
    "scan_interval": 0  # 0 means never
}

def load_config():
    if not os.path.exists(CONFIG_FILE):
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_FILE, 'r') as f:
            data = json.load(f)
            # Merge with defaults in case new keys were added
            config = DEFAULT_CONFIG.copy()
            config.update(data)
            return config
    except Exception as e:
        print(f"Error loading config: {e}")
        return DEFAULT_CONFIG.copy()

def save_config(config):
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving config: {e}")
        return False

def get_config_val(key):
    config = load_config()
    return config.get(key, DEFAULT_CONFIG.get(key))

def set_config_val(key, value):
    config = load_config()
    config[key] = value
    save_config(config)
