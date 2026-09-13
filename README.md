# Smart Network Guardian 🛡️

Smart Network Guardian is an advanced local network security dashboard designed to monitor, analyze, and protect your digital environment. With a sleek dark mode UI and powerful backend services, it empowers you to take control of your network security through continuous packet sniffing, active device scanning, and file integrity monitoring.

## 🌟 Key Features

*   **Active Network Scanner**: Uses Nmap to discover all devices connected to your local network, resolving IP addresses, MAC addresses, hostnames, and vendor details.
*   **Intelligent Packet Sniffer**: Analyzes live network traffic to detect anomalies such as packet floods, high-rate connections, and massive outbound data transfers. 
*   **App Attribution**: Automatically cross-references network anomalies with your local ports to determine exactly which application (e.g., `chrome.exe`, `python.exe`) is responsible for suspicious traffic.
*   **File Integrity Monitor (Watchdog)**: Monitors local directories for mass file modifications, creations, or deletions (e.g., ransomware behavior) and alerts you immediately if activity spikes.
*   **Advanced Threat Dashboard**: An intuitive, premium dark-mode interface to view alerts in real-time, configure thresholds, and manage your network state.
*   **Customizable Settings**: Set specific thresholds for packets/sec and configure Nmap paths directly from the UI.

## 🛠️ Technology Stack

*   **Backend**: Python, FastAPI, Uvicorn, SQLite
*   **Network Analysis**: Scapy (Packet Sniffing), python-nmap (Device Scanning), psutil (App Tracing)
*   **Frontend**: Vanilla HTML, CSS, JavaScript (Dynamic UI with Premium Themes)

## 🚀 Installation

1. **Prerequisites**: 
   * Install [Python 3.10+](https://www.python.org/downloads/)
   * Install [Npcap](https://npcap.com/) (Required on Windows for Scapy packet sniffing)
   * Install [Nmap](https://nmap.org/download.html) (Ensure it is added to your System PATH)

2. **Clone the Repository**:
   ```bash
   git clone https://github.com/KVS-04/smart-network-guardian.git
   cd smart-network-guardian
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## 💻 Usage

1. **Start the Backend Server**:
   ```bash
   python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
   ```
   *Note: You may need to run this command as Administrator to grant Scapy full access to your network interfaces.*

2. **Open the Dashboard**:
   Navigate to `http://127.0.0.1:8000` in your web browser.

3. **Features Overview**:
   * **Scan Network**: Performs an ARP and port scan on your local subnet to discover devices.
   * **Start Network Sniffer**: Begins background packet inspection to watch for floods and anomalies.
   * **Select Folder & Enable File Watch**: Prompts you for an absolute folder path (e.g., `C:\Users\Name\Downloads`) and begins watching it for mass modifications.

## ⚠️ Disclaimer

This tool is designed for educational and defensive purposes only. Ensure you have explicit permission to monitor and scan any network you run Smart Network Guardian on.
