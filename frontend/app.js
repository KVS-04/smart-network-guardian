document.addEventListener('DOMContentLoaded', () => {
    // Navigation
    const navItems = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.page-section');
    const pageTitle = document.getElementById('page-title');

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            const target = item.getAttribute('data-target');
            sections.forEach(s => s.classList.remove('active'));
            document.getElementById(target).classList.add('active');
            
            pageTitle.textContent = item.textContent.trim();
            
            if(target === 'devices') fetchDevices();
            if(target === 'alerts') fetchAlerts();
        });
    });

    // Control Buttons
    const scanBtn = document.getElementById('scan-btn');
    const sniffBtn = document.getElementById('sniff-btn');
    const watchBtn = document.getElementById('watch-btn');
    const folderBtn = document.getElementById('folder-btn');
    
    let isSniffing = false;
    let isWatching = false;

    scanBtn.addEventListener('click', async () => {
        scanBtn.textContent = 'Scanning...';
        scanBtn.style.opacity = '0.7';
        scanBtn.disabled = true;
        
        const res = await fetch('/api/scan', { method: 'POST' });
        const data = await res.json();
        
        if (data.message === 'Scan already in progress') {
            return;
        }

        const pollInterval = setInterval(async () => {
            try {
                const statusRes = await fetch('/api/status');
                const statusData = await statusRes.json();
                
                if (statusData.scanning) {
                    scanBtn.textContent = `Scanning... ${statusData.scan_progress || 0}%`;
                } else {
                    clearInterval(pollInterval);
                    scanBtn.textContent = 'Scan Network';
                    scanBtn.style.opacity = '1';
                    scanBtn.disabled = false;
                    fetchDevices();
                    alert("Scan complete! The network devices list has been updated.");
                }
            } catch (e) {
                console.error("Polling error:", e);
            }
        }, 1000);
    });

    sniffBtn.addEventListener('click', async () => {
        if(!isSniffing) {
            await fetch('/api/sniff/start', { method: 'POST' });
            sniffBtn.textContent = 'Stop Network Sniffer';
            sniffBtn.classList.replace('success', 'danger');
            isSniffing = true;
        } else {
            await fetch('/api/sniff/stop', { method: 'POST' });
            sniffBtn.textContent = 'Start Network Sniffer';
            sniffBtn.classList.replace('danger', 'success');
            isSniffing = false;
        }
    });

    let hasSelectedFolder = false;
    let selectedFolderPath = "";

    folderBtn.addEventListener('click', async () => {
        const path = prompt("Enter the absolute path of the folder to monitor (e.g. C:\\Users\\veer1\\Downloads):");
        if(path) {
            try {
                const res = await fetch('/api/watchdog/select_folder', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({folder: path})
                });
                const data = await res.json();
                if(data.status === 'success') {
                    hasSelectedFolder = true;
                    selectedFolderPath = data.folder;
                    alert(`Successfully selected folder: ${data.folder}`);
                } else {
                    alert(`Error: ${data.message}`);
                }
            } catch (e) {
                alert(`Error: ${e.message}`);
            }
        }
    });

    watchBtn.addEventListener('click', async () => {
        if(!isWatching) {
            if (!hasSelectedFolder) {
                alert("Please click 'Select Folder' and choose a folder before enabling the File Watch monitor.");
                return;
            }
            await fetch('/api/watchdog/start', { method: 'POST' });
            watchBtn.textContent = 'Disable File Watch';
            isWatching = true;
        } else {
            await fetch('/api/watchdog/stop', { method: 'POST' });
            watchBtn.textContent = 'Enable File Watch';
            isWatching = false;
        }
    });

    // Fetch initial status
    fetch('/api/status').then(r => r.json()).then(data => {
        if(data.sniffing) {
            sniffBtn.textContent = 'Stop Monitor';
            sniffBtn.classList.replace('success', 'danger');
            isSniffing = true;
        }
    });

    fetch('/api/watchdog/status').then(r => r.json()).then(data => {
        if(data.folder) {
            hasSelectedFolder = true;
            selectedFolderPath = data.folder;
        }
        if(data.is_watching) {
            watchBtn.textContent = 'Disable File Watch';
            isWatching = true;
        }
    });

    // Data Fetching
    function renderAlerts(alerts, containerId) {
        const container = document.getElementById(containerId);
        container.innerHTML = '';
        alerts.forEach(alert => {
            const el = document.createElement('div');
            el.className = `alert-item ${alert.level}`;
            el.innerHTML = `
                <div class="alert-header">
                    <span class="alert-level ${alert.level}">[${alert.level.toUpperCase()}]</span>
                    <span class="alert-time">${alert.ts}</span>
                </div>
                <div class="alert-body">${alert.msg}</div>
                ${(alert.src || alert.dst) ? `<div class="alert-meta">SRC: ${alert.src || 'N/A'} | DST: ${alert.dst || 'N/A'}</div>` : ''}
            `;
            container.appendChild(el);
        });
    }

    async function fetchAlerts() {
        try {
            const res = await fetch('/api/alerts');
            const data = await res.json();
            document.getElementById('stat-alerts').textContent = data.alerts.length;
            renderAlerts(data.alerts.slice(0, 10), 'recent-alerts');
            renderAlerts(data.alerts, 'full-alerts-feed');
        } catch (e) {
            console.error(e);
        }
    }

    async function fetchDevices() {
        try {
            const res = await fetch('/api/devices');
            const data = await res.json();
            
            document.getElementById('stat-devices').textContent = data.devices.length;
            
            let highThreats = 0;
            const tbody = document.getElementById('device-table-body');
            tbody.innerHTML = '';
            
            data.devices.forEach(dev => {
                if(dev.threat === 'High') highThreats++;
                
                let detailsHtml = '';
                if (dev.details) {
                    if (dev.details.open_ports && dev.details.open_ports.length > 0) {
                        detailsHtml += `<div><strong>Open Ports:</strong> ${dev.details.open_ports.join(', ')}</div>`;
                    }
                    if (dev.details.suspicious_ports && dev.details.suspicious_ports.length > 0) {
                        detailsHtml += `<div><strong>Suspicious Ports:</strong> <span style="color: red;">${dev.details.suspicious_ports.join(', ')}</span></div>`;
                    }
                    if (dev.details.is_blacklisted) {
                        detailsHtml += `<div><strong>Blacklisted:</strong> <span style="color: red;">Yes</span></div>`;
                    }
                    if (dev.details.traffic_spike) {
                        detailsHtml += `<div><strong>Anomalous Traffic:</strong> <span style="color: orange;">Detected</span></div>`;
                    }
                }
                
                // Fallback if no specific details are recorded but threat is high/medium (likely historical scan data)
                if (!detailsHtml) {
                    if (dev.threat === 'High' || dev.threat === 'Medium') {
                        detailsHtml = '<div style="color: var(--text-muted)"><i>Historical data (run scan again for details)</i></div>';
                    }
                }
                
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><strong>${dev.ip}</strong></td>
                    <td><span style="font-family: monospace; color: var(--text-muted)">${dev.mac}</span></td>
                    <td>${dev.hostname}</td>
                    <td>${dev.vendor}</td>
                    <td class="text-muted" style="font-size: 0.85em;">${dev.last_seen}</td>
                    <td><span class="threat-badge ${dev.threat}">${dev.threat}</span></td>
                    <td style="font-size: 0.9em;">
                        ${detailsHtml}
                    </td>
                `;
                tbody.appendChild(tr);
            });
            
            document.getElementById('stat-threats').textContent = highThreats;
        } catch (e) {
            console.error(e);
        }
    }

    // Initial fetch
    fetchDevices();
    fetchAlerts();
    setInterval(fetchDevices, 10000); // Poll devices
    setInterval(fetchAlerts, 5000);   // Poll alerts

    // WebSocket for realtime stats and alerts
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
    
    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if(msg.type === 'stats') {
            document.getElementById('stat-pps').textContent = msg.data.pps;
        } else if(msg.type === 'alert') {
            fetchAlerts(); // Re-fetch all alerts on new alert
        }
    };

    // Settings - Blacklist Management
    const addBlacklistBtn = document.getElementById('add-blacklist-btn');
    const newBlacklistIp = document.getElementById('new-blacklist-ip');
    const blacklistTableBody = document.getElementById('blacklist-table-body');

    async function fetchBlacklist() {
        try {
            const res = await fetch('/api/settings/blacklist');
            const data = await res.json();
            renderBlacklist(data.blacklist);
        } catch (e) {
            console.error("Error fetching blacklist", e);
        }
    }

    function renderBlacklist(ips) {
        blacklistTableBody.innerHTML = '';
        ips.forEach(ip => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${ip}</strong></td>
                <td>
                    <button class="btn danger" onclick="removeBlacklistIp('${ip}')" style="padding: 4px 8px; font-size: 0.8em;">Remove</button>
                </td>
            `;
            blacklistTableBody.appendChild(tr);
        });
    }

    addBlacklistBtn.addEventListener('click', async () => {
        const ip = newBlacklistIp.value.trim();
        if(ip) {
            try {
                const res = await fetch('/api/settings/blacklist', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: ip })
                });
                const data = await res.json();
                if(data.status === 'success') {
                    newBlacklistIp.value = '';
                    renderBlacklist(data.blacklist);
                }
            } catch (e) {
                console.error("Error adding IP", e);
            }
        }
    });

    window.removeBlacklistIp = async function(ip) {
        try {
            const res = await fetch('/api/settings/blacklist', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            });
            const data = await res.json();
            if(data.status === 'success') {
                renderBlacklist(data.blacklist);
            }
        } catch (e) {
            console.error("Error removing IP", e);
        }
    };

    // Fetch blacklist initially
    fetchBlacklist();

    // Advanced Configuration Management
    const nmapPathInput = document.getElementById('nmap-path');
    const ppsThresholdInput = document.getElementById('pps-threshold');
    const scanIntervalSelect = document.getElementById('scan-interval');
    
    let autoScanTimer = null;

    function applyTheme(themeName) {
        document.documentElement.setAttribute('data-theme', themeName);
        if (themeName === 'cyber-green') {
            document.documentElement.style.setProperty('--accent-color', '#10b981');
            document.documentElement.style.setProperty('--accent-hover', '#059669');
        } else if (themeName === 'hacker-red') {
            document.documentElement.style.setProperty('--accent-color', '#ef4444');
            document.documentElement.style.setProperty('--accent-hover', '#dc2626');
        } else {
            // Default Neon Blue
            document.documentElement.style.setProperty('--accent-color', '#3b82f6');
            document.documentElement.style.setProperty('--accent-hover', '#2563eb');
        }
    }

    async function fetchConfig() {
        try {
            const res = await fetch('/api/settings/config');
            const data = await res.json();
            
            if (data.nmap_path) nmapPathInput.value = data.nmap_path;
            if (data.pps_threshold) ppsThresholdInput.value = data.pps_threshold;
            if (data.scan_interval !== undefined) {
                scanIntervalSelect.value = data.scan_interval;
                setupAutoScan(data.scan_interval);
            }
            if (data.theme) applyTheme(data.theme);
        } catch (e) {
            console.error("Error fetching config", e);
        }
    }

    async function saveConfig(updates) {
        try {
            const res = await fetch('/api/settings/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(updates)
            });
            const data = await res.json();
            if (data.status === 'success') {
                alert("Settings saved successfully!");
            }
        } catch (e) {
            alert(`Error saving config: ${e.message}`);
        }
    }

    document.getElementById('save-nmap-btn').addEventListener('click', () => {
        saveConfig({ nmap_path: nmapPathInput.value.trim() });
    });

    document.getElementById('save-pps-btn').addEventListener('click', () => {
        saveConfig({ pps_threshold: parseInt(ppsThresholdInput.value, 10) });
    });

    document.getElementById('save-interval-btn').addEventListener('click', () => {
        const minutes = parseInt(scanIntervalSelect.value, 10);
        saveConfig({ scan_interval: minutes });
        setupAutoScan(minutes);
    });

    document.querySelectorAll('.theme-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const theme = e.target.getAttribute('data-theme');
            applyTheme(theme);
            saveConfig({ theme: theme });
        });
    });

    document.getElementById('clear-db-btn').addEventListener('click', async () => {
        if(confirm("Are you sure you want to completely wipe all historical devices and alerts? This cannot be undone.")) {
            try {
                const res = await fetch('/api/settings/clear_db', { method: 'POST' });
                const data = await res.json();
                if(data.status === 'success') {
                    alert("Database cleared successfully!");
                    fetchDevices();
                    fetchAlerts();
                }
            } catch (e) {
                alert(`Error clearing database: ${e.message}`);
            }
        }
    });

    function setupAutoScan(minutes) {
        if (autoScanTimer) clearInterval(autoScanTimer);
        if (minutes > 0) {
            autoScanTimer = setInterval(() => {
                if(!scanBtn.disabled) scanBtn.click();
            }, minutes * 60 * 1000);
        }
    }

    // Fetch initial config
    fetchConfig();
});
