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
    
    let isSniffing = false;
    let isWatching = false;

    scanBtn.addEventListener('click', async () => {
        scanBtn.textContent = 'Scanning...';
        scanBtn.style.opacity = '0.7';
        await fetch('/api/scan', { method: 'POST' });
        setTimeout(() => {
            scanBtn.textContent = 'Scan Network';
            scanBtn.style.opacity = '1';
            fetchDevices();
        }, 5000);
    });

    sniffBtn.addEventListener('click', async () => {
        if(!isSniffing) {
            await fetch('/api/sniff/start', { method: 'POST' });
            sniffBtn.textContent = 'Stop Monitor';
            sniffBtn.classList.replace('success', 'danger');
            isSniffing = true;
        } else {
            await fetch('/api/sniff/stop', { method: 'POST' });
            sniffBtn.textContent = 'Start Monitor';
            sniffBtn.classList.replace('danger', 'success');
            isSniffing = false;
        }
    });

    watchBtn.addEventListener('click', async () => {
        if(!isWatching) {
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
        if(data.monitoring) {
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
                
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><strong>${dev.ip}</strong></td>
                    <td><span style="font-family: monospace; color: var(--text-muted)">${dev.mac}</span></td>
                    <td>${dev.hostname}</td>
                    <td>${dev.vendor}</td>
                    <td><span class="threat-badge ${dev.threat}">${dev.threat}</span></td>
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
});
