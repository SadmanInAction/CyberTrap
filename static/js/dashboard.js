// ===== Configuration =====
const API = {
    stats: '/api/stats',
    recent: '/api/attacks/recent',
    timeline: '/api/attacks/timeline',
    byType: '/api/attacks/by-type',
    byService: '/api/attacks/by-service',
    attacks: '/api/attacks',
    stream: '/api/stream',
    exportCsv: '/api/export/csv',
    settings: '/api/settings',
    status: '/api/status',
    clearLogs: '/api/clear-logs'
};

// Color palette for charts
const COLORS = {
    cyan: '#00d4ff',
    red: '#ff4444',
    green: '#00e676',
    orange: '#ffab00',
    purple: '#b388ff',
    blue: '#448aff',
    pink: '#ff80ab',
    bgLight: 'rgba(255,255,255,0.1)',
    textLight: '#e0e0e0'
};

const SERVICE_COLORS = {
    'SSH': COLORS.green,
    'HTTP': COLORS.blue,
    'FTP': COLORS.orange
};

const SEVERITY_COLORS = {
    'critical': COLORS.red,
    'high': COLORS.orange,
    'medium': COLORS.cyan,
    'low': '#6c757d'
};

// Global Chart.js Defaults
if(typeof Chart !== 'undefined') {
    Chart.defaults.color = COLORS.textLight;
    Chart.defaults.scale.grid.color = COLORS.bgLight;
    Chart.defaults.plugins.legend.labels.color = COLORS.textLight;
}

// ===== Utility Functions =====
function formatTimestamp(ts) {
    const d = new Date(ts);
    return d.toLocaleString();
}

function createBadge(text, type, dictionary) {
    const color = dictionary[text] || '#6c757d';
    return `<span class="badge" style="background-color: ${color}">${text}</span>`;
}

function truncate(text, maxLen) {
    if (!text) return '';
    return text.length > maxLen ? text.substring(0, maxLen) + '...' : text;
}

function formatUptime(seconds) {
    seconds = Math.max(0, Math.floor(seconds || 0));
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
}

function formatBytes(bytes) {
    bytes = Math.max(0, bytes || 0);
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

// ===== Dashboard Functions =====
let timelineChart, typeChart, serviceChart;

async function loadStats() {
    try {
        const res = await fetch(API.stats);
        if(!res.ok) throw new Error('Network response was not ok');
        const data = await res.json();
        
        document.getElementById('stat-total').innerText = data.total_attacks || 0;
        document.getElementById('stat-ips').innerText = data.unique_ips || 0;
        document.getElementById('stat-today').innerText = data.attacks_today || 0;
        
        // top_attack_type is an object: {attack_type: "...", count: N}
        const topAttack = data.top_attack_type;
        if (topAttack && topAttack.attack_type && topAttack.attack_type !== 'None') {
            document.getElementById('stat-top-attack').innerText = topAttack.attack_type;
        } else {
            document.getElementById('stat-top-attack').innerText = '-';
        }
        
        document.getElementById('stat-services').innerText = data.services_active || 0;
    } catch(err) {
        console.error('Error loading stats', err);
    }
}

async function loadTimeline() {
    try {
        const res = await fetch(API.timeline);
        const data = await res.json();
        
        const ctx = document.getElementById('timelineChart');
        if(!ctx) return;
        
        const labels = data.map(d => d.hour);
        const values = data.map(d => d.count);
        
        if(timelineChart) timelineChart.destroy();
        
        timelineChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Attacks',
                    data: values,
                    borderColor: COLORS.cyan,
                    backgroundColor: 'rgba(0, 212, 255, 0.2)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    } catch (err) { console.error('Timeline error:', err); }
}

async function loadTypeChart() {
    try {
        const res = await fetch(API.byType);
        const data = await res.json();
        
        const ctx = document.getElementById('typeChart');
        if(!ctx) return;
        
        const labels = data.map(d => d.type);
        const values = data.map(d => d.count);
        const bgColors = [COLORS.purple, COLORS.blue, COLORS.orange, COLORS.cyan, COLORS.red, COLORS.pink];
        
        if(typeChart) typeChart.destroy();
        
        typeChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: bgColors,
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
    } catch (err) { console.error('Type chart error:', err); }
}

async function loadServiceChart() {
    try {
        const res = await fetch(API.byService);
        const data = await res.json();
        
        const ctx = document.getElementById('serviceChart');
        if(!ctx) return;
        
        const labels = data.map(d => d.service);
        const values = data.map(d => d.count);
        const bgColors = labels.map(l => SERVICE_COLORS[l] || COLORS.cyan);
        
        if(serviceChart) serviceChart.destroy();
        
        serviceChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Attacks',
                    data: values,
                    backgroundColor: bgColors
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    } catch (err) { console.error('Service chart error:', err); }
}

function createAttackEntry(attack) {
    const div = document.createElement('div');
    div.className = 'feed-item';
    div.innerHTML = `
        <div class="text-secondary small" style="min-width: 140px;">${formatTimestamp(attack.timestamp)}</div>
        <div style="min-width: 70px;">${createBadge(attack.service, 'service', SERVICE_COLORS)}</div>
        <div class="text-light" style="min-width: 120px; font-family: monospace;">${attack.source_ip}</div>
        <div class="text-info flex-grow-1">${attack.attack_type || 'Unknown'}</div>
        <div>${createBadge(attack.severity || 'low', 'severity', SEVERITY_COLORS)}</div>
    `;
    return div;
}

function initSSE() {
    const feed = document.getElementById('live-feed');
    if(!feed) return;
    
    // Load some initial recent attacks to fill feed
    fetch(API.recent)
        .then(res => res.json())
        .then(data => {
            data.forEach(attack => {
                feed.appendChild(createAttackEntry(attack));
            });
        }).catch(err => console.error(err));

    const evtSource = new EventSource(API.stream);
    evtSource.onmessage = function(event) {
        try {
            const attack = JSON.parse(event.data);
            const entry = createAttackEntry(attack);
            feed.insertBefore(entry, feed.firstChild);
            
            // Keep feed size manageable
            while(feed.children.length > 50) {
                feed.removeChild(feed.lastChild);
            }
        } catch(e) {
            console.error('Error parsing SSE data', e);
        }
    };
}

// ===== Logs Page Functions =====
let currentPage = 1;
const limit = 20;

async function loadLogs(page = 1) {
    const tbody = document.getElementById('logs-tbody');
    if(!tbody) return;
    
    const service = document.getElementById('filter-service').value;
    const type = document.getElementById('filter-type').value;
    const severity = document.getElementById('filter-severity').value;
    const ip = document.getElementById('filter-ip').value;
    
    const offset = (page - 1) * limit;
    
    const params = new URLSearchParams({ limit, offset });
    if(service) params.append('service', service);
    if(type) params.append('attack_type', type);
    if(severity) params.append('severity', severity);
    if(ip) params.append('source_ip', ip);
    
    try {
        const res = await fetch(`${API.attacks}?${params.toString()}`);
        const data = await res.json();
        
        tbody.innerHTML = '';
        const attacks = data.attacks || [];
        attacks.forEach((attack, idx) => {
            const tr = document.createElement('tr');
            tr.style.cursor = 'pointer';
            tr.onclick = () => showDetail(attack);
            tr.innerHTML = `
                <td>${offset + idx + 1}</td>
                <td>${formatTimestamp(attack.timestamp)}</td>
                <td>${createBadge(attack.service, 'service', SERVICE_COLORS)}</td>
                <td style="font-family: monospace;">${attack.source_ip}</td>
                <td>${attack.attack_type || '-'}</td>
                <td>${createBadge(attack.severity || 'low', 'severity', SEVERITY_COLORS)}</td>
                <td><small class="text-muted">${truncate(attack.payload || '-', 30)}</small></td>
            `;
            tbody.appendChild(tr);
        });
        
        document.getElementById('current-page').innerText = page;
        document.getElementById('prev-page').parentElement.classList.toggle('disabled', page === 1);
        document.getElementById('next-page').parentElement.classList.toggle('disabled', attacks.length < limit);
    } catch(err) {
        console.error('Logs fetch error', err);
    }
}

function showDetail(attack) {
    const content = document.getElementById('modal-content');
    content.innerHTML = `
        <div class="row mb-3">
            <div class="col-sm-4 fw-bold">Timestamp:</div>
            <div class="col-sm-8">${formatTimestamp(attack.timestamp)}</div>
        </div>
        <div class="row mb-3">
            <div class="col-sm-4 fw-bold">Service:</div>
            <div class="col-sm-8">${createBadge(attack.service, 'service', SERVICE_COLORS)}</div>
        </div>
        <div class="row mb-3">
            <div class="col-sm-4 fw-bold">Source IP:</div>
            <div class="col-sm-8 font-monospace">${attack.source_ip}</div>
        </div>
        <div class="row mb-3">
            <div class="col-sm-4 fw-bold">Attack Type:</div>
            <div class="col-sm-8">${attack.attack_type || '-'}</div>
        </div>
        <div class="row mb-3">
            <div class="col-sm-4 fw-bold">Severity:</div>
            <div class="col-sm-8">${createBadge(attack.severity || 'low', 'severity', SEVERITY_COLORS)}</div>
        </div>
        <div class="row mb-3">
            <div class="col-sm-4 fw-bold">Raw Payload:</div>
            <div class="col-sm-12 mt-2">
                <pre class="bg-dark p-3 rounded border border-secondary text-light"><code>${attack.payload || 'No payload'}</code></pre>
            </div>
        </div>
    `;
    
    document.getElementById('modal-view-ip').onclick = () => {
        document.getElementById('filter-ip').value = attack.source_ip;
        bootstrap.Modal.getInstance(document.getElementById('detail-modal')).hide();
        currentPage = 1;
        loadLogs(currentPage);
    };
    
    const modal = new bootstrap.Modal(document.getElementById('detail-modal'));
    modal.show();
}

// ===== Settings Page Functions =====
async function loadStatus() {
    try {
        const res = await fetch(API.status);
        const data = await res.json();

        ['ssh', 'http', 'ftp'].forEach(svc => {
            const el = document.getElementById(`status-${svc}`);
            if (!el) return;
            const online = data.services && data.services[svc];
            el.innerText = online ? 'Online' : 'Offline';
            el.className = `badge rounded-pill ${online ? 'bg-success' : 'bg-danger'}`;
        });

        const uptime = document.getElementById('status-uptime');
        if (uptime) uptime.innerText = formatUptime(data.uptime_seconds);

        const dbSize = document.getElementById('status-db-size');
        if (dbSize) dbSize.innerText = formatBytes(data.db_size_bytes);
    } catch (err) {
        console.error('Status error', err);
    }
}

// ===== Initialization =====
document.addEventListener('DOMContentLoaded', () => {
    // Dashboard page check
    if(document.getElementById('stat-total')) {
        loadStats();
        loadTimeline();
        loadTypeChart();
        loadServiceChart();
        initSSE();
        
        setInterval(loadStats, 30000); // 30s refresh
    }
    
    // Logs page check
    if(document.getElementById('logs-table')) {
        loadLogs(1);
        
        document.getElementById('filter-form').addEventListener('submit', (e) => {
            e.preventDefault();
            currentPage = 1;
            loadLogs(currentPage);
        });
        
        document.getElementById('prev-page').addEventListener('click', (e) => {
            e.preventDefault();
            if(currentPage > 1) {
                currentPage--;
                loadLogs(currentPage);
            }
        });
        
        document.getElementById('next-page').addEventListener('click', (e) => {
            e.preventDefault();
            if(!e.target.parentElement.classList.contains('disabled')) {
                currentPage++;
                loadLogs(currentPage);
            }
        });
    }
    
    // Settings page check
    const settingsForm = document.getElementById('settings-form');
    if(settingsForm) {
        loadStatus();
        setInterval(loadStatus, 10000); // 10s refresh

        settingsForm.addEventListener('submit', (e) => {
            e.preventDefault();
            alert('Settings saved! Changes will take effect on next restart (Demo Mode).');
        });

        const clearBtn = document.getElementById('clear-logs-btn');
        if(clearBtn) {
            clearBtn.addEventListener('click', async () => {
                if(!confirm('Are you sure you want to permanently delete all logs? This cannot be undone.')) {
                    return;
                }
                try {
                    const res = await fetch(API.clearLogs, { method: 'POST' });
                    const data = await res.json();
                    alert(data.message || 'Logs cleared successfully.');
                    loadStatus();
                } catch(err) {
                    console.error('Clear logs error', err);
                    alert('Failed to clear logs.');
                }
            });
        }
    }
});
