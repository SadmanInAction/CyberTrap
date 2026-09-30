// CyberTrap - Incident Report page

const SEV_COLOR = {
    critical: '#ff4444',
    high: '#ffab00',
    medium: '#00d4ff',
    low: '#8892a4'
};

function esc(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}

async function getJson(url) {
    return (await fetch(url)).json();
}

document.addEventListener('DOMContentLoaded', async () => {
    if (!document.getElementById('r-total')) return;

    document.getElementById('report-time').innerText = new Date().toLocaleString();

    try {
        const [stats, severity, attackers, bans] = await Promise.all([
            getJson('/api/stats'),
            getJson('/api/severity'),
            getJson('/api/attackers'),
            getJson('/api/bans')
        ]);

        document.getElementById('r-total').innerText = stats.total_attacks || 0;
        document.getElementById('r-ips').innerText = stats.unique_ips || 0;
        document.getElementById('r-today').innerText = stats.attacks_today || 0;
        document.getElementById('r-bans').innerText = bans.length;

        document.getElementById('r-severity').innerHTML = severity.length
            ? severity.map(s => `
                <tr>
                    <td><span class="badge" style="background-color:${SEV_COLOR[s.severity] || SEV_COLOR.low}">${esc(s.severity)}</span></td>
                    <td class="text-end">${s.count}</td>
                </tr>`).join('')
            : '<tr><td class="text-muted">No data.</td></tr>';

        document.getElementById('r-attackers').innerHTML = attackers.length
            ? attackers.slice(0, 15).map(a => `
                <tr>
                    <td class="font-monospace">${esc(a.source_ip)}</td>
                    <td>${a.total}</td>
                    <td>${a.types}</td>
                    <td class="${a.critical > 0 ? 'text-red fw-bold' : ''}">${a.critical}</td>
                    <td><span class="badge" style="background-color:${SEV_COLOR[a.max_severity] || SEV_COLOR.low}">${esc(a.max_severity)}</span></td>
                    <td class="text-muted small">${esc(a.first_seen)}</td>
                    <td class="text-muted small">${esc(a.last_seen)}</td>
                </tr>`).join('')
            : '<tr><td colspan="7" class="text-muted">No attackers recorded.</td></tr>';
    } catch (err) {
        console.error('Report load error', err);
    }
});
