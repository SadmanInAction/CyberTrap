// CyberTrap - Threat Intelligence page

const THREAT_API = {
    attackers: '/api/attackers',
    bans: '/api/bans'
};

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

function severityBadge(severity) {
    const color = SEV_COLOR[severity] || SEV_COLOR.low;
    return `<span class="badge" style="background-color:${color}">${esc(severity)}</span>`;
}

async function loadAttackers() {
    const tbody = document.getElementById('attackers-tbody');
    if (!tbody) return;
    try {
        const rows = await (await fetch(THREAT_API.attackers)).json();
        document.getElementById('attacker-count').innerText = `${rows.length} sources`;

        if (!rows.length) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-4">No attacks recorded yet.</td></tr>';
            return;
        }

        tbody.innerHTML = rows.map(r => `
            <tr>
                <td class="font-monospace">${esc(r.source_ip)}</td>
                <td>${r.total}</td>
                <td>${r.types}</td>
                <td class="${r.critical > 0 ? 'text-red fw-bold' : ''}">${r.critical}</td>
                <td>${severityBadge(r.max_severity)}</td>
                <td class="text-muted small">${esc(r.last_seen)}</td>
                <td>${r.banned
                    ? '<span class="badge bg-danger">Banned</span>'
                    : '<span class="badge bg-secondary">Active</span>'}</td>
                <td class="text-end">
                    ${r.banned
                        ? `<button class="btn btn-sm btn-outline-success" data-action="unban" data-ip="${esc(r.source_ip)}">Unban</button>`
                        : `<button class="btn btn-sm btn-outline-danger" data-action="ban" data-ip="${esc(r.source_ip)}">Ban</button>`}
                </td>
            </tr>
        `).join('');
    } catch (err) {
        console.error('Attackers load error', err);
    }
}

async function loadBans() {
    const list = document.getElementById('bans-list');
    if (!list) return;
    try {
        const bans = await (await fetch(THREAT_API.bans)).json();
        document.getElementById('ban-count').innerText = bans.length;
        if (!bans.length) {
            list.innerHTML = '<li class="list-group-item bg-transparent text-muted border-secondary">No active bans.</li>';
            return;
        }
        list.innerHTML = bans.map(b => `
            <li class="list-group-item bg-transparent text-light border-secondary">
                <div class="d-flex justify-content-between align-items-center">
                    <span class="font-monospace">${esc(b.source_ip)}</span>
                    <button class="btn btn-sm btn-outline-success" data-action="unban" data-ip="${esc(b.source_ip)}">Unban</button>
                </div>
                <div class="small text-muted">${esc(b.reason || '')}</div>
                <div class="small text-muted">expires ${esc(b.expires_at || 'never')}</div>
            </li>
        `).join('');
    } catch (err) {
        console.error('Bans load error', err);
    }
}

function refreshAll() {
    loadAttackers();
    loadBans();
}

async function banIp(ip) {
    try {
        await fetch(THREAT_API.bans, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason: 'Manual ban from Threat Intel' })
        });
        refreshAll();
    } catch (err) {
        console.error('Ban error', err);
    }
}

async function unbanIp(ip) {
    try {
        await fetch(`${THREAT_API.bans}/${encodeURIComponent(ip)}`, { method: 'DELETE' });
        refreshAll();
    } catch (err) {
        console.error('Unban error', err);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    if (!document.getElementById('attackers-table')) return;

    refreshAll();
    setInterval(refreshAll, 10000);

    document.addEventListener('click', (event) => {
        const button = event.target.closest('[data-action]');
        if (!button) return;
        const ip = button.getAttribute('data-ip');
        if (button.getAttribute('data-action') === 'ban') banIp(ip);
        else unbanIp(ip);
    });

    const banBtn = document.getElementById('ban-btn');
    if (banBtn) {
        banBtn.addEventListener('click', () => {
            const input = document.getElementById('ban-ip');
            const ip = (input.value || '').trim();
            if (!ip) return;
            banIp(ip);
            input.value = '';
        });
    }
});
