// CyberTrap - Live Attack Console
// Subscribes to the same SSE feed as the dashboard and renders each attack
// as a terminal-style request -> response pair.

const CONSOLE_API = {
    recent: '/api/attacks/recent',
    stream: '/api/stream'
};

const SERVICE_LABEL = { SSH: 'SSH', HTTP: 'HTTP', FTP: 'FTP' };

const SEVERITY_COLOR = {
    critical: '#ff4444',
    high: '#ffab00',
    medium: '#00d4ff',
    low: '#8892a4'
};

function escapeHtml(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}

// Turn the stored payload into a readable "attacker request" line.
function buildRequestLine(attack) {
    const payload = attack.payload || '';
    if (attack.service === 'HTTP') {
        const match = payload.match(/Method:\s*(\S+)\s+Path:\s*(.*?)\s+Payload:\s*([\s\S]*)/);
        if (match) {
            const method = match[1];
            const path = match[2];
            const body = (match[3] || '').trim();
            return body ? `${method} ${path}   [body: ${body}]` : `${method} ${path}`;
        }
    }
    return payload || '(empty)';
}

function buildEntry(attack) {
    const entry = document.createElement('div');
    entry.className = 'console-entry';
    entry.style.borderLeftColor = SEVERITY_COLOR[attack.severity] || SEVERITY_COLOR.low;

    const time = (attack.timestamp || '').split(' ')[1] || attack.timestamp || '';
    const service = (attack.service || '?').toLowerCase();
    const severity = (attack.severity || 'low').toUpperCase();

    entry.innerHTML = `
        <div class="console-head">
            <span class="c-time">${escapeHtml(time)}</span>
            <span class="c-service c-${escapeHtml(service)}">${escapeHtml(SERVICE_LABEL[attack.service] || attack.service)}</span>
            <span class="c-ip">${escapeHtml(attack.source_ip)}:${escapeHtml(attack.source_port)}</span>
            <span class="c-type" style="color:${SEVERITY_COLOR[attack.severity] || SEVERITY_COLOR.low}">
                ${escapeHtml(attack.attack_type || 'Unknown')} &middot; ${escapeHtml(severity)}
            </span>
        </div>
        <div class="console-line c-req"><span class="arrow">&gt;</span> ${escapeHtml(buildRequestLine(attack))}</div>
        <div class="console-line c-res"><span class="arrow">&lt;</span> ${escapeHtml(attack.details || '(no response recorded)')}</div>
    `;
    return entry;
}

document.addEventListener('DOMContentLoaded', () => {
    const output = document.getElementById('console-output');
    if (!output) return;

    const countEl = document.getElementById('console-count');
    let paused = false;
    let eventCount = 0;

    function addEvent(attack, prepend) {
        const idle = output.querySelector('.console-idle');
        if (idle) idle.remove();

        const entry = buildEntry(attack);
        if (prepend) {
            output.insertBefore(entry, output.firstChild);
            if (!paused) output.scrollTop = 0;
        } else {
            output.appendChild(entry);
        }

        eventCount++;
        countEl.innerText = `${eventCount} events`;

        while (output.children.length > 300) {
            output.removeChild(output.lastChild);
        }
    }

    // Seed with recent history (already newest-first from the API)
    fetch(`${CONSOLE_API.recent}?limit=50`)
        .then(res => res.json())
        .then(rows => rows.forEach(attack => addEvent(attack, false)))
        .catch(err => console.error('Console history error', err));

    // Live stream
    const source = new EventSource(CONSOLE_API.stream);
    source.onmessage = (event) => {
        try {
            addEvent(JSON.parse(event.data), true);
        } catch (err) {
            console.error('Console stream parse error', err);
        }
    };

    document.getElementById('console-pause').addEventListener('click', function () {
        paused = !paused;
        this.classList.toggle('active', paused);
        this.innerHTML = paused
            ? '<i class="bi bi-play-fill me-1"></i> Resume'
            : '<i class="bi bi-pause-fill me-1"></i> Pause';
    });

    document.getElementById('console-clear').addEventListener('click', () => {
        output.innerHTML = '';
        eventCount = 0;
        countEl.innerText = '0 events';
    });
});
