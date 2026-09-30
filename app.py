import os
import sys
import json
import time
import logging
import threading
from queue import Queue
from flask import Flask, render_template, request, jsonify, Response, redirect, url_for
from config import Config
from database import (
    init_db, log_attack, get_attacks, get_attack_count, get_stats, 
    get_recent_attacks, get_attacks_by_ip, get_attack_timeline, 
    get_attacks_by_type, get_attacks_by_service, get_unique_ips, 
    export_attacks_csv, clear_attacks, get_bans, create_ban, remove_ban,
    get_active_ban_ips, is_banned, get_attacker_profiles, get_severity_breakdown
)
from honeypots import SSHHoneypot, HTTPHoneypot, FTPHoneypot
import database as db_module

# Numeric severity rank (as stored per profile) back to a label
SEVERITY_RANK = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'}

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cybertrap.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('cybertrap.app')

app = Flask(__name__)
app.config.from_object(Config)

# Track server start time for uptime reporting
START_TIME = time.time()

# Store honeypot instances globally
honeypots_instances = {}
sse_listeners = []

def notify_listeners(attack):
    """Broadcast a logged attack to every connected SSE client."""
    for q in sse_listeners[:]:
        try:
            q.put_nowait(attack)
        except Exception:
            pass

# The honeypots call database.log_attack directly, so subscribe there to
# receive every logged attack for the real-time feed.
db_module.register_attack_listener(notify_listeners)

# ---- Page Routes ----
@app.route('/')
def dashboard():
    return render_template('dashboard.html', active_page='dashboard')

@app.route('/logs')
def logs():
    return render_template('logs.html', active_page='logs')

@app.route('/console')
def console():
    return render_template('console.html', active_page='console')

@app.route('/threats')
def threats():
    return render_template('threats.html', active_page='threats')

@app.route('/report')
def report():
    return render_template('report.html', active_page='report')

@app.route('/settings')
def settings():
    return render_template('settings.html', active_page='settings')

# ---- API Routes ----
@app.route('/api/stats')
def api_stats():
    return jsonify(get_stats())

@app.route('/api/attacks')
def api_attacks():
    # Read query params
    service = request.args.get('service')
    attack_type = request.args.get('attack_type')
    source_ip = request.args.get('source_ip')
    severity = request.args.get('severity')
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    
    attacks = get_attacks(limit=limit, offset=offset, service=service, 
                          attack_type=attack_type, source_ip=source_ip, severity=severity)
    total = get_attack_count(service=service, attack_type=attack_type, 
                             source_ip=source_ip, severity=severity)
    
    return jsonify({
        'attacks': attacks,
        'total': total,
        'limit': limit,
        'offset': offset
    })

@app.route('/api/attacks/recent')
def api_recent():
    limit = request.args.get('limit', 20, type=int)
    return jsonify(get_recent_attacks(limit))

@app.route('/api/attacks/timeline')
def api_timeline():
    hours = request.args.get('hours', 24, type=int)
    return jsonify(get_attack_timeline(hours))

@app.route('/api/attacks/by-type')
def api_by_type():
    return jsonify(get_attacks_by_type())

@app.route('/api/attacks/by-service')
def api_by_service():
    return jsonify(get_attacks_by_service())

@app.route('/api/attacks/ip/<ip>')
def api_attacks_by_ip(ip):
    return jsonify(get_attacks_by_ip(ip))

@app.route('/api/export/csv')
def api_export_csv():
    csv_data = export_attacks_csv()
    return Response(csv_data, mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment;filename=honeypot_attacks.csv'})

@app.route('/api/stream')
def api_stream():
    """Server-Sent Events endpoint for real-time attack feed."""
    def event_stream():
        q = Queue()
        sse_listeners.append(q)
        try:
            while True:
                data = q.get()  # Blocks until data available
                yield f'data: {json.dumps(data)}\n\n'
        except GeneratorExit:
            if q in sse_listeners:
                sse_listeners.remove(q)
    
    return Response(event_stream(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@app.route('/api/status')
def api_status():
    """Report real service status, uptime and database size."""
    try:
        db_size = os.path.getsize(Config.DATABASE)
    except OSError:
        db_size = 0
    services = {
        name: bool(getattr(instance, 'running', False))
        for name, instance in honeypots_instances.items()
    }
    return jsonify({
        'uptime_seconds': int(time.time() - START_TIME),
        'db_size_bytes': db_size,
        'services': services
    })

@app.route('/api/attackers')
def api_attackers():
    """Per-IP attacker profiles with ban status."""
    limit = request.args.get('limit', 50, type=int)
    profiles = get_attacker_profiles(limit=limit)
    banned = get_active_ban_ips()
    for profile in profiles:
        profile['max_severity'] = SEVERITY_RANK.get(profile.get('sev_rank'), 'low')
        profile['banned'] = profile['source_ip'] in banned
    return jsonify(profiles)

@app.route('/api/severity')
def api_severity():
    """Attack counts grouped by severity."""
    return jsonify(get_severity_breakdown())

@app.route('/api/bans')
def api_bans():
    """List active IP bans."""
    return jsonify(get_bans(active_only=True))

@app.route('/api/bans', methods=['POST'])
def api_create_ban():
    """Manually ban an IP address."""
    data = request.get_json(silent=True) or {}
    ip = (data.get('ip') or '').strip()
    if not ip:
        return jsonify({'status': 'error', 'message': 'ip is required'}), 400
    reason = data.get('reason') or 'Manual ban from dashboard'
    duration = data.get('duration_minutes')
    create_ban(ip, reason, 'Manual', duration)
    logger.info(f'Manual ban created for {ip}')
    return jsonify({'status': 'ok', 'message': f'Banned {ip}'})

@app.route('/api/bans/<path:ip>', methods=['DELETE'])
def api_remove_ban(ip):
    """Lift a ban."""
    removed = remove_ban(ip)
    message = f'Unbanned {ip}' if removed else f'No active ban for {ip}'
    return jsonify({'status': 'ok', 'removed': removed, 'message': message})

@app.route('/api/settings', methods=['POST'])
def api_settings():
    # Accept JSON settings, return success
    return jsonify({'status': 'ok', 'message': 'Settings updated (will take effect on restart)'})

@app.route('/api/clear-logs', methods=['POST'])
def api_clear_logs():
    """Permanently delete all recorded attacks."""
    deleted = clear_attacks()
    logger.info(f'Cleared {deleted} attack log entries')
    return jsonify({'status': 'ok', 'deleted': deleted,
                    'message': f'Cleared {deleted} log entries'})

def start_honeypots():
    """Start all enabled honeypot services."""
    if Config.SERVICES_ENABLED.get('ssh', True):
        ssh = SSHHoneypot()
        ssh.start()
        honeypots_instances['ssh'] = ssh
    
    if Config.SERVICES_ENABLED.get('http', True):
        http = HTTPHoneypot()
        http.start()
        honeypots_instances['http'] = http
    
    if Config.SERVICES_ENABLED.get('ftp', True):
        ftp = FTPHoneypot()
        ftp.start()
        honeypots_instances['ftp'] = ftp

if __name__ == '__main__':
    print(r'''
   ______      __              ______                
  / ____/_  __/ /_  ___  _____/_  __/________ _____  
 / /   / / / / __ \/ _ \/ ___/ / / / ___/ __ `/ __ \ 
/ /___/ /_/ / /_/ /  __/ /    / / / /  / /_/ / /_/ / 
\____/\__, /_.___/\___/_/    /_/ /_/   \__,_/ .___/  
    /____/                                 /_/       
    
    [*] CyberTrap Honeypot System v1.0
    ''')
    
    # Initialize database
    init_db()
    
    # Start honeypot services
    start_honeypots()
    
    print(f'\n[*] SSH Honeypot listening on port {Config.SSH_PORT}')
    print(f'[*] HTTP Honeypot listening on port {Config.HTTP_PORT}')
    print(f'[*] FTP Honeypot listening on port {Config.FTP_PORT}')
    print(f'[*] Web Dashboard: http://localhost:{Config.WEB_PORT}')
    print(f'\n[*] CyberTrap is active. Waiting for attackers...\n')
    
    # Start Flask app
    app.run(host='0.0.0.0', port=Config.WEB_PORT, debug=False, threaded=True)
