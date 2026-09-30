import sqlite3
import csv
import io
import ipaddress
from datetime import datetime, timedelta
from config import Config
from classifier import AttackClassifier

# Attack types that represent authentication attempts (used for brute-force detection)
CREDENTIAL_ATTACK_TYPES = ('Credential Harvesting', 'Brute Force')

def _dict_factory(cursor, row):
    """Helper function to return rows as dictionaries."""
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def _get_connection():
    """Helper to get a database connection."""
    conn = sqlite3.connect(Config.DATABASE, check_same_thread=False)
    conn.row_factory = _dict_factory
    return conn

_attack_listeners = []

def register_attack_listener(callback):
    """Register a callback invoked with each newly logged attack."""
    if callback not in _attack_listeners:
        _attack_listeners.append(callback)

def _notify_attack(attack):
    """Push a logged attack to all registered listeners (e.g. SSE clients)."""
    for callback in _attack_listeners[:]:
        try:
            callback(attack)
        except Exception:
            pass

def init_db():
    """Initialize the database schema, upgrading older databases if needed."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                service TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                source_port INTEGER,
                attack_type TEXT DEFAULT 'Unknown',
                payload TEXT,
                severity TEXT DEFAULT 'medium',
                details TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS bans (
                source_ip TEXT PRIMARY KEY,
                reason TEXT,
                attack_type TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME
            )
        ''')

        # Lightweight migration for databases created before this column existed
        cursor.execute('PRAGMA table_info(attacks)')
        columns = {row['name'] for row in cursor.fetchall()}
        if 'confidence' not in columns:
            cursor.execute('ALTER TABLE attacks ADD COLUMN confidence REAL')

        # Rename the legacy 'Reconnaissance' label to 'Probing'
        cursor.execute("UPDATE attacks SET attack_type = 'Probing' WHERE attack_type = 'Reconnaissance'")

        conn.commit()

def count_recent_credential_attempts(source_ip, service, window_minutes=10):
    """Count recent authentication attempts from an IP against a service."""
    cutoff = (datetime.utcnow() - timedelta(minutes=window_minutes)).strftime('%Y-%m-%d %H:%M:%S')
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT COUNT(*) as count FROM attacks
            WHERE source_ip = ? AND service = ?
              AND attack_type IN (?, ?)
              AND timestamp >= ?
        ''', (source_ip, service, CREDENTIAL_ATTACK_TYPES[0], CREDENTIAL_ATTACK_TYPES[1], cutoff))
        return cursor.fetchone()['count']

def log_attack(service, source_ip, source_port, attack_type, payload, severity='medium', details='',
               confidence=None):
    """Log a new attack into the database and notify any live listeners."""
    # Escalate repeated authentication attempts to a brute-force attack
    if attack_type == 'Credential Harvesting':
        prior_attempts = count_recent_credential_attempts(source_ip, service)
        if prior_attempts + 1 >= Config.ALERT_THRESHOLD:
            attack_type = 'Brute Force'
            severity = AttackClassifier.get_severity('Brute Force')

            # Active defense: automatically ban the source
            if Config.IP_BAN_ENABLED and (Config.BAN_LOCALHOST or not _is_local_address(source_ip)):
                create_ban(source_ip, f'{prior_attempts + 1} failed authentication attempts', attack_type)

    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO attacks
                (service, source_ip, source_port, attack_type, payload, severity, details, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (service, source_ip, source_port, attack_type, payload, severity, details, confidence))
        conn.commit()
        attack_id = cursor.lastrowid

    _notify_attack({
        'id': attack_id,
        'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        'service': service,
        'source_ip': source_ip,
        'source_port': source_port,
        'attack_type': attack_type,
        'payload': payload,
        'severity': severity,
        'details': details,
        'confidence': confidence
    })
    return attack_id

def clear_attacks():
    """Delete all logged attacks and return the number of rows removed."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM attacks')
        conn.commit()
        return cursor.rowcount

# ---- Active defense: IP bans ----

def _is_local_address(source_ip):
    """Return True for loopback or private addresses."""
    try:
        address = ipaddress.ip_address(source_ip)
        return address.is_loopback or address.is_private
    except ValueError:
        return False

def create_ban(source_ip, reason, attack_type='', duration_minutes=None):
    """Ban an IP address (or refresh an existing ban)."""
    duration = Config.BAN_DURATION_MINUTES if duration_minutes is None else duration_minutes
    now = datetime.utcnow()
    created = now.strftime('%Y-%m-%d %H:%M:%S')
    expires = None if duration <= 0 else (now + timedelta(minutes=duration)).strftime('%Y-%m-%d %H:%M:%S')
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO bans (source_ip, reason, attack_type, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(source_ip) DO UPDATE SET
                reason = excluded.reason,
                attack_type = excluded.attack_type,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at
        ''', (source_ip, reason, attack_type, created, expires))
        conn.commit()

def is_banned(source_ip):
    """Return True if the IP currently has an active ban."""
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM bans WHERE source_ip = ? AND (expires_at IS NULL OR expires_at > ?)',
                       (source_ip, now))
        return cursor.fetchone() is not None

def get_bans(active_only=True):
    """List bans, newest first."""
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    with _get_connection() as conn:
        cursor = conn.cursor()
        if active_only:
            cursor.execute('SELECT * FROM bans WHERE expires_at IS NULL OR expires_at > ? ORDER BY created_at DESC', (now,))
        else:
            cursor.execute('SELECT * FROM bans ORDER BY created_at DESC')
        return cursor.fetchall()

def get_active_ban_ips():
    return {row['source_ip'] for row in get_bans(active_only=True)}

def remove_ban(source_ip):
    """Lift a ban and return the number of rows removed."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM bans WHERE source_ip = ?', (source_ip,))
        conn.commit()
        return cursor.rowcount

# ---- Analysis helpers ----

def count_recent_attacks(source_ip, window_minutes=10):
    """Count any attacks from an IP within the window (used for tarpitting)."""
    cutoff = (datetime.utcnow() - timedelta(minutes=window_minutes)).strftime('%Y-%m-%d %H:%M:%S')
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) AS count FROM attacks WHERE source_ip = ? AND timestamp >= ?',
                       (source_ip, cutoff))
        return cursor.fetchone()['count']

def get_attacker_profiles(limit=50, offset=0):
    """Aggregate per-source-IP attacker profiles for analysis."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT source_ip,
                   COUNT(*) AS total,
                   MIN(timestamp) AS first_seen,
                   MAX(timestamp) AS last_seen,
                   COUNT(DISTINCT attack_type) AS types,
                   SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical,
                   MAX(CASE severity
                       WHEN 'critical' THEN 4
                       WHEN 'high' THEN 3
                       WHEN 'medium' THEN 2
                       ELSE 1 END) AS sev_rank
            FROM attacks
            GROUP BY source_ip
            ORDER BY total DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset))
        return cursor.fetchall()

def get_severity_breakdown():
    """Attack counts grouped by severity."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT severity, COUNT(*) AS count FROM attacks GROUP BY severity ORDER BY count DESC')
        return cursor.fetchall()

def get_attacks(service=None, attack_type=None, source_ip=None, severity=None, start_date=None, end_date=None, limit=100, offset=0):
    """Retrieve attacks with optional filtering."""
    query = 'SELECT * FROM attacks WHERE 1=1'
    params = []

    if service:
        query += ' AND service = ?'
        params.append(service)
    if attack_type:
        query += ' AND attack_type = ?'
        params.append(attack_type)
    if source_ip:
        query += ' AND source_ip = ?'
        params.append(source_ip)
    if severity:
        query += ' AND severity = ?'
        params.append(severity)
    if start_date:
        query += ' AND timestamp >= ?'
        params.append(start_date)
    if end_date:
        query += ' AND timestamp <= ?'
        params.append(end_date)

    query += ' ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()

def get_attack_count(service=None, attack_type=None, source_ip=None, severity=None):
    """Count attacks based on filters."""
    query = 'SELECT COUNT(*) as count FROM attacks WHERE 1=1'
    params = []

    if service:
        query += ' AND service = ?'
        params.append(service)
    if attack_type:
        query += ' AND attack_type = ?'
        params.append(attack_type)
    if source_ip:
        query += ' AND source_ip = ?'
        params.append(source_ip)
    if severity:
        query += ' AND severity = ?'
        params.append(severity)

    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchone()['count']

def get_stats():
    """Get overall statistics of the attacks."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        
        # Total attacks
        cursor.execute('SELECT COUNT(*) as total FROM attacks')
        total_attacks = cursor.fetchone()['total']
        
        # Unique IPs
        cursor.execute('SELECT COUNT(DISTINCT source_ip) as unique_ips FROM attacks')
        unique_ips = cursor.fetchone()['unique_ips']
        
        # Top attack type
        cursor.execute('SELECT attack_type, COUNT(*) as count FROM attacks GROUP BY attack_type ORDER BY count DESC LIMIT 1')
        top_attack_row = cursor.fetchone()
        top_attack_type = top_attack_row if top_attack_row else {'attack_type': 'None', 'count': 0}
        
        # Attacks today
        today = datetime.utcnow().strftime('%Y-%m-%d')
        cursor.execute('SELECT COUNT(*) as attacks_today FROM attacks WHERE DATE(timestamp) = ?', (today,))
        attacks_today = cursor.fetchone()['attacks_today']
        
        # Services active
        cursor.execute('SELECT COUNT(DISTINCT service) as services_active FROM attacks')
        services_active = cursor.fetchone()['services_active']
        
        return {
            'total_attacks': total_attacks,
            'unique_ips': unique_ips,
            'top_attack_type': top_attack_type,
            'attacks_today': attacks_today,
            'services_active': services_active
        }

def get_recent_attacks(limit=20):
    """Get the most recent attacks."""
    return get_attacks(limit=limit)

def get_attacks_by_ip(ip):
    """Get all attacks from a specific IP."""
    return get_attacks(source_ip=ip, limit=1000)

def get_attack_timeline(hours=24):
    """Get attack count timeline for the last N hours."""
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    
    with _get_connection() as conn:
        cursor = conn.cursor()
        # Extracting hour (e.g. YYYY-MM-DD HH) using substr
        cursor.execute('''
            SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as count 
            FROM attacks 
            WHERE timestamp >= ? 
            GROUP BY strftime('%Y-%m-%d %H', timestamp)
            ORDER BY timestamp ASC
        ''', (cutoff.strftime('%Y-%m-%d %H:%M:%S'),))
        return cursor.fetchall()

def get_attacks_by_type():
    """Get distribution of attack types."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT attack_type as type, COUNT(*) as count FROM attacks GROUP BY attack_type ORDER BY count DESC')
        return cursor.fetchall()

def get_attacks_by_service():
    """Get distribution of attacks by service."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT service, COUNT(*) as count FROM attacks GROUP BY service ORDER BY count DESC')
        return cursor.fetchall()

def get_unique_ips():
    """Get list of unique IPs and their total attacks."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT source_ip, COUNT(*) as count FROM attacks GROUP BY source_ip ORDER BY count DESC')
        return cursor.fetchall()

def export_attacks_csv():
    """Export all attacks to a CSV formatted string."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM attacks ORDER BY timestamp DESC, id DESC')
        rows = cursor.fetchall()
        
        if not rows:
            return ""
            
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
        return output.getvalue()
