import socket
import threading
import time
import logging
import json
import urllib.parse
from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler
from config import Config
from database import log_attack, is_banned, count_recent_attacks
from classifier import AttackClassifier

logger = logging.getLogger('CyberTrap.HTTP')

FAKE_LOGIN_PAGE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Corporate Portal Login</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-container { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 300px; }
        h2 { text-align: center; color: #333; margin-bottom: 1.5rem; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        input[type="submit"] { width: 100%; background-color: #0056b3; color: white; padding: 10px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        input[type="submit"]:hover { background-color: #004494; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Corporate Portal</h2>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="submit" value="Login">
        </form>
    </div>
</body>
</html>
'''

FAKE_ADMIN_PAGE = '''<!DOCTYPE html>
<html lang="en">
<head><title>Admin Panel</title></head>
<body><h1>Unauthorized Access</h1><p>You do not have permission to view this directory.</p></body>
</html>
'''

FAKE_404_PAGE = '''<!DOCTYPE html>
<html lang="en">
<head><title>404 Not Found</title></head>
<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body>
</html>
'''

class HoneypotHTTPHandler(BaseHTTPRequestHandler):
    server_version = Config.HTTP_SERVER_HEADER if hasattr(Config, 'HTTP_SERVER_HEADER') else 'Apache/2.4.41 (Ubuntu)'
    sys_version = ""

    SERVED_PATHS = {'/', '/login', '/admin', '/wp-admin', '/phpmyadmin', '/robots.txt'}

    def _apply_defenses(self):
        """Return True if the request should be dropped (source is banned)."""
        client_ip, client_port = self.client_address
        if is_banned(client_ip):
            logger.info(f'Rejected banned IP {client_ip} on HTTP')
            self.send_response(403)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<h1>403 Forbidden</h1><p>Your address has been blocked.</p>")
            log_attack('HTTP', client_ip, client_port, 'Blocked', 'Connection refused (IP banned)',
                       'medium', 'Blocked -> 403 Forbidden',
                       confidence=1.0)
            return True

        if Config.TARPIT_ENABLED:
            recent = count_recent_attacks(client_ip)
            if recent >= Config.TARPIT_START_ATTEMPTS:
                time.sleep(min(Config.TARPIT_MAX_SECONDS, 0.1 * recent))
        return False

    def _log_request_to_db(self, method, payload, response=''):
        client_ip, client_port = self.client_address
        # URL-decode the path and payload to detect encoded attack patterns
        decoded_path = urllib.parse.unquote(self.path)
        decoded_payload = urllib.parse.unquote(payload) if payload else ''
        full_payload = f"Method: {method} Path: {decoded_path} Payload: {decoded_payload}"
        result = AttackClassifier.classify_full(full_payload, service='http')
        attack_type, severity = result['attack_type'], result['severity']

        # A POST to the login form is a credential-harvesting attempt unless the
        # payload already matched a stronger attack (e.g. SQL injection).
        path_only = urllib.parse.urlparse(decoded_path).path
        if method == 'POST' and path_only == '/login' and attack_type == 'Probing':
            attack_type = 'Credential Harvesting'
            severity = AttackClassifier.get_severity(attack_type)

        details = f'{method} {path_only}'
        if response:
            details += f' -> {response}'
        log_attack('HTTP', client_ip, client_port, attack_type, full_payload, severity, details,
                   confidence=result['confidence'])
        logger.info(f"HTTP {method} from {client_ip}:{client_port} - {self.path}")

    def do_GET(self):
        if self._apply_defenses():
            return
        path = urllib.parse.urlparse(self.path).path
        status = 200 if path in self.SERVED_PATHS else 404
        self._log_request_to_db('GET', '', f'{status} {HTTPStatus(status).phrase}')

        self.send_response(status)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        if path in ['/', '/login']:
            self.wfile.write(FAKE_LOGIN_PAGE.encode('utf-8'))
        elif path in ['/admin', '/wp-admin', '/phpmyadmin']:
            self.wfile.write(FAKE_ADMIN_PAGE.encode('utf-8'))
        elif path == '/robots.txt':
            self.wfile.write(b"User-agent: *\nDisallow: /admin\nDisallow: /wp-admin\n")
        else:
            self.wfile.write(FAKE_404_PAGE.encode('utf-8'))
    
    def do_POST(self):
        if self._apply_defenses():
            return
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')
        path = urllib.parse.urlparse(self.path).path

        if path == '/login':
            status, body = 200, b"Invalid username or password. Please try again."
        else:
            status, body = 404, FAKE_404_PAGE.encode('utf-8')

        self._log_request_to_db('POST', post_data, f'{status} {HTTPStatus(status).phrase}')

        self.send_response(status)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(body)
    
    def log_message(self, format, *args):
        # Suppress default logging, use our logger instead
        pass

class HTTPHoneypot:
    def __init__(self, host='0.0.0.0', port=None):
        self.host = host
        self.port = port or (Config.HTTP_PORT if hasattr(Config, 'HTTP_PORT') else 80)
        self.running = False
        self.server = None
        self.thread = None
    
    def start(self):
        self.running = True
        self.server = HTTPServer((self.host, self.port), HoneypotHTTPHandler)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info(f'HTTP Honeypot started on {self.host}:{self.port}')
    
    def stop(self):
        self.running = False
        if self.server:
            self.server.shutdown()
        logger.info('HTTP Honeypot stopped')
    
    def _run(self):
        self.server.serve_forever()
