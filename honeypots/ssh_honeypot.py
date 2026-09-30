import socket
import threading
import time
import logging
import paramiko
from config import Config
from database import log_attack, is_banned, count_recent_attacks, count_recent_credential_attempts
from classifier import AttackClassifier

logger = logging.getLogger('CyberTrap.SSH')

FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "mysql:x:112:117:MySQL Server:/nonexistent:/bin/false\n"
)

FAKE_SHADOW = "root:$6$rY9k2pQ$mZ9v...:19000:0:99999:7:::\n"


class FakeSSHServer(paramiko.ServerInterface):
    """Fake SSH server: rejects N attempts, then grants a fake shell."""
    def __init__(self, client_ip, client_port):
        self.client_ip = client_ip
        self.client_port = client_port
        self.event = threading.Event()
        self.attempts = 0
        self.accepted = False

    def check_auth_password(self, username, password):
        self.attempts += 1
        prior_attempts = count_recent_credential_attempts(self.client_ip, 'SSH')
        payload = f'Username: {username}, Password: {password}'
        result = AttackClassifier.classify_full(payload, service='ssh')

        if Config.SSH_SHELL_ENABLED and prior_attempts + self.attempts >= Config.SSH_ACCEPT_AFTER:
            self.accepted = True
            details = f'USER {username} / PASS {password} -> Authentication SUCCEEDED (fake shell opened)'
            logger.info(f'SSH fake shell access granted to {self.client_ip}:{self.client_port}')
            log_attack('SSH', self.client_ip, self.client_port, result['attack_type'], payload,
                       result['severity'], details,
                       confidence=result['confidence'])
            return paramiko.AUTH_SUCCESSFUL

        details = f'USER {username} / PASS {password} -> Authentication failed'
        logger.info(f'SSH login attempt from {self.client_ip}:{self.client_port} - {username}:{password}')
        log_attack('SSH', self.client_ip, self.client_port, result['attack_type'], payload,
                   result['severity'], details,
                   confidence=result['confidence'])
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def get_allowed_auths(self, username):
        return 'password'


class SSHHoneypot:
    def __init__(self, host='0.0.0.0', port=None):
        self.host = host
        self.port = port or Config.SSH_PORT
        self.running = False
        self.server_socket = None
        self.thread = None
        # Generate RSA host key
        self.host_key = paramiko.RSAKey.generate(2048)

    def start(self):
        """Start SSH honeypot in a background thread."""
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info(f'SSH Honeypot started on {self.host}:{self.port}')

    def stop(self):
        """Stop the SSH honeypot."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logger.info('SSH Honeypot stopped')

    def _run(self):
        """Main server loop."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(1.0)  # Allow checking self.running
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(Config.MAX_CONNECTIONS)

        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                # Handle each client in a new thread
                t = threading.Thread(target=self._handle_client, args=(client_socket, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f'SSH accept error: {e}')

    def _handle_client(self, client_socket, addr):
        """Handle a single SSH client connection."""
        client_ip, client_port = addr
        logger.info(f'SSH connection from {client_ip}:{client_port}')

        # Active defense: refuse banned sources
        if is_banned(client_ip):
            logger.info(f'Rejected banned IP {client_ip} on SSH')
            log_attack('SSH', client_ip, client_port, 'Blocked', 'Connection refused (IP banned)',
                       'medium', 'Blocked -> connection closed',
                       confidence=1.0)
            try:
                client_socket.close()
            except Exception:
                pass
            return

        # Active defense: tarpit repeat offenders
        if Config.TARPIT_ENABLED:
            recent = count_recent_attacks(client_ip)
            if recent >= Config.TARPIT_START_ATTEMPTS:
                time.sleep(min(Config.TARPIT_MAX_SECONDS, 0.1 * recent))

        try:
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)
            transport.local_version = Config.SSH_BANNER

            server = FakeSSHServer(client_ip, client_port)
            transport.start_server(server=server)

            # Wait for the client to open a session channel (timeout 30 seconds)
            channel = transport.accept(30)
            if channel:
                if server.accepted and Config.SSH_SHELL_ENABLED:
                    self._run_fake_shell(channel, server)
                else:
                    channel.close()
        except Exception as e:
            logger.debug(f'SSH session error from {client_ip}: {e}')
            # Log connection even if transport fails
            log_attack('SSH', client_ip, client_port, 'Probing',
                       f'Connection attempt (transport failed)', 'low',
                       f'SSH probe from {client_ip} -> connection closed',
                       confidence=0.5)
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def _run_fake_shell(self, channel, server):
        """Serve a fake interactive shell and log every command typed."""
        client_ip, client_port = server.client_ip, server.client_port
        logger.info(f'Starting fake shell for {client_ip}:{client_port}')

        channel.send(b"Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-146-generic x86_64)\r\n\r\n")
        channel.send(b"Last login: Mon Sep 27 10:00:00 2026 from 10.0.0.1\r\n")
        channel.send(b"root@web-01:~# ")

        buffer = ''
        try:
            while True:
                data = channel.recv(1024)
                if not data:
                    break
                for char in data.decode('utf-8', 'ignore'):
                    if char in ('\r', '\n'):
                        command = buffer.strip()
                        buffer = ''
                        channel.send(b'\r\n')
                        if command:
                            output, should_exit = self._handle_shell_command(command, client_ip, client_port)
                            if output:
                                channel.send(output)
                            if should_exit:
                                channel.send(b'logout\r\n')
                                return
                        channel.send(b'root@web-01:~# ')
                    elif char in ('\x7f', '\b'):
                        if buffer:
                            buffer = buffer[:-1]
                            channel.send(b'\b \b')
                    elif char == '\x03':
                        buffer = ''
                        channel.send(b'^C\r\nroot@web-01:~# ')
                    elif char.isprintable():
                        buffer += char
                        channel.send(char.encode())
        except Exception as e:
            logger.debug(f'Fake shell error from {client_ip}: {e}')
        finally:
            try:
                channel.close()
            except Exception:
                pass

    def _handle_shell_command(self, command, client_ip, client_port):
        """Log and respond to a command typed in the fake shell."""
        result = AttackClassifier.classify_shell_command(command)
        log_attack('SSH', client_ip, client_port, result['attack_type'], f'Shell command: {command}',
                   result['severity'], f'$ {command}',
                   confidence=result['confidence'])

        base = command.strip()
        parts = base.split()
        cmd = parts[0] if parts else ''

        if base in ('exit', 'logout'):
            return b'', True
        if cmd == 'whoami':
            return b"root\r\n", False
        if cmd == 'id':
            return b"uid=0(root) gid=0(root) groups=0(root)\r\n", False
        if cmd == 'pwd':
            return b"/root\r\n", False
        if cmd == 'hostname':
            return b"web-01\r\n", False
        if cmd == 'uname':
            return b"Linux web-01 5.4.0-146-generic #163-Ubuntu SMP x86_64 GNU/Linux\r\n", False
        if cmd == 'ls':
            return b"backup.sql  config.php  index.php  uploads\r\n", False
        if cmd in ('cat', 'head', 'less', 'more', 'tail'):
            if 'passwd' in base:
                return FAKE_PASSWD.encode(), False
            if 'shadow' in base:
                return FAKE_SHADOW.encode(), False
            target = parts[-1] if len(parts) > 1 else ''
            return f"cat: {target}: No such file or directory\r\n".encode(), False
        if cmd == 'history':
            return b"    1  whoami\r\n    2  ls -la\r\n    3  cat /etc/passwd\r\n", False
        if cmd in ('wget', 'curl'):
            return b"Connecting... connected. Transfer complete.\r\n", False
        if cmd in ('ps', 'netstat', 'ifconfig', 'ip', 'ss'):
            return b"(output truncated)\r\n", False
        return f"bash: {cmd}: command not found\r\n".encode(), False
