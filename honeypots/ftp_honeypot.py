import socket
import threading
import time
import logging
from config import Config
from database import log_attack, is_banned, count_recent_attacks
from classifier import AttackClassifier

logger = logging.getLogger('CyberTrap.FTP')

class FTPHoneypot:
    def __init__(self, host='0.0.0.0', port=None):
        self.host = host
        self.port = port or (Config.FTP_PORT if hasattr(Config, 'FTP_PORT') else 21)
        self.running = False
        self.server_socket = None
        self.thread = None
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info(f'FTP Honeypot started on {self.host}:{self.port}')

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        logger.info('FTP Honeypot stopped')
    
    def _run(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(1.0)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(Config.MAX_CONNECTIONS if hasattr(Config, 'MAX_CONNECTIONS') else 5)
        
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                t = threading.Thread(target=self._handle_client, args=(client_socket, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f'FTP accept error: {e}')
    
    @staticmethod
    def _reply_for(cmd):
        """Return the exact FTP response line the honeypot sends for a command."""
        replies = {
            'USER': b"331 Please specify the password.\r\n",
            'PASS': b"530 Login incorrect.\r\n",
            'SYST': b"215 UNIX Type: L8\r\n",
            'PWD': b'257 "/" is the current directory\r\n',
            'QUIT': b"221 Goodbye.\r\n",
            'LIST': b"530 Please login with USER and PASS.\r\n",
            'PORT': b"530 Please login with USER and PASS.\r\n",
            'PASV': b"530 Please login with USER and PASS.\r\n",
        }
        return replies.get(cmd, b"500 Unknown command.\r\n")

    def _handle_client(self, client_socket, addr):
        client_ip, client_port = addr
        logger.info(f'FTP connection from {client_ip}:{client_port}')

        # Active defense: refuse banned sources
        if is_banned(client_ip):
            logger.info(f'Rejected banned IP {client_ip} on FTP')
            try:
                client_socket.sendall(b"421 Service not available.\r\n")
                client_socket.close()
            except Exception:
                pass
            log_attack('FTP', client_ip, client_port, 'Blocked', 'Connection refused (IP banned)',
                       'medium', 'Blocked -> 421 Service not available',
                       confidence=1.0)
            return

        # Active defense: tarpit repeat offenders
        if Config.TARPIT_ENABLED:
            recent = count_recent_attacks(client_ip)
            if recent >= Config.TARPIT_START_ATTEMPTS:
                time.sleep(min(Config.TARPIT_MAX_SECONDS, 0.1 * recent))
        
        try:
            client_socket.sendall(b"220 (vsFTPd 3.0.3)\r\n")
            
            while self.running:
                data = client_socket.recv(1024)
                if not data:
                    break
                
                command_line = data.decode('utf-8', errors='ignore').strip()
                if not command_line:
                    continue
                
                parts = command_line.split(' ', 1)
                cmd = parts[0].upper()
                args = parts[1] if len(parts) > 1 else ""
                reply = self._reply_for(cmd)
                
                # Log the command together with the reply we send back
                payload = f"Command: {cmd} Args: {args}"
                result = AttackClassifier.classify_full(payload, service='ftp')
                command = f'{cmd} {args}'.strip()
                details = f'{command} -> {reply.decode("utf-8").strip()}'
                if cmd in ['USER', 'PASS']:
                    log_attack('FTP', client_ip, client_port, result['attack_type'], payload,
                               result['severity'], details,
                               confidence=result['confidence'])
                else:
                    log_attack('FTP', client_ip, client_port, 'Probing', payload, 'low', details,
                               confidence=0.5)
                
                client_socket.sendall(reply)
                if cmd == 'QUIT':
                    break
                    
        except Exception as e:
            logger.debug(f'FTP session error from {client_ip}: {e}')
        finally:
            try:
                client_socket.close()
            except:
                pass
