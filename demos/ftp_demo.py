"""FTP attack demonstration.

Owned by Member Three - brute-forces credentials against the FTP decoy on port
2121 until the source crosses the brute-force threshold and is automatically
banned.
"""

import socket
import time

from config import Config
from demos import common
from demos.common import BOLD, GREEN, RESET, YELLOW


def bruteforce():
    common.attack_header(8, "FTP Brute Force Attack", "FTP (port 2121)", "MEDIUM")
    print(f"""
  {BOLD}What's happening:{RESET}
  The attacker tries multiple username/password combinations against
  our FTP server. This simulates a brute-force attack.

  {YELLOW}Note: after {Config.ALERT_THRESHOLD} attempts from the same IP, CyberTrap escalates
  them to a BRUTE FORCE attack and automatically BANS the source IP.
  This is the final attack step - localhost gets banned here, so unban it
  from the Threat Intel page if you want to keep attacking.{RESET}

  {BOLD}Login attempts:{RESET}
    """)
    common.pause()

    ftp_creds = [
        ('anonymous', 'anonymous'),
        ('admin', 'admin'),
        ('root', 'root123'),
        ('ftp', 'ftp'),
        ('user', 'password'),
        ('test', 'test'),
        ('oracle', 'oracle'),
        ('postgres', 'postgres'),
    ]
    for user, password in ftp_creds:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect(('127.0.0.1', 2121))
            sock.recv(1024)  # banner
            sock.sendall(f'USER {user}\r\n'.encode())
            sock.recv(1024)
            sock.sendall(f'PASS {password}\r\n'.encode())
            response = sock.recv(1024).decode().strip()
            sock.sendall(b'QUIT\r\n')
            sock.close()
            print(f"  {YELLOW}[!] FTP: {user} / {password}  ->  {response}{RESET}")
        except Exception as exc:
            print(f"  [x] FTP connection error: {exc}")
        time.sleep(0.6)

    print(f"\n  {GREEN}[+] {len(ftp_creds) * 2} FTP login attempts captured!{RESET}")
    print(f"  {GREEN}[+] The last attempts were auto-escalated to BRUTE FORCE.{RESET}")
    print(f"  {YELLOW}    Filter the Attack Logs page by 'Brute Force' to show them.{RESET}")
    time.sleep(1)
