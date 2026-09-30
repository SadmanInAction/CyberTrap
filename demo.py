"""
CyberTrap Honeypot - Live Demo Script
======================================
Run this script WHILE the dashboard (http://localhost:5000) is open
in the browser. The attacks will appear in REAL-TIME on the live feed!

Usage:
    1. Start the honeypot:  python app.py
    2. Open browser:        http://localhost:5000
    3. Run this script:     python demo.py

The attack scripts themselves live in the ``demos`` package, one module per
attack vector.
"""

from demos import common
from demos.common import BOLD, CYAN, GREEN, RESET
from demos import http_demo, ssh_demo, ftp_demo


def show_dashboard_tour():
    print(f"""
{CYAN}{BOLD}
    ╔══════════════════════════════════════════════════╗
    ║                  DASHBOARD TOUR                  ║
    ╚══════════════════════════════════════════════════╝
{RESET}
  Now switch to the browser (http://localhost:5000) and show:

  {BOLD}1. Dashboard Page (/) :{RESET}
     - Top row: Stats cards (total attacks, unique IPs, etc.)
     - Middle row: Three charts
       * Attack Timeline (line chart - attacks over time)
       * Attacks by Type (doughnut chart - SQL injection, XSS, etc.)
       * Attacks by Service (bar chart - SSH vs HTTP vs FTP)
     - Bottom: Live Attack Feed (real-time, auto-updating)

  {BOLD}2. Attack Logs Page (/logs) :{RESET}
     - Click "Attack Logs" in sidebar
     - Show filtering: try filtering by Service = "HTTP"
     - Try filtering by Attack Type = "SQL Injection"
     - Click any row to see full attack details + raw payload
     - Click "Export CSV" to download all logs

  {BOLD}3. Settings Page (/settings) :{RESET}
     - Shows service configuration (ports, banners)
     - Alert thresholds
     - System status

  {BOLD}4. Live Console Page (/console) :{RESET}
     - Terminal-style request -> response stream for every attack

  {BOLD}5. Threat Intel Page (/threats) :{RESET}
     - Per-IP attacker profiles and active IP bans

  {BOLD}6. Report Page (/report) :{RESET}
     - One-page incident summary (use Print -> Save as PDF)
    """)


def main():
    common.banner()
    common.pause("Press ENTER to start the live demo...")

    http_demo.recon()
    http_demo.admin_probe()
    http_demo.sql_injection()
    http_demo.xss()
    http_demo.path_traversal()
    http_demo.command_injection()
    http_demo.credential_harvesting()
    ssh_demo.bruteforce()
    ftp_demo.bruteforce()
    show_dashboard_tour()

    print(f"""
{GREEN}{BOLD}
    ╔══════════════════════════════════════════════════╗
    ║              DEMO COMPLETE!                      ║
    ║                                                  ║
    ║  All attacks have been captured and classified.  ║
    ║  The dashboard shows everything in real-time.    ║
    ╚══════════════════════════════════════════════════╝
{RESET}""")


if __name__ == '__main__':
    main()
