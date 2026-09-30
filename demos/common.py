"""Shared terminal helpers for the attack demonstration scripts."""

import os

os.system('')  # Enable ANSI colors on Windows

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
BOLD = '\033[1m'
RESET = '\033[0m'


def banner():
    print(f"""{CYAN}{BOLD}
    ╔══════════════════════════════════════════════════╗
    ║         CyberTrap Honeypot - LIVE DEMO          ║
    ║                                                  ║
    ║   Make sure the dashboard is open in browser:    ║
    ║          http://localhost:5000                    ║
    ╚══════════════════════════════════════════════════╝
    {RESET}""")


def pause(msg="Press ENTER to continue to next attack..."):
    input(f"\n{YELLOW}>>> {msg}{RESET}")


def attack_header(num, title, service, severity):
    colors = {'CRITICAL': RED, 'HIGH': '\033[91m', 'MEDIUM': YELLOW, 'LOW': GREEN}
    sev_color = colors.get(severity, YELLOW)
    print(f"\n{'='*60}")
    print(f"{BOLD}  Attack #{num}: {title}{RESET}")
    print(f"  Service: {CYAN}{service}{RESET}  |  Severity: {sev_color}{severity}{RESET}")
    print(f"{'='*60}")
