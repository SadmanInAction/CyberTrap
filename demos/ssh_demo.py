"""SSH attack demonstration.

Owned by Member Two - brute-forces credentials against the SSH decoy on port
2222 and demonstrates the deception shell that records commands typed after a
simulated login.
"""

from config import Config
from demos import common
from demos.common import BOLD, CYAN, RESET


def bruteforce():
    common.attack_header(9, "SSH Brute Force + Deception Shell", "SSH (port 2222)", "MEDIUM")
    print(f"""
  {BOLD}What's happening:{RESET}
  Attackers try to brute-force SSH credentials. The honeypot rejects the
  first attempts, then - after {Config.SSH_ACCEPT_AFTER} tries - pretends to let them
  in and drops them into a FAKE SHELL, logging every command they type.

  {CYAN}>>> To demonstrate this LIVE, open a NEW terminal and run:{RESET}

  {BOLD}    ssh root@localhost -p 2222{RESET}

  Type 'yes' if asked about the host key fingerprint, then enter any
  password (e.g. "password123"). Retry until a shell appears.

  {BOLD}Then type commands and watch them appear live:{RESET}
      whoami            -> root
      ls                -> backup.sql  config.php  index.php  uploads
      cat /etc/passwd   -> fake password file
      exit              -> closes the session

  Every command is logged and classified (Discovery / Command Execution).
    """)
    common.pause("Press ENTER when you're done with SSH demo (or skip)...")
