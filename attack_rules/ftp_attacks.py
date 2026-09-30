"""FTP attack detection rules.

Owned by Member Three - the FTP attack vector: credential harvesting and
brute-force attempts against the FTP service.
"""

import re

SEVERITY = {
    'Credential Harvesting': 'medium',
}

AUTH_COMMANDS = ('user', 'pass')

# The FTP honeypot describes each command as "Command: <CMD> Args: <args>".
_AUTH_PATTERN = re.compile(r"command:\s*(user|pass)\b")


def classify_command(normalized):
    """Return the attack category for an FTP command, or None for plain probing."""
    if _AUTH_PATTERN.search(normalized):
        return 'Credential Harvesting'
    return None
