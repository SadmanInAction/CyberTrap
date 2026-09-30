"""SSH attack detection rules.

Owned by Member Two - the SSH attack vector: credential brute force and the
commands typed into the deception shell after a simulated login.
"""

SEVERITY = {
    'Credential Harvesting': 'medium',
    'Command Execution':     'high',
    'Discovery':             'high',
}

# Commands that indicate the attacker is surveying the host rather than
# executing a specific payload.
DISCOVERY_COMMANDS = (
    'whoami', 'id', 'uname', 'hostname', 'pwd', 'ls', 'ps',
    'ifconfig', 'ip a', 'netstat', 'env', 'history', 'w', 'last',
)


def classify_auth(normalized):
    """Any password authentication against the SSH service is a credential attempt."""
    return 'Credential Harvesting'


def classify_command(normalized):
    """Classify a command typed into the deception shell."""
    if any(normalized.startswith(cmd) or f' {cmd}' in f' {normalized}'
           for cmd in DISCOVERY_COMMANDS):
        return 'Discovery'
    return 'Command Execution'
