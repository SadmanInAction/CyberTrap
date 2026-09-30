import os

class Config:
    """Central configuration for CyberTrap Honeypot System."""
    
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cybertrap-honeypot-secret-2024')
    DATABASE = os.path.join(BASE_DIR, 'honeypot.db')
    
    # Honeypot service ports
    SSH_PORT = 2222
    HTTP_PORT = 8080
    FTP_PORT = 2121
    
    # Web dashboard port
    WEB_PORT = 5000
    
    # Service banners (made to look like real services)
    SSH_BANNER = 'SSH-2.0-OpenSSH_7.4'
    HTTP_SERVER_HEADER = 'Apache/2.4.29 (Ubuntu)'
    FTP_BANNER = '220 ProFTPD 1.3.5 Server ready.'
    
    # Alert threshold - trigger alert after N attempts from same IP
    ALERT_THRESHOLD = 10

    # Attack classification
    CLASSIFIER_MIN_SCORE = 0.6

    # Active defense - automatic IP banning
    IP_BAN_ENABLED = True
    BAN_DURATION_MINUTES = 10
    BAN_LOCALHOST = True

    # Active defense - tarpitting (slow down repeat offenders)
    TARPIT_ENABLED = True
    TARPIT_MAX_SECONDS = 0.5
    TARPIT_START_ATTEMPTS = 5

    # SSH deception shell (accept login after N attempts, then log commands)
    SSH_ACCEPT_AFTER = 3
    SSH_SHELL_ENABLED = True
    
    # Max connections per honeypot service
    MAX_CONNECTIONS = 100
    
    # Logging
    LOG_FILE = os.path.join(BASE_DIR, 'honeypot.log')
    LOG_LEVEL = 'INFO'
    
    # Services enabled by default
    SERVICES_ENABLED = {
        'ssh': True,
        'http': True,
        'ftp': True
    }
