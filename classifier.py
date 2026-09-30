import html
import re
import urllib.parse

from config import Config
from attack_rules import http_attacks, ssh_attacks, ftp_attacks

# Response-level categories shared by every attack vector.
_BASE_SEVERITY = {
    'Brute Force': 'medium',
    'Blocked':     'medium',
    'Probing':     'low',
}


class AttackClassifier:
    """Shared detection engine.

    The engine owns payload normalization and confidence scoring. The actual
    attack signatures live in ``attack_rules`` - one module per attack vector -
    so each vector can be developed and reviewed independently.
    """

    SEVERITY = {
        **_BASE_SEVERITY,
        **http_attacks.SEVERITY,
        **ssh_attacks.SEVERITY,
        **ftp_attacks.SEVERITY,
    }

    @staticmethod
    def _normalize(payload):
        """Decode and normalize a payload so trivial evasion does not work."""
        if payload is None:
            return ''
        text = str(payload)

        # Repeatedly URL-decode to defeat single/double encoding
        for _ in range(3):
            decoded = urllib.parse.unquote(text)
            if decoded == text:
                break
            text = decoded

        text = html.unescape(text)
        text = text.replace('\x00', '')
        text = re.sub(r'\s+', ' ', text)
        return text.lower()

    @staticmethod
    def _result(category, confidence):
        return {
            'attack_type': category,
            'severity': AttackClassifier.SEVERITY.get(category, 'low'),
            'confidence': round(float(confidence), 2),
        }

    @staticmethod
    def classify_full(payload, service='unknown'):
        """Classify a payload and return type, severity and confidence."""
        normalized = AttackClassifier._normalize(payload)

        if not normalized.strip():
            return AttackClassifier._result('Probing', 0.4)

        # Authentication traffic is classified by the service it arrived on
        if service == 'ssh':
            return AttackClassifier._result(ssh_attacks.classify_auth(normalized), 0.9)

        if service == 'ftp':
            category = ftp_attacks.classify_command(normalized)
            if category:
                return AttackClassifier._result(category, 0.9)
            return AttackClassifier._result('Probing', 0.5)

        # Everything else is evaluated against the HTTP attack rules
        scores = http_attacks.analyze(normalized)
        # Drop weak, lone indicators to limit false positives
        scores = {c: s for c, s in scores.items() if s >= Config.CLASSIFIER_MIN_SCORE}
        if not scores:
            return AttackClassifier._result('Probing', 0.5)

        category = sorted(scores.items(), key=lambda item: http_attacks.rank(item[0], item[1]))[0][0]
        return AttackClassifier._result(category, scores[category])

    @staticmethod
    def classify(payload, service='unknown'):
        """Backwards-compatible helper returning (attack_type, severity)."""
        result = AttackClassifier.classify_full(payload, service)
        return result['attack_type'], result['severity']

    @staticmethod
    def get_severity(attack_type):
        return AttackClassifier.SEVERITY.get(attack_type, 'low')

    @staticmethod
    def classify_shell_command(command):
        """Classify a command typed into the fake SSH shell."""
        normalized = AttackClassifier._normalize(command)
        category = ssh_attacks.classify_command(normalized)
        confidence = 0.7 if category == 'Discovery' else 0.8
        return AttackClassifier._result(category, confidence)
