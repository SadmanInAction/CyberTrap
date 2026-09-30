"""HTTP attack detection rules.

Owned by Member One - the HTTP attack vector: SQL injection, cross-site
scripting, path traversal and command injection.
"""

import re

SEVERITY = {
    'SQL Injection':     'critical',
    'Command Injection': 'critical',
    'Path Traversal':    'high',
    'XSS':               'high',
}

# Weighted detection rules: category -> [(regex, confidence weight), ...].
# A higher weight means a stronger, less ambiguous indicator of that attack.
RULES = {
    'SQL Injection': [
        (r"\bunion\b[\s\S]{0,20}\bselect\b", 0.95),
        (r"\bor\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?", 0.8),
        (r"\bdrop\s+table\b", 0.95),
        (r"\binsert\s+into\b", 0.85),
        (r"\bxp_cmdshell\b", 0.95),
        (r"\bupdate\b[\s\S]{0,20}\bset\b", 0.7),
        (r"\bsleep\s*\(", 0.7),
        (r"\bbenchmark\s*\(", 0.7),
        (r"information_schema", 0.7),
        (r"--\s|/\*[\s\S]*?\*/", 0.5),
    ],
    'Command Injection': [
        (r";\s*(ls|cat|id|whoami|rm|sh|bash|cmd|dir|type|nc)\b", 0.95),
        (r"\|\s*(cat|ls|nc|bash|sh|whoami|id)\b", 0.95),
        (r"\$\([^)]*\)", 0.8),
        (r"`[^`]+`", 0.8),
        (r"\b(wget|curl)\s+https?://", 0.8),
        (r"/bin/(sh|bash)", 0.9),
        (r"\bnc\s+-e\b", 0.9),
        (r"&&", 0.55),
        (r"\|\|", 0.55),
    ],
    'Path Traversal': [
        (r"\.\./", 0.9),
        (r"\.\.\\", 0.9),
        (r"/etc/(passwd|shadow)", 0.95),
        (r"\\windows\\system32", 0.8),
        (r"\bboot\.ini\b", 0.8),
        (r"\bcmd\.exe\b", 0.7),
    ],
    'XSS': [
        (r"<script[^>]*>", 0.95),
        (r"javascript:", 0.85),
        (r"on(error|load|mouseover|click|focus)\s*=", 0.8),
        (r"\balert\s*\(", 0.6),
        (r"document\.cookie", 0.85),
        (r"<img[^>]+src\s*=", 0.6),
    ],
}

# Order used to break ties between categories that score equally.
PRIORITY = ['Command Injection', 'SQL Injection', 'Path Traversal', 'XSS']


def analyze(normalized):
    """Return a {category: score} mapping for a normalized payload."""
    scores = {}
    for category, rules in RULES.items():
        weight = 0.0
        hits = 0
        for pattern, rule_weight in rules:
            if re.search(pattern, normalized):
                hits += 1
                weight = max(weight, rule_weight)
        if hits:
            scores[category] = min(1.0, weight + 0.05 * (hits - 1))
    return scores


def rank(category, score):
    """Sort key: higher score first, then the fixed priority order."""
    priority = PRIORITY.index(category) if category in PRIORITY else 99
    return (-score, priority)
