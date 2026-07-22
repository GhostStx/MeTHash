"""
MeTHash - Feature Engineering Module
Extracts numerical features from URL strings for ML classification.
"""

import re
import math
import hashlib
from urllib.parse import urlparse

import tldextract
import validators


# ── URL shortening services list ────────────────────────────────────────────
SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly',
    'shorturl.at', 'rb.gy', 'short.link', 'cutt.ly', 'rebrand.ly',
    'soo.gd', 's2r.co', 'bl.ink', 'v.gd', '2.gp', 'tiny.cc', 'tr.im',
    'clck.ru', '0x0.st', 's.id', 'shortcm.xyz', 'x.co', 'qr.ae',
}


def extract_features(url: str) -> dict:
    """
    Extract a comprehensive set of numerical features from a single URL.

    Parameters
    ----------
    url : str
        The URL to analyze.

    Returns
    -------
    dict
        Dictionary of feature names -> values (float/int).
    """
    features = {}
    url_str = str(url).strip()
    parsed = urlparse(url_str)
    hostname = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''

    # ── 1. Basic URL properties ──────────────────────────────────────────
    features['url_len'] = len(url_str)
    features['digits_count'] = sum(c.isdigit() for c in url_str)
    features['special_chars_count'] = sum(
        1 for c in url_str if c in "!@#$%^&*()_+-=[]{}|;':\",./<>?~`"
    )

    # ── 2. Protocol & security ───────────────────────────────────────────
    features['secure_http'] = 1 if parsed.scheme == 'https' else 0

    # ── 3. Shortened URL check ───────────────────────────────────────────
    features['shortened'] = 1 if hostname.lower() in SHORTENERS else 0

    # ── 4. IP address check ──────────────────────────────────────────────
    features['have_ip'] = _is_ip_address(hostname)

    # ── 5. Character counts ──────────────────────────────────────────────
    features['nb_dots'] = url_str.count('.')
    features['nb_hyphens'] = url_str.count('-')
    features['nb_slash'] = url_str.count('/')
    features['nb_question_mark'] = url_str.count('?')
    features['nb_eq'] = url_str.count('=')
    features['nb_at'] = url_str.count('@')
    features['nb_and'] = url_str.count('&')
    features['nb_or'] = url_str.count('|')
    features['nb_hash'] = url_str.count('#')
    features['nb_percent'] = url_str.count('%')

    # ── 6. URL structure ─────────────────────────────────────────────────
    features['url_depth'] = path.count('/')
    features['hostname_len'] = len(hostname)
    features['path_len'] = len(path)
    features['query_len'] = len(query)

    # ── 7. Encoding detection ────────────────────────────────────────────
    features['is_encoded'] = 1 if re.search(r'%[0-9a-fA-F]{2}', url_str) else 0

    # ── 8. Domain-level features (via tldextract) ────────────────────────
    ext = tldextract.extract(url_str)
    domain = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain

    features['tld_length'] = len(suffix)
    features['subdomain_len'] = len(subdomain)
    features['domain_len'] = len(domain)
    features['domain_entropy'] = _shannon_entropy(domain)

    # ── 9. Hashed root domain (categorical feature hashed for tree models) ──
    full_domain = f"{domain}.{suffix}" if suffix else domain
    features['root_domain_hash'] = int(hashlib.md5(
        full_domain.encode()
    ).hexdigest(), 16) % (10 ** 8)

    # ── 10. Suspicious patterns ──────────────────────────────────────────
    # Presence of multiple subdomains (e.g., a.b.c.evil.com)
    features['nb_subdomains'] = len([s for s in subdomain.split('.') if s]) if subdomain else 0
    # Check for "suspicious" TLDs often used maliciously
    suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'loan'}
    features['suspicious_tld'] = 1 if suffix in suspicious_tlds else 0
    # Presence of "login", "verify", "secure", "update", "bank" in URL
    sensitive_words = ['login', 'verify', 'secure', 'update', 'bank', 'account',
                       'confirm', 'signin', 'webscr', 'password', 'credential']
    features['sensitive_words'] = sum(
        1 for w in sensitive_words if w in url_str.lower()
    )

    return features


def extract_features_batch(urls: list) -> list:
    """Extract features for a list of URLs."""
    return [extract_features(url) for url in urls]


def get_feature_names() -> list:
    """Return the ordered list of feature column names."""
    # Extract from a dummy URL to guarantee ordering
    dummy = extract_features('http://example.com')
    return list(dummy.keys())


# ── Internal helpers ────────────────────────────────────────────────────────

def _is_ip_address(hostname: str) -> int:
    """Return 1 if hostname is a valid IPv4 or IPv6 address."""
    try:
        if validators.ipv4(hostname) or validators.ipv6(hostname):
            return 1
    except Exception:
        pass
    # Regex fallback for IPv4
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, hostname):
        parts = hostname.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            return 1
    return 0


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy of a string (indicator of randomness)."""
    if not text:
        return 0.0
    text = str(text)
    prob = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob if p > 0)
