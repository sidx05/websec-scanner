"""
Pytest configuration and fixtures
"""
import pytest
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def sample_secure_results():
    """Sample scan results for a secure website"""
    return {
        'url_info': {
            'original_url': 'https://example.com',
            'normalized_url': 'https://example.com',
            'https_enabled': True,
            'domain': 'example.com',
            'tld': 'com',
            'phishing_indicators': []
        },
        'ssl_certificate': {
            'valid': True,
            'days_until_expiry': 365,
            'issuer': 'DigiCert Inc',
            'subject': 'example.com',
            'not_after': '2025-12-31'
        },
        'security_headers': {
            'score': 90,
            'present': [
                'strict-transport-security',
                'content-security-policy',
                'x-frame-options',
                'x-content-type-options',
                'referrer-policy'
            ],
            'missing': []
        },
        'cookies': {
            'score': 100,
            'total_count': 2,
            'secure_count': 2,
            'insecure_count': 0
        },
        'whois_info': {
            'domain_age_days': 3650,
            'registrar': 'Example Registrar',
            'status': 'clientTransferProhibited'
        },
        'dns_records': {
            'a_records': ['93.184.216.34'],
            'aaaa_records': ['2606:2800:220:1:248:1893:25c8:1946'],
            'mx_records': ['mail.example.com'],
            'ns_records': ['ns1.example.com', 'ns2.example.com']
        },
        'redirects': {
            'count': 0,
            'chain': []
        },
        'page_content': {
            'title': 'Example Domain',
            'word_count': 50,
            'has_forms': False,
            'external_links': 1
        }
    }


@pytest.fixture
def sample_insecure_results():
    """Sample scan results for an insecure website"""
    return {
        'url_info': {
            'original_url': 'http://insecure.com',
            'normalized_url': 'http://insecure.com',
            'https_enabled': False,
            'domain': 'insecure.com',
            'tld': 'tk',
            'phishing_indicators': ['Suspicious TLD: .tk']
        },
        'ssl_certificate': {},
        'security_headers': {
            'score': 0,
            'present': [],
            'missing': [
                'strict-transport-security',
                'content-security-policy',
                'x-frame-options',
                'x-content-type-options'
            ]
        },
        'cookies': {
            'score': 0,
            'total_count': 1,
            'secure_count': 0,
            'insecure_count': 1
        },
        'whois_info': {
            'domain_age_days': 3,
            'registrar': 'Unknown',
            'status': 'unknown'
        },
        'dns_records': {},
        'redirects': {
            'count': 0,
            'chain': []
        },
        'page_content': {}
    }


@pytest.fixture
def sample_headers_secure():
    """Sample secure headers"""
    return {
        'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
        'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'",
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'permissions-policy': 'geolocation=()'
    }


@pytest.fixture
def sample_headers_insecure():
    """Sample insecure headers (mostly missing)"""
    return {
        'content-type': 'text/html; charset=utf-8',
        'server': 'Apache/2.4.41 (Ubuntu)'
    }


@pytest.fixture
def sample_cookies_secure():
    """Sample secure cookies"""
    return [
        {
            'name': 'session_id',
            'value': 'abc123',
            'secure': True,
            'httponly': True,
            'samesite': 'Strict',
            'domain': 'example.com',
            'path': '/'
        },
        {
            'name': 'csrf_token',
            'value': 'xyz789',
            'secure': True,
            'httponly': True,
            'samesite': 'Lax',
            'domain': 'example.com',
            'path': '/'
        }
    ]


@pytest.fixture
def sample_cookies_insecure():
    """Sample insecure cookies"""
    return [
        {
            'name': 'tracking',
            'value': 'abc123',
            'secure': False,
            'httponly': False,
            'samesite': None,
            'domain': '.example.com',
            'path': '/'
        }
    ]
