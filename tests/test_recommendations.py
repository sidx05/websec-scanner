"""Unit tests for recommendations module."""
import pytest
from recommendations import generate_recommendations, format_recommendations_text


def test_generate_recommendations_https():
    """Test CRITICAL recommendation for missing HTTPS."""
    scan_results = {
        'url_info': {'https_enabled': False, 'domain': 'example.com'},
        'ssl_certificate': {},
        'security_headers': {'score': 50},
        'page_analysis': {}
    }
    
    recs = generate_recommendations(scan_results)
    
    # Should have CRITICAL recommendation for missing HTTPS
    critical = [r for r in recs if r['priority'] == 'CRITICAL']
    assert len(critical) > 0
    assert any('HTTPS' in r['issue'] for r in critical)


def test_generate_recommendations_expired_cert():
    """Test CRITICAL recommendation for expired certificate."""
    scan_results = {
        'url_info': {'https_enabled': True, 'domain': 'example.com'},
        'ssl_certificate': {'is_expired': True, 'days_until_expiry': -10},
        'security_headers': {'score': 50},
        'page_analysis': {}
    }
    
    recs = generate_recommendations(scan_results)
    
    # Should have CRITICAL recommendation for expired cert
    critical = [r for r in recs if r['priority'] == 'CRITICAL']
    assert len(critical) > 0
    assert any('expired' in r['issue'].lower() for r in critical)


def test_generate_recommendations_missing_headers():
    """Test HIGH recommendations for missing security headers."""
    scan_results = {
        'url_info': {'https_enabled': True, 'domain': 'example.com'},
        'ssl_certificate': {'is_expired': False, 'days_until_expiry': 90},
        'security_headers': {
            'score': 0,
            'headers': {
                'Strict-Transport-Security': {'present': False},
                'Content-Security-Policy': {'present': False},
                'X-Frame-Options': {'present': False}
            }
        },
        'page_analysis': {}
    }
    
    recs = generate_recommendations(scan_results)
    
    # Should have HIGH recommendations for missing headers
    high = [r for r in recs if r['priority'] == 'HIGH']
    assert len(high) >= 3
    assert any('HSTS' in r['issue'] or 'Strict-Transport-Security' in r['issue'] for r in high)
    assert any('CSP' in r['issue'] or 'Content-Security-Policy' in r['issue'] for r in high)
    assert any('X-Frame-Options' in r['issue'] for r in high)


def test_generate_recommendations_csp_unsafe():
    """Test MEDIUM recommendations for unsafe CSP patterns."""
    scan_results = {
        'url_info': {'https_enabled': True, 'domain': 'example.com'},
        'ssl_certificate': {'is_expired': False, 'days_until_expiry': 90},
        'security_headers': {
            'score': 50,
            'headers': {
                'Content-Security-Policy': {'present': True}
            },
            'csp_findings': {
                'unsafe_inline': True,
                'unsafe_eval': True,
                'wildcards': True
            }
        },
        'page_analysis': {}
    }
    
    recs = generate_recommendations(scan_results)
    
    # Should have MEDIUM recommendations for unsafe CSP
    medium = [r for r in recs if r['priority'] == 'MEDIUM']
    assert any('unsafe-inline' in r['issue'].lower() or 'unsafe-eval' in r['issue'].lower() for r in medium)


def test_generate_recommendations_cookie_security():
    """Test HIGH recommendations for insecure cookies."""
    scan_results = {
        'url_info': {'https_enabled': True, 'domain': 'example.com'},
        'ssl_certificate': {'is_expired': False, 'days_until_expiry': 90},
        'security_headers': {
            'score': 50,
            'cookie_findings': {
                'total_cookies': 2,
                'insecure_cookies': 2,
                'details': [
                    {'name': 'session', 'secure': False, 'httponly': False, 'samesite': None}
                ]
            }
        },
        'page_analysis': {}
    }
    
    recs = generate_recommendations(scan_results)
    
    # Should have HIGH recommendation for insecure cookies
    high = [r for r in recs if r['priority'] == 'HIGH']
    assert any('cookie' in r['issue'].lower() for r in high)


def test_generate_recommendations_suspicious_tld():
    """Test LOW recommendation for suspicious TLD."""
    scan_results = {
        'url_info': {'https_enabled': True, 'domain': 'example.tk', 'tld': 'tk'},
        'ssl_certificate': {'is_expired': False, 'days_until_expiry': 90},
        'security_headers': {'score': 100},
        'page_analysis': {}
    }
    
    recs = generate_recommendations(scan_results)
    
    # Should have LOW recommendation for suspicious TLD
    low = [r for r in recs if r['priority'] == 'LOW']
    assert any('TLD' in r['issue'] for r in low)


def test_generate_recommendations_low_header_score():
    """Test MEDIUM recommendation for low security header score."""
    scan_results = {
        'url_info': {'https_enabled': True, 'domain': 'example.com'},
        'ssl_certificate': {'is_expired': False, 'days_until_expiry': 90},
        'security_headers': {'score': 25},
        'page_analysis': {}
    }
    
    recs = generate_recommendations(scan_results)
    
    # Should have MEDIUM recommendation for low score
    medium = [r for r in recs if r['priority'] == 'MEDIUM']
    assert any('score' in r['issue'].lower() for r in medium)


def test_format_recommendations_text():
    """Test text formatting of recommendations."""
    recommendations = [
        {
            'priority': 'HIGH',
            'category': 'Security Headers',
            'issue': 'Missing HSTS header',
            'impact': 'SSL stripping attacks possible',
            'fix': 'Add Strict-Transport-Security header',
            'references': ['https://hstspreload.org/']
        }
    ]
    
    text = format_recommendations_text(recommendations)
    
    assert 'HIGH' in text
    assert 'Missing HSTS header' in text
    assert 'SSL stripping attacks possible' in text
    assert 'Add Strict-Transport-Security header' in text
    assert 'https://hstspreload.org/' in text


def test_empty_recommendations():
    """Test handling of scan with no issues."""
    scan_results = {
        'url_info': {'https_enabled': True, 'domain': 'example.com'},
        'ssl_certificate': {'is_expired': False, 'days_until_expiry': 365},
        'security_headers': {'score': 100, 'headers': {}},
        'page_analysis': {}
    }
    
    recs = generate_recommendations(scan_results)
    
    # Should return empty or minimal recommendations
    assert isinstance(recs, list)
    # A perfect site might still have LOW priority recommendations
    if recs:
        assert all(r['priority'] in ['LOW', 'MEDIUM'] for r in recs)


def test_recommendation_structure():
    """Test that recommendations have required fields."""
    scan_results = {
        'url_info': {'https_enabled': False, 'domain': 'example.com'},
        'ssl_certificate': {},
        'security_headers': {'score': 0},
        'page_analysis': {}
    }
    
    recs = generate_recommendations(scan_results)
    
    for rec in recs:
        assert 'priority' in rec
        assert rec['priority'] in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        assert 'category' in rec
        assert 'issue' in rec
        assert 'impact' in rec
        assert 'fix' in rec
        assert isinstance(rec.get('references', []), list)
