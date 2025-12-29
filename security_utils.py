"""
Security analysis utilities for headers, certificates, and risk scoring.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Tuple


class SecurityHeaders:
    """Important security headers to check."""
    
    IMPORTANT_HEADERS = {
        'Strict-Transport-Security': 'HSTS - Forces HTTPS',
        'Content-Security-Policy': 'CSP - Prevents XSS attacks',
        'X-Frame-Options': 'Prevents clickjacking',
        'X-Content-Type-Options': 'Prevents MIME sniffing',
        'Referrer-Policy': 'Controls referrer information',
        'Permissions-Policy': 'Controls browser features',
        'X-XSS-Protection': 'Legacy XSS protection'
    }


def analyze_security_headers(headers: dict, set_cookies: List[str] | None = None) -> dict:
    """
    Analyze HTTP security headers.
    
    Args:
        headers: Dictionary of HTTP headers
        
    Returns:
        Dictionary with analysis results
    """
    # Normalize header names (case-insensitive)
    normalized_headers = {k.lower(): v for k, v in headers.items()}
    
    analysis = {
        'present': [],
        'missing': [],
        'details': {},
        'csp_findings': [],
        'cookie_findings': []
    }
    
    for header, description in SecurityHeaders.IMPORTANT_HEADERS.items():
        header_lower = header.lower()
        
        if header_lower in normalized_headers:
            analysis['present'].append(header)
            analysis['details'][header] = {
                'value': normalized_headers[header_lower],
                'description': description
            }
        else:
            analysis['missing'].append(header)
            analysis['details'][header] = {
                'value': None,
                'description': description,
                'status': 'MISSING'
            }
    
    # Calculate score (percentage of present headers)
    total = len(SecurityHeaders.IMPORTANT_HEADERS)
    present_count = len(analysis['present'])
    analysis['score'] = round((present_count / total) * 100, 1)

    # Additional analyses
    # CSP analysis
    csp = normalized_headers.get('content-security-policy')
    if csp:
        analysis['csp_findings'] = analyze_csp_policy(csp)

    # Cookie flags analysis
    if set_cookies:
        analysis['cookie_findings'] = analyze_cookie_flags(set_cookies)
    
    return analysis


def check_https_issues(url: str, final_url: str, https_enabled: bool) -> List[str]:
    """
    Check for HTTPS-related issues.
    
    Args:
        url: Original URL
        final_url: Final URL after redirects
        https_enabled: Whether final URL uses HTTPS
        
    Returns:
        List of issue descriptions
    """
    issues = []
    
    if not https_enabled:
        issues.append("Site does not use HTTPS")
    
    # Check if started with HTTP but didn't redirect to HTTPS
    if url.startswith('http://') and final_url.startswith('http://'):
        issues.append("No HTTP to HTTPS redirect")
    
    return issues


def check_certificate_issues(cert_info: dict) -> List[str]:
    """
    Check SSL certificate for issues.
    
    Args:
        cert_info: Certificate information dictionary
        
    Returns:
        List of issue descriptions
    """
    issues = []
    
    if not cert_info:
        issues.append("No SSL certificate found")
        return issues
    
    if 'error' in cert_info:
        issues.append(f"Certificate error: {cert_info['error']}")
        return issues
    
    # Check expiration
    if cert_info.get('is_expired'):
        issues.append("Certificate is EXPIRED")
    elif cert_info.get('days_until_expiry') is not None:
        days = cert_info['days_until_expiry']
        if days < 30:
            issues.append(f"Certificate expires soon ({days} days)")
    
    return issues


def check_redirect_issues(redirect_chain: List[dict]) -> List[str]:
    """
    Check for redirect-related issues.
    
    Args:
        redirect_chain: List of redirect steps
        
    Returns:
        List of issue descriptions
    """
    issues = []
    
    if len(redirect_chain) > 3:
        issues.append(f"Excessive redirects ({len(redirect_chain)} hops)")
    
    # Check for mixed HTTP/HTTPS in redirect chain
    has_http = any('http://' in r['url'] for r in redirect_chain)
    has_https = any('https://' in r['url'] for r in redirect_chain)
    
    if has_http and has_https:
        issues.append("Mixed HTTP/HTTPS in redirect chain")
    
    return issues


def calculate_domain_age(creation_date) -> Tuple[int, str]:
    """
    Calculate domain age from creation date.
    
    Args:
        creation_date: Domain creation date (datetime or list of datetimes)
        
    Returns:
        Tuple of (days, human_readable_string)
    """
    if not creation_date:
        return None, "Unknown"
    
    # Handle list of dates (some WHOIS return multiple)
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    
    try:
        age = datetime.now() - creation_date
        days = age.days
        
        if days < 365:
            return days, f"{days} days"
        else:
            years = days // 365
            return days, f"{years} year{'s' if years > 1 else ''}"
    except Exception:
        return None, "Unknown"


def calculate_risk_score(
    https_enabled: bool,
    cert_info: dict,
    security_headers: dict,
    redirect_chain: List[dict],
    domain_age_days: int,
    is_suspicious_tld: bool,
    config: dict = None
) -> Tuple[str, List[str], int]:
    """
    Calculate overall risk score based on multiple factors.
    
    Args:
        https_enabled: Whether site uses HTTPS
        cert_info: SSL certificate information
        security_headers: Security headers analysis
        redirect_chain: Redirect chain
        domain_age_days: Domain age in days
        is_suspicious_tld: Whether TLD is suspicious
        
    Returns:
        Tuple of (risk_level, risk_factors, numeric_score)
    """
    # Load config if not provided
    if config is None:
        import yaml
        from pathlib import Path
        config_path = Path(__file__).parent / 'config.yaml'
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
    
    weights = config.get('risk_weights', {})
    thresholds = config.get('risk_thresholds', {})
    
    risk_factors = []
    score = 0  # Lower is better
    
    # HTTPS issues (high impact)
    if not https_enabled:
        risk_factors.append("No HTTPS encryption")
        score += weights.get('https_missing', 30)
    
    # Certificate issues (high impact)
    if cert_info:
        if 'error' in cert_info:
            risk_factors.append("SSL certificate error")
            score += weights.get('ssl_error', 25)
        elif cert_info.get('is_expired'):
            risk_factors.append("Expired SSL certificate")
            score += weights.get('ssl_expired', 35)
        elif cert_info.get('days_until_expiry', 999) < config.get('ssl_expiry_warning_days', 30):
            risk_factors.append("SSL certificate expiring soon")
            score += weights.get('ssl_expiring_soon', 10)
    
    # Security headers (medium impact)
    headers_score = security_headers.get('score', 0)
    headers_threshold_low = config.get('headers_score_fair', 40)
    headers_threshold_mid = config.get('headers_score_good', 60)
    
    if headers_score < headers_threshold_low:
        risk_factors.append("Most security headers missing")
        score += weights.get('headers_low', 20)
    elif headers_score < headers_threshold_mid:
        risk_factors.append("Some security headers missing")
        score += weights.get('headers_medium', 10)
    
    # Domain age (medium impact)
    if domain_age_days is not None:
        very_new = config.get('domain_age_very_new', 30)
        new = config.get('domain_age_new', 90)
        
        if domain_age_days < very_new:
            risk_factors.append(f"Very new domain (< {very_new} days)")
            score += weights.get('domain_very_new', 25)
        elif domain_age_days < new:
            risk_factors.append(f"Recently registered domain (< {new} days)")
            score += weights.get('domain_recent', 15)
    
    # Suspicious TLD (low-medium impact)
    if is_suspicious_tld:
        risk_factors.append("Suspicious top-level domain")
        score += weights.get('suspicious_tld', 15)
    
    # Excessive redirects (low impact)
    max_redirects = config.get('max_redirects', 10)
    if len(redirect_chain) > 3:
        risk_factors.append(f"Many redirects ({len(redirect_chain)})")
        score += weights.get('excessive_redirects', 10)
    
    # Determine risk level using dynamic thresholds
    high_threshold = thresholds.get('high_score', 50)
    medium_threshold = thresholds.get('medium_score', 25)
    
    if score >= high_threshold:
        risk_level = "HIGH"
    elif score >= medium_threshold:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    if not risk_factors:
        risk_factors.append("No significant issues detected")
    
    return risk_level, risk_factors, score


def get_recommended_headers() -> Dict[str, str]:
    """
    Get recommended security header configurations.
    
    Returns:
        Dictionary of header names and recommended values
    """
    return {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }


def analyze_cookie_flags(set_cookies: List[str]) -> List[str]:
    """
    Analyze Set-Cookie headers for security flags.

    Checks for Secure, HttpOnly, and SameSite on likely session cookies.
    """
    findings: List[str] = []

    for cookie in set_cookies:
        c = cookie.lower()
        # Heuristic: focus on session/auth cookies
        is_session = ('session' in c) or ('auth' in c) or ('token' in c)

        secure = 'secure' in c
        httponly = 'httponly' in c
        samesite_lax = 'samesite=lax' in c
        samesite_strict = 'samesite=strict' in c
        samesite_none = 'samesite=none' in c

        if is_session:
            if not secure:
                findings.append('Session cookie missing Secure flag')
            if not httponly:
                findings.append('Session cookie missing HttpOnly flag')
            if not (samesite_lax or samesite_strict or samesite_none):
                findings.append('Session cookie missing SameSite attribute')
            if samesite_none and not secure:
                findings.append('SameSite=None must be paired with Secure')
        else:
            # For non-session cookies, still flag risky patterns
            if samesite_none and not secure:
                findings.append('Cookie with SameSite=None without Secure')

    # Deduplicate
    return list(dict.fromkeys(findings))


def analyze_csp_policy(csp: str) -> List[str]:
    """
    Parse and analyze a Content-Security-Policy for risky directives.

    Flags usage of unsafe-inline/unsafe-eval, wildcard sources, data: URIs,
    and absence of key directives like default-src, frame-ancestors.
    """
    findings: List[str] = []

    policy = csp.strip()
    directives = [d.strip() for d in policy.split(';') if d.strip()]

    has_default = any(d.startswith('default-src') for d in directives)
    if not has_default:
        findings.append('CSP missing default-src directive')

    for d in directives:
        parts = d.split()
        if not parts:
            continue
        name = parts[0]
        values = parts[1:]

        val_str = ' '.join(values)
        if "'unsafe-inline'" in val_str:
            findings.append(f"CSP {name} allows 'unsafe-inline'")
        if "'unsafe-eval'" in val_str:
            findings.append(f"CSP {name} allows 'unsafe-eval'")
        if '*' in values:
            findings.append(f"CSP {name} uses wildcard * sources")
        if 'data:' in values:
            findings.append(f"CSP {name} allows data: URIs")
        if 'blob:' in values:
            findings.append(f"CSP {name} allows blob: URIs")

        if name == 'frame-ancestors' and not values:
            findings.append('CSP frame-ancestors directive empty')
        if name == 'script-src' and not values:
            findings.append('CSP script-src has no sources')
        if name == 'object-src' and ('none' not in values):
            findings.append("CSP object-src not set to 'none'")

    # Deduplicate
    return list(dict.fromkeys(findings))
