"""
Security recommendations generator.

Provides actionable fix suggestions for detected issues.
"""

from typing import List, Dict


def generate_recommendations(scan_results: Dict) -> List[Dict]:
    """
    Generate prioritized security recommendations based on scan results.
    
    Returns:
        List of recommendations with priority, issue, and fix guidance
    """
    recommendations = []
    
    url_info = scan_results.get('url_info', {})
    network = scan_results.get('network_info', {})
    cert = scan_results.get('ssl_certificate', {})
    headers = scan_results.get('security_headers', {})
    risk = scan_results.get('risk_assessment', {})
    whois = scan_results.get('whois', {})
    
    # CRITICAL: No HTTPS
    if not url_info.get('https_enabled'):
        recommendations.append({
            'priority': 'CRITICAL',
            'category': 'Encryption',
            'issue': 'Website not using HTTPS',
            'impact': 'All traffic is transmitted in plain text and can be intercepted',
            'fix': 'Obtain an SSL/TLS certificate (free from Let\'s Encrypt) and configure your web server to use HTTPS',
            'references': [
                'https://letsencrypt.org/',
                'https://www.cloudflare.com/ssl/'
            ]
        })
    
    # CRITICAL: Expired certificate
    if cert and cert.get('is_expired'):
        recommendations.append({
            'priority': 'CRITICAL',
            'category': 'SSL/TLS',
            'issue': 'SSL certificate has expired',
            'impact': 'Browsers will show security warnings, users cannot access site safely',
            'fix': 'Renew your SSL certificate immediately. Set up auto-renewal to prevent future expiration',
            'references': ['https://certbot.eff.org/']
        })
    
    # HIGH: Certificate expiring soon
    if cert and cert.get('days_until_expiry') is not None:
        days = cert['days_until_expiry']
        if 0 < days < 30:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'SSL/TLS',
                'issue': f'SSL certificate expires in {days} days',
                'impact': 'Certificate will expire soon, causing service disruption',
                'fix': 'Renew certificate before expiration. Configure automated renewal',
                'references': ['https://certbot.eff.org/']
            })
    
    # HIGH: Missing critical security headers
    missing_headers = headers.get('missing', [])
    headers_dict = headers.get('headers', {})
    critical_headers = {
        'Strict-Transport-Security': {
            'name': 'HSTS (HTTP Strict Transport Security)',
            'impact': 'Users may access site over insecure HTTP, vulnerable to SSL stripping attacks',
            'fix': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            'references': ['https://hstspreload.org/']
        },
        'Content-Security-Policy': {
            'name': 'Content-Security-Policy (CSP)',
            'impact': 'Site vulnerable to XSS (Cross-Site Scripting) attacks',
            'fix': 'Implement CSP header: Content-Security-Policy: default-src \'self\'; script-src \'self\'',
            'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP']
        },
        'X-Frame-Options': {
            'name': 'X-Frame-Options',
            'impact': 'Site vulnerable to clickjacking attacks',
            'fix': 'Add header: X-Frame-Options: DENY or SAMEORIGIN',
            'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options']
        }
    }
    
    for header, details in critical_headers.items():
        # Check if header is missing (either in missing list or not present in headers dict)
        is_missing = (header in missing_headers) or \
                    (headers_dict.get(header, {}).get('present') == False)
        
        if is_missing:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Security Headers',
                'issue': f'Missing {details["name"]} header',
                'impact': details['impact'],
                'fix': details['fix'],
                'references': details['references']
            })
    
    # CSP issues - can be a dict or a list
    csp_findings = headers.get('csp_findings', {})
    if isinstance(csp_findings, dict):
        if csp_findings.get('unsafe_inline'):
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Content Security Policy',
                'issue': 'CSP allows unsafe-inline scripts',
                'impact': 'Weakens XSS protection, allows inline scripts',
                'fix': 'Remove unsafe-inline. Use nonces or hashes for inline scripts',
                'references': ['https://content-security-policy.com/']
            })
        if csp_findings.get('unsafe_eval'):
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Content Security Policy',
                'issue': 'CSP allows unsafe-eval',
                'impact': 'Allows dynamic code evaluation, XSS risk',
                'fix': 'Remove unsafe-eval from CSP policy',
                'references': ['https://content-security-policy.com/']
            })
        if csp_findings.get('wildcards'):
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Content Security Policy',
                'issue': 'CSP uses wildcard domains',
                'impact': 'Reduces effectiveness of CSP, allows many sources',
                'fix': 'Replace wildcards with specific trusted domains',
                'references': ['https://content-security-policy.com/']
            })
    elif isinstance(csp_findings, list):
        # Legacy list format
        for finding in csp_findings:
            if 'unsafe-inline' in finding or 'unsafe-eval' in finding:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'Content Security Policy',
                    'issue': finding,
                    'impact': 'Weakens XSS protection, allows inline scripts',
                    'fix': 'Remove unsafe-inline/unsafe-eval. Use nonces or hashes for inline scripts',
                    'references': ['https://content-security-policy.com/']
                })
    
    # Cookie security - check for dict structure
    cookie_findings = headers.get('cookie_findings', {})
    if isinstance(cookie_findings, dict):
        if cookie_findings.get('insecure_cookies', 0) > 0:
            details = cookie_findings.get('details', [])
            for cookie in details:
                issues = []
                if not cookie.get('secure'):
                    issues.append('Secure')
                if not cookie.get('httponly'):
                    issues.append('HttpOnly')
                if not cookie.get('samesite'):
                    issues.append('SameSite')
                
                if issues:
                    recommendations.append({
                        'priority': 'HIGH',
                        'category': 'Cookie Security',
                        'issue': f'Cookie "{cookie.get("name", "unknown")}" missing flags: {", ".join(issues)}',
                        'impact': 'Cookies vulnerable to interception and XSS attacks',
                        'fix': f'Add missing cookie attributes: {", ".join(issues)}',
                        'references': ['https://owasp.org/www-community/controls/SecureCookieAttribute']
                    })
                    break  # Only report once for all insecure cookies
    elif isinstance(cookie_findings, list):
        # Legacy list format
        for finding in cookie_findings:
            if 'missing Secure' in finding or 'missing HttpOnly' in finding:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Cookie Security',
                    'issue': finding,
                    'impact': 'Cookies vulnerable to interception and XSS attacks',
                    'fix': 'Add Secure and HttpOnly flags to all cookies',
                    'references': ['https://owasp.org/www-community/controls/SecureCookieAttribute']
                })
    
    # HTML security issues
    html_issues = scan_results.get('html_security_issues', [])
    for issue in html_issues:
        if 'Mixed content' in issue:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Mixed Content',
                'issue': issue,
                'impact': 'HTTPS security compromised by HTTP resources',
                'fix': 'Change all resource URLs (images, scripts) to HTTPS',
                'references': ['https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content']
            })
    
    # Suspicious TLD - check both risk factors and direct TLD
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq']
    domain_tld = url_info.get('tld', '').lower()
    
    if domain_tld in suspicious_tlds:
        recommendations.append({
            'priority': 'LOW',
            'category': 'Domain Reputation',
            'issue': f'Domain uses suspicious TLD: .{domain_tld}',
            'impact': 'May be flagged by security tools, lower user trust',
            'fix': 'Consider migrating to a more reputable TLD (.com, .org, .net)',
            'references': ['https://www.spamhaus.org/statistics/tlds/']
        })
    
    # Also check risk factors for TLD mention
    if risk.get('factors'):
        for factor in risk['factors']:
            if 'Suspicious top-level domain' in factor and domain_tld not in suspicious_tlds:
                recommendations.append({
                    'priority': 'LOW',
                    'category': 'Domain Reputation',
                    'issue': 'Domain uses TLD commonly associated with spam/phishing',
                    'impact': 'May be flagged by security tools, lower user trust',
                    'fix': 'Consider migrating to a more reputable TLD (.com, .org, .net)',
                    'references': ['https://www.spamhaus.org/statistics/tlds/']
                })
    
    # Domain age
    if whois and whois.get('domain_age_days'):
        if whois['domain_age_days'] < 30:
            recommendations.append({
                'priority': 'LOW',
                'category': 'Domain Reputation',
                'issue': 'Very new domain (< 30 days old)',
                'impact': 'May be flagged as suspicious by security tools',
                'fix': 'Build domain reputation over time through consistent use and security best practices',
                'references': []
            })
    
    # Low security header score
    if headers.get('score', 0) < 50:
        recommendations.append({
            'priority': 'MEDIUM',
            'category': 'Security Headers',
            'issue': f"Low security header score: {headers.get('score')}%",
            'impact': 'Missing multiple security protections',
            'fix': 'Implement missing security headers. Use securityheaders.com to test',
            'references': ['https://securityheaders.com/', 'https://owasp.org/www-project-secure-headers/']
        })
    
    # Sort by priority
    priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    recommendations.sort(key=lambda x: priority_order.get(x['priority'], 4))
    
    return recommendations


def format_recommendations_text(recommendations: List[Dict]) -> str:
    """Format recommendations as human-readable text."""
    if not recommendations:
        return "✅ No security issues detected. Great job!\n"
    
    output = [f"🔒 SECURITY RECOMMENDATIONS ({len(recommendations)} issues found)\n"]
    output.append("=" * 80 + "\n")
    
    for i, rec in enumerate(recommendations, 1):
        priority_icon = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }.get(rec['priority'], '⚪')
        
        output.append(f"\n{i}. {priority_icon} [{rec['priority']}] {rec['category']}")
        output.append(f"   Issue: {rec['issue']}")
        output.append(f"   Impact: {rec['impact']}")
        output.append(f"   Fix: {rec['fix']}")
        
        if rec.get('references'):
            output.append(f"   References:")
            for ref in rec['references']:
                output.append(f"     • {ref}")
        output.append("")
    
    return "\n".join(output)
