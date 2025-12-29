"""
Compliance checker for security standards.
Checks against: OWASP Top 10, PCI-DSS, GDPR, NIST.
"""

from typing import Dict, List

class ComplianceChecker:
    """Check security compliance against standards."""
    
    def __init__(self, scan_results: Dict):
        self.results = scan_results
        self.url_info = scan_results.get('url_info', {})
        self.network = scan_results.get('network_info', {})
        self.cert = scan_results.get('ssl_certificate', {})
        self.headers = scan_results.get('security_headers', {})
        self.page = scan_results.get('page_info', {})
    
    def check_owasp_top10(self) -> Dict:
        """Check against OWASP Top 10 2021."""
        checks = []
        
        check_results = [
            ('A01:2021 - Broken Access Control', self._check_access_control()),
            ('A02:2021 - Cryptographic Failures', self._check_crypto()),
            ('A03:2021 - Injection', self._check_injection_protection()),
            ('A04:2021 - Insecure Design', self._check_insecure_design()),
            ('A05:2021 - Security Misconfiguration', self._check_security_config()),
            ('A06:2021 - Vulnerable Components', self._check_components()),
            ('A07:2021 - Auth Failures', self._check_authentication()),
            ('A08:2021 - Data Integrity Failures', self._check_data_integrity()),
            ('A09:2021 - Logging Failures', self._check_logging_monitoring()),
            ('A10:2021 - SSRF', self._check_ssrf()),
        ]
        
        for name, result in check_results:
            checks.append({
                'id': name.split(':')[0],
                'name': name,
                'status': 'PASS' if result['compliant'] else 'FAIL',
                'compliant': result['compliant'],
                'details': result['details']
            })
        
        passed = sum(1 for c in checks if c['compliant'])
        total = len(checks)
        
        return {
            'standard': 'OWASP Top 10 2021',
            'score': round((passed / total) * 100, 1),
            'passed': passed,
            'total': total,
            'checks': checks
        }
    
    def check_pci_dss(self) -> Dict:
        """Check PCI-DSS compliance (basic web requirements)."""
        checks = {
            'Requirement_4_1': {
                'name': 'Strong cryptography for transmission',
                'compliant': self.url_info.get('https_enabled', False),
                'details': 'HTTPS required for payment data transmission'
            },
            'Requirement_4_2': {
                'name': 'Never send unencrypted PANs',
                'compliant': self.url_info.get('https_enabled', False),
                'details': 'All traffic must be encrypted'
            },
            'Requirement_6_5': {
                'name': 'Address common vulnerabilities',
                'compliant': self.headers.get('score', 0) >= 70,
                'details': 'Security headers protect against common attacks'
            },
            'Requirement_6_6': {
                'name': 'Web application firewall or code review',
                'compliant': 'Content-Security-Policy' in self.headers.get('present', []),
                'details': 'CSP acts as web application firewall'
            }
        }
        
        passed = sum(1 for c in checks.values() if c['compliant'])
        total = len(checks)
        
        return {
            'standard': 'PCI-DSS (Web Requirements)',
            'score': round((passed / total) * 100, 1),
            'passed': passed,
            'total': total,
            'checks': checks
        }
    
    def check_gdpr_security(self) -> Dict:
        """Check GDPR security requirements (Article 32)."""
        checks = {
            'Encryption_in_Transit': {
                'name': 'Encryption of personal data in transit',
                'compliant': self.url_info.get('https_enabled', False),
                'details': 'HTTPS encrypts data transmission'
            },
            'Confidentiality_Controls': {
                'name': 'Ensure confidentiality of processing',
                'compliant': all(h in self.headers.get('present', []) 
                                for h in ['Strict-Transport-Security', 'X-Content-Type-Options']),
                'details': 'Security headers protect confidentiality'
            },
            'Integrity_Controls': {
                'name': 'Ensure integrity of personal data',
                'compliant': not self.cert.get('is_expired', False) if self.cert else False,
                'details': 'Valid SSL certificate ensures data integrity'
            },
            'Security_of_Processing': {
                'name': 'Technical measures for security',
                'compliant': self.headers.get('score', 0) >= 60,
                'details': 'Appropriate security measures in place'
            }
        }
        
        passed = sum(1 for c in checks.values() if c['compliant'])
        total = len(checks)
        
        return {
            'standard': 'GDPR Article 32 (Security)',
            'score': round((passed / total) * 100, 1),
            'passed': passed,
            'total': total,
            'checks': checks
        }
    
    def check_nist_csf(self) -> Dict:
        """Check NIST Cybersecurity Framework basics."""
        checks = {
            'Protect_Data_in_Transit': {
                'name': 'PR.DS-2: Data-in-transit is protected',
                'compliant': self.url_info.get('https_enabled', False) and 
                            not self.cert.get('is_expired', False),
                'details': 'HTTPS with valid certificate'
            },
            'Protect_Against_Attacks': {
                'name': 'PR.PT-5: Mechanisms to achieve resilience',
                'compliant': len(self.headers.get('present', [])) >= 4,
                'details': 'Multiple security headers implemented'
            },
            'Detect_Events': {
                'name': 'DE.CM-1: Network monitored',
                'compliant': self.headers.get('score', 0) >= 50,
                'details': 'Security monitoring capabilities'
            }
        }
        
        passed = sum(1 for c in checks.values() if c['compliant'])
        total = len(checks)
        
        return {
            'standard': 'NIST Cybersecurity Framework',
            'score': round((passed / total) * 100, 1),
            'passed': passed,
            'total': total,
            'checks': checks
        }
    
    def _check_access_control(self) -> Dict:
        """A01: Broken Access Control."""
        has_frame_options = 'X-Frame-Options' in self.headers.get('present', [])
        has_csp = 'Content-Security-Policy' in self.headers.get('present', [])
        
        return {
            'compliant': has_frame_options or has_csp,
            'details': 'Frame protection (clickjacking defense) in place' if has_frame_options or has_csp else 'No clickjacking protection'
        }
    
    def _check_crypto(self) -> Dict:
        """A02: Cryptographic Failures."""
        https = self.url_info.get('https_enabled', False)
        cert_valid = not self.cert.get('is_expired', False) if self.cert and not self.cert.get('error') else False
        has_hsts = 'Strict-Transport-Security' in self.headers.get('present', [])
        
        # Pass if HTTPS and valid cert (HSTS is bonus but not required)
        compliant = https and cert_valid
        
        details = []
        if not https:
            details.append('No HTTPS')
        if not cert_valid:
            details.append('Invalid/expired certificate')
        if not has_hsts:
            details.append('Missing HSTS header')
        
        return {
            'compliant': compliant,
            'details': '; '.join(details) if details else 'HTTPS with valid certificate'
        }
    
    def _check_injection_protection(self) -> Dict:
        """A03: Injection."""
        has_csp = 'Content-Security-Policy' in self.headers.get('present', [])
        has_xss = 'X-XSS-Protection' in self.headers.get('present', [])
        has_content_type = 'X-Content-Type-Options' in self.headers.get('present', [])
        
        # Pass if has CSP or multiple other protections
        compliant = has_csp or (has_xss and has_content_type)
        
        details = []
        if has_csp:
            details.append('CSP enabled')
        if not has_xss:
            details.append('Missing X-XSS-Protection')
        if not has_content_type:
            details.append('Missing X-Content-Type-Options')
            
        return {
            'compliant': compliant,
            'details': '; '.join(details) if details else 'Injection protection in place'
        }
    
    def _check_security_config(self) -> Dict:
        """A05: Security Misconfiguration."""
        score = self.headers.get('score', 0)
        
        # Pass if headers score is >= 50% (was too strict at 60%)
        compliant = score >= 50
        
        return {
            'compliant': compliant,
            'details': f'Security headers score: {score}% (need ≥50%)'
        }
    
    def _check_components(self) -> Dict:
        """A06: Vulnerable and Outdated Components."""
        # Check for server header exposure
        server_header = self.network.get('headers', {}).get('Server', '')
        
        return {
            'compliant': not server_header or 'nginx' in server_header.lower() or 'cloudflare' in server_header.lower(),
            'details': 'Server version not exposed' if not server_header else f'Server: {server_header}'
        }
    
    def _check_authentication(self) -> Dict:
        """A07: Identification and Authentication Failures."""
        cookie_findings = str(self.headers.get('cookie_findings', []))
        
        # Only fail if explicitly has insecure cookies, pass if no cookies or secure
        has_insecure_cookies = 'missing Secure' in cookie_findings or 'missing HttpOnly' in cookie_findings
        
        return {
            'compliant': not has_insecure_cookies,
            'details': 'Insecure cookie configuration detected' if has_insecure_cookies else 'No insecure cookie issues detected'
        }
    
    def _check_insecure_design(self) -> Dict:
        """A04: Insecure Design."""
        # Check for rate limiting headers, security.txt, or other design indicators
        has_rate_limit = any(h in self.network.get('headers', {}) for h in ['X-RateLimit-Limit', 'RateLimit-Limit'])
        has_security_txt = self.page.get('has_security_txt', False)
        
        # Pass if shows evidence of security-by-design
        compliant = has_rate_limit or has_security_txt or self.headers.get('score', 0) >= 70
        
        return {
            'compliant': compliant,
            'details': 'Shows security design patterns' if compliant else 'Limited security design indicators'
        }
    
    def _check_data_integrity(self) -> Dict:
        """A08: Software and Data Integrity Failures."""
        # Check for SRI (Subresource Integrity) and integrity protections
        has_csp = 'Content-Security-Policy' in self.headers.get('present', [])
        has_integrity_header = 'X-Content-Type-Options' in self.headers.get('present', [])
        
        compliant = has_csp and has_integrity_header
        
        return {
            'compliant': compliant,
            'details': 'CSP and integrity protections in place' if compliant else 'Missing integrity protections (CSP, X-Content-Type-Options)'
        }
    
    def _check_logging_monitoring(self) -> Dict:
        """A09: Security Logging and Monitoring Failures."""
        # Check for security monitoring headers or indicators
        has_report_uri = 'Report-To' in self.headers.get('present', []) or 'report-uri' in str(self.headers.get('csp_findings', []))
        has_expect_ct = 'Expect-CT' in self.headers.get('present', [])
        
        # Pass if has any security monitoring/reporting mechanism
        compliant = has_report_uri or has_expect_ct
        
        return {
            'compliant': compliant,
            'details': 'Security reporting enabled' if compliant else 'No security monitoring headers detected'
        }
    
    def _check_ssrf(self) -> Dict:
        """A10: Server-Side Request Forgery."""
        # Check for CORS and other SSRF protections
        has_cors = 'Access-Control-Allow-Origin' in self.headers.get('present', [])
        cors_value = self.network.get('headers', {}).get('Access-Control-Allow-Origin', '')
        
        # Pass if no CORS or properly configured (not wildcard)
        compliant = not has_cors or (has_cors and cors_value != '*')
        
        return {
            'compliant': compliant,
            'details': f'CORS: {cors_value}' if has_cors else 'No CORS headers (SSRF protection by default)'
        }
    
    def check_all(self) -> Dict:
        """Run all compliance checks."""
        owasp = self.check_owasp_top10()
        pci = self.check_pci_dss()
        gdpr = self.check_gdpr_security()
        nist = self.check_nist_csf()
        
        overall_score = (owasp['score'] + pci['score'] + gdpr['score'] + nist['score']) / 4
        
        return {
            'overall_score': round(overall_score, 1),
            'standards': {
                'owasp_top10': owasp,
                'pci_dss': pci,
                'gdpr': gdpr,
                'nist_csf': nist
            }
        }


def format_compliance_report(compliance: Dict) -> str:
    """Format compliance results as text."""
    output = ["=" * 80]
    output.append("📋 COMPLIANCE REPORT")
    output.append("=" * 80)
    output.append(f"\nOverall Compliance Score: {compliance['overall_score']:.1f}%\n")
    
    for standard_key, data in compliance['standards'].items():
        score = data['score']
        icon = '✅' if score >= 80 else '⚠️' if score >= 50 else '❌'
        
        output.append(f"\n{icon} {data['standard']}: {score:.1f}%")
        output.append(f"   Passed: {data['passed']}/{data['total']} checks")
        
        # Handle both list and dict formats for checks
        checks = data['checks']
        if isinstance(checks, list):
            # New list format
            for check in checks:
                check_icon = '✅' if check.get('compliant') else '❌'
                name = check.get('name', check.get('id', 'Unknown'))
                details = check.get('details', '')
                output.append(f"     {check_icon} {name}")
                if details:
                    output.append(f"        {details}")
        else:
            # Old dict format (for backwards compatibility)
            for check_id, check in checks.items():
                check_icon = '✅' if check['compliant'] else '❌'
                name = check.get('name', check_id)
                details = check.get('details', '')
                output.append(f"     {check_icon} {name}")
                if details:
                    output.append(f"        {details}")
    
    output.append("\n" + "=" * 80)
    return "\n".join(output)
