"""
Advanced granular scoring system with weighted factors.
Provides more nuanced differentiation between similar sites.
"""

from typing import Dict, Tuple
import math


class AdvancedScorer:
    """Granular scoring system with weighted factors."""
    
    def __init__(self, scan_results: Dict, config: Dict = None):
        """Initialize with scan results and optional config."""
        # Load config
        if config is None:
            import yaml
            from pathlib import Path
            config_path = Path(__file__).parent / 'config.yaml'
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
        
        self.config = config
        
        # Dynamic weights from config
        self.WEIGHTS = config.get('advanced_weights', {
            'https': 15,
            'ssl_quality': 15,
            'security_headers': 20,
            'certificate_validation': 10,
            'domain_reputation': 10,
            'redirect_safety': 5,
            'cookie_security': 5,
            'content_security': 10,
            'dns_security': 5,
            'response_security': 5
        })
        
        # Store scan results
        self.results = scan_results
        self.url_info = scan_results.get('url_info', {})
        self.network = scan_results.get('network_info', {})
        self.cert = scan_results.get('ssl_certificate', {})
        self.headers = scan_results.get('security_headers', {})
        self.whois = scan_results.get('whois', {})
        self.page = scan_results.get('page_info', {})
    
    def calculate_advanced_score(self) -> Dict:
        """Calculate granular weighted security score."""
        
        scores = {
            'https': self._score_https(),
            'ssl_quality': self._score_ssl_quality(),
            'security_headers': self._score_security_headers(),
            'certificate_validation': self._score_certificate_validation(),
            'domain_reputation': self._score_domain_reputation(),
            'redirect_safety': self._score_redirect_safety(),
            'cookie_security': self._score_cookie_security(),
            'content_security': self._score_content_security(),
            'dns_security': self._score_dns_security(),
            'response_security': self._score_response_security()
        }
        
        # Calculate weighted total
        weighted_total = sum(
            scores[key] * self.WEIGHTS[key] / 100
            for key in scores
        )
        
        # Convert to 0-100 scale
        final_score = weighted_total
        
        # Determine grade
        grade = self._get_grade(final_score)
        risk = self._get_risk_level(final_score)
        
        return {
            'overall_score': round(final_score, 2),
            'grade': grade,
            'risk_level': risk,
            'category_scores': {
                key: round(scores[key], 2)
                for key in scores
            },
            'weighted_breakdown': {
                key: round(scores[key] * self.WEIGHTS[key] / 100, 2)
                for key in scores
            }
        }
    
    def _score_https(self) -> float:
        """Score HTTPS implementation (0-100)."""
        if not self.url_info.get('https_enabled', False):
            return 0.0
        
        # HTTPS enabled, check quality
        score = 60.0
        
        # Bonus for HSTS
        if 'Strict-Transport-Security' in self.headers.get('present', []):
            hsts_value = self.headers.get('details', {}).get('Strict-Transport-Security', {}).get('value', '')
            
            # Check max-age
            if 'max-age' in hsts_value:
                try:
                    max_age = int(hsts_value.split('max-age=')[1].split(';')[0])
                    one_year = 31536000
                    six_months = 15768000
                    if max_age >= one_year:
                        score += 25.0
                    elif max_age >= six_months:
                        score += 15.0
                    else:
                        score += 5.0
                except:
                    score += 5.0
            
            # Bonus for includeSubDomains
            if 'includeSubDomains' in hsts_value:
                score += 10.0
            
            # Bonus for preload
            if 'preload' in hsts_value:
                score += 5.0
        else:
            score += 10.0  # Has HTTPS but no HSTS
        
        return min(score, 100.0)
    
    def _score_ssl_quality(self) -> float:
        """Score SSL certificate quality (0-100)."""
        if not self.cert or 'error' in self.cert:
            return 0.0
        
        score = 50.0
        
        # Check expiration (use dynamic thresholds)
        days = self.cert.get('days_until_expiry', 0)
        excellent = self.config.get('ssl_min_days_excellent', 365)
        good = self.config.get('ssl_min_days_good', 180)
        fair = self.config.get('ssl_min_days_fair', 90)
        warning = self.config.get('ssl_expiry_warning_days', 30)
        
        if days > excellent:
            score += 30.0
        elif days > good:
            score += 20.0
        elif days > fair:
            score += 10.0
        elif days > warning:
            score += 5.0
        elif days > 0:
            score -= 20.0
        else:
            return 0.0  # Expired
        
        # Check key strength
        # (Would need cert parsing - placeholder)
        score += 10.0
        
        # Check issuer
        issuer = self.cert.get('issuer', '')
        trusted_cas = self.config.get('trusted_cas', [
            'Let\'s Encrypt', 'DigiCert', 'Sectigo', 'GlobalSign', 'GoDaddy'
        ])
        if any(ca in issuer for ca in trusted_cas):
            score += 10.0
        
        return min(score, 100.0)
    
    def _score_security_headers(self) -> float:
        """Score security headers comprehensively (0-100)."""
        present = self.headers.get('present', [])
        details = self.headers.get('details', {})
        
        score = 0.0
        max_per_header = 100.0 / 10  # 10 important headers
        
        # Critical headers
        if 'Strict-Transport-Security' in present:
            score += max_per_header * 1.5  # Extra weight
        if 'Content-Security-Policy' in present:
            csp = details.get('Content-Security-Policy', {}).get('value', '')
            if 'default-src' in csp:
                score += max_per_header * 1.5
            else:
                score += max_per_header * 0.7
        if 'X-Frame-Options' in present:
            score += max_per_header
        if 'X-Content-Type-Options' in present:
            score += max_per_header
        
        # Important headers
        if 'Referrer-Policy' in present:
            score += max_per_header * 0.8
        if 'Permissions-Policy' in present:
            score += max_per_header * 0.8
        if 'X-XSS-Protection' in present:
            score += max_per_header * 0.5
        
        # Modern headers
        if 'Cross-Origin-Opener-Policy' in present:
            score += max_per_header * 0.6
        if 'Cross-Origin-Resource-Policy' in present:
            score += max_per_header * 0.6
        if 'Cross-Origin-Embedder-Policy' in present:
            score += max_per_header * 0.6
        
        return min(score, 100.0)
    
    def _score_certificate_validation(self) -> float:
        """Score certificate validation details (0-100)."""
        if not self.cert or 'error' in self.cert:
            return 0.0
        
        score = 70.0
        
        # Check SAN (Subject Alternative Names)
        # Check certificate chain
        # Check revocation status
        # (Placeholders - would need full cert parsing)
        
        score += 30.0
        
        return score
    
    def _score_domain_reputation(self) -> float:
        """Score domain reputation factors (0-100)."""
        score = 50.0
        
        # Domain age (dynamic thresholds)
        age_days = self.whois.get('domain_age_days')
        if age_days:
            excellent = self.config.get('domain_age_excellent', 1825)
            good = self.config.get('domain_age_good', 730)
            fair = self.config.get('domain_age_fair', 365)
            new = self.config.get('domain_age_new', 90)
            very_new = self.config.get('domain_age_very_new', 30)
            
            if age_days > excellent:
                score += 30.0
            elif age_days > good:
                score += 20.0
            elif age_days > fair:
                score += 10.0
            elif age_days > 180:
                score += 5.0
            elif age_days < very_new:
                score -= 30.0
            elif age_days < new:
                score -= 15.0
        
        # TLD reputation
        domain = self.url_info.get('domain', '')
        tld = self.url_info.get('tld', '')
        
        trusted_tlds = ['.com', '.org', '.net', '.edu', '.gov']
        suspicious_tlds = self.config.get('suspicious_tlds', [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz'
        ])
        
        if any(domain.endswith(t) for t in trusted_tlds):
            score += 10.0
        elif any(domain.endswith(t) for t in suspicious_tlds):
            score -= 25.0
        
        # IP-based domains
        if any(c.isdigit() for c in domain.replace('.', '')):
            if domain.replace('.', '').isdigit():
                score -= 30.0  # Pure IP
        
        return max(score, 0.0)
    
    def _score_redirect_safety(self) -> float:
        """Score redirect chain safety (0-100)."""
        redirect_chain = self.network.get('redirect_chain', [])
        
        if not redirect_chain:
            return 100.0
        
        score = 100.0
        
        # Penalize excessive redirects
        if len(redirect_chain) > 5:
            score -= 40.0
        elif len(redirect_chain) > 3:
            score -= 20.0
        elif len(redirect_chain) > 1:
            score -= 10.0
        
        # Check for HTTP -> HTTPS upgrade
        if redirect_chain:
            first_url = redirect_chain[0].get('url', '')
            last_url = self.network.get('final_url', '')
            
            if first_url.startswith('http://') and last_url.startswith('https://'):
                score += 10.0  # Good redirect
        
        return max(score, 0.0)
    
    def _score_cookie_security(self) -> float:
        """Score cookie security (0-100)."""
        cookie_findings = self.headers.get('cookie_findings', [])
        
        if not cookie_findings:
            return 100.0  # No cookies, no issues
        
        score = 100.0
        
        # Check for issues
        for finding in cookie_findings:
            if 'missing Secure' in finding:
                score -= 30.0
            if 'missing HttpOnly' in finding:
                score -= 30.0
            if 'missing SameSite' in finding:
                score -= 20.0
        
        return max(score, 0.0)
    
    def _score_content_security(self) -> float:
        """Score content security (0-100)."""
        score = 50.0
        
        # Check for mixed content
        html_issues = self.results.get('html_security_issues', [])
        for issue in html_issues:
            if 'mixed content' in issue.lower():
                score -= 30.0
            if 'inline script' in issue.lower():
                score -= 10.0
        
        # Check forms
        if self.page.get('form_count', 0) > 0:
            if self.url_info.get('https_enabled'):
                score += 20.0
            else:
                score -= 30.0
        
        return max(score, 0.0)
    
    def _score_dns_security(self) -> float:
        """Score DNS security (0-100)."""
        score = 50.0
        
        dns_records = self.network.get('dns_records', {})
        
        # Check for security records
        if dns_records.get('TXT'):
            score += 20.0
        if dns_records.get('MX'):
            score += 15.0
        if dns_records.get('A'):
            score += 15.0
        
        return min(score, 100.0)
    
    def _score_response_security(self) -> float:
        """Score HTTP response security (0-100)."""
        score = 50.0
        
        headers = self.network.get('headers', {})
        
        # Check for information disclosure
        if 'Server' in headers:
            server = headers['Server']
            # Penalize version disclosure
            if any(c.isdigit() for c in server):
                score -= 20.0
        else:
            score += 20.0  # Good, server hidden
        
        # Check for secure values
        if headers.get('X-Powered-By'):
            score -= 15.0  # Information disclosure
        
        if headers.get('X-AspNet-Version'):
            score -= 15.0
        
        return max(score, 0.0)
    
    def _get_grade(self, score: float) -> str:
        """Convert score to letter grade."""
        if score >= 95:
            return 'A+'
        elif score >= 90:
            return 'A'
        elif score >= 85:
            return 'A-'
        elif score >= 80:
            return 'B+'
        elif score >= 75:
            return 'B'
        elif score >= 70:
            return 'B-'
        elif score >= 65:
            return 'C+'
        elif score >= 60:
            return 'C'
        elif score >= 55:
            return 'C-'
        elif score >= 50:
            return 'D+'
        elif score >= 45:
            return 'D'
        elif score >= 40:
            return 'D-'
        else:
            return 'F'
    
    def _get_risk_level(self, score: float) -> str:
        """Convert score to risk level using dynamic thresholds."""
        thresholds = self.config.get('compliance_thresholds', {
            'excellent': 90,
            'good': 70,
            'fair': 50,
            'poor': 30
        })
        
        if score >= 80:
            return 'LOW'
        elif score >= 60:
            return 'MEDIUM'
        elif score >= 40:
            return 'HIGH'
        else:
            return 'CRITICAL'
