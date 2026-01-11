"""
Main scanner application that orchestrates all modules.
"""

import sys
import json
import csv
from datetime import datetime
from pathlib import Path

# Import our modules
import url_utils
import network_utils
import security_utils
import parser
import whois_utils
import ui
import logging

RAW_MODE = '--raw' in sys.argv or '-r' in sys.argv

try:
    from config import get_config
    CONFIG = get_config()
except Exception:
    CONFIG = {}

try:
    from logging_utils import setup_logging
    setup_logging()
except Exception:
    pass
from storage_utils import save_report_and_history
from recommendations import generate_recommendations
from compliance import ComplianceChecker


class WebsiteScanner:
    """Main scanner class that coordinates all analysis modules."""
    
    def __init__(self):
        self.results = {}
    
    def scan(self, url: str) -> dict:
        """
        Perform complete website scan.
        
        Args:
            url: Website URL to scan
            
        Returns:
            Dictionary with all scan results
        """
        logging.info(f"Scanning: {url}")
        if not RAW_MODE:
            print(f"\nScanning: {url}")
            print("Please wait, this may take a few seconds...\n")
        else:
            print(f"SCAN: {url}")
        
        # Step 1: Validate and normalize URL
        logging.debug("Validating URL...")
        if not RAW_MODE:
            print("-> Validating URL...")
        try:
            normalized_url = url_utils.normalize_url(url)
            is_valid, error = url_utils.validate_url_format(normalized_url)
            # Even if validation fails, try to continue - log the warning
            if not is_valid:
                logging.warning(f"URL validation warning: {error}")
                # Still continue with the scan
        except Exception as e:
            # Try to continue anyway with original URL
            logging.warning(f"URL normalization failed: {e}, using original URL")
            normalized_url = url if url.startswith(('http://', 'https://')) else 'https://' + url
        
        # Step 2: Extract domain
        logging.debug("Extracting domain information...")
        domain_info = url_utils.extract_domain(normalized_url)
        domain = domain_info['registered_domain']
        
        # Check for phishing techniques
        phishing_indicators = []
        from urllib.parse import urlparse
        parsed = urlparse(normalized_url)
        
        # Check for @ symbol (user:pass@host phishing)
        if '@' in parsed.netloc:
            fake_domain = parsed.netloc.split('@')[0].split(':')[-1] if ':' in parsed.netloc.split('@')[0] else parsed.netloc.split('@')[0]
            real_domain = parsed.netloc.split('@')[-1].split(':')[0]
            phishing_indicators.append(f"URL uses @ symbol phishing technique - shows '{fake_domain}' but actually goes to '{real_domain}'")
        
        self.results['url_info'] = {
            'original_url': url,
            'normalized_url': normalized_url,
            'domain': domain,
            'subdomain': domain_info['subdomain'],
            'tld': domain_info['suffix'],
            'phishing_indicators': phishing_indicators
        }
        
        # Step 3: DNS Lookups
        logging.debug("Performing DNS lookups...")
        try:
            dns_records = network_utils.perform_dns_lookup(domain)
            ip_address = network_utils.resolve_ip_address(domain)
            
            self.results['network_info'] = {
                'dns_records': dns_records,
                'ip_address': ip_address
            }
        except Exception as e:
            self.results['network_info'] = {'error': str(e)}
        
        # Step 4: Fetch HTTP information
        logging.debug("Fetching HTTP response...")
        try:
            http_info = network_utils.fetch_http_info(normalized_url)
            
            if http_info.error:
                self.results['network_info']['http_error'] = http_info.error
                # Set final_url to original URL when there's an error
                self.results['url_info']['final_url'] = normalized_url
                self.results['url_info']['redirect_count'] = 0
            else:
                self.results['network_info'].update({
                    'status_code': http_info.status_code,
                    'final_url': http_info.final_url,
                    'response_time': http_info.response_time,
                    'redirect_chain': http_info.redirect_chain,
                    'headers': http_info.headers
                })
                
                self.results['url_info']['final_url'] = http_info.final_url
                self.results['url_info']['https_enabled'] = http_info.https_enabled
                self.results['url_info']['redirect_count'] = len(http_info.redirect_chain)
        except Exception as e:
            self.results['network_info']['http_error'] = str(e)
            # Set final_url to original URL when there's an exception
            self.results['url_info']['final_url'] = normalized_url
            self.results['url_info']['redirect_count'] = 0
        
        # Step 5: SSL Certificate check
        logging.debug("Checking SSL certificate...")
        try:
            cert_info = network_utils.get_ssl_certificate(domain)
            self.results['ssl_certificate'] = cert_info
        except Exception as e:
            self.results['ssl_certificate'] = {'error': str(e)}
        
        # Step 6: WHOIS lookup
        logging.debug("Performing WHOIS lookup...")
        try:
            whois_info = whois_utils.get_whois_info(domain)
            
            # Calculate domain age
            if whois_info.get('creation_date'):
                domain_age_days, domain_age_str = security_utils.calculate_domain_age(
                    whois_info['creation_date']
                )
                whois_info['domain_age'] = domain_age_str
                whois_info['domain_age_days'] = domain_age_days
            
            self.results['whois'] = whois_info
        except Exception as e:
            self.results['whois'] = {'error': str(e)}
        
        # Step 7: Parse HTML content
        logging.debug("Parsing HTML content...")
        try:
            if 'headers' in self.results.get('network_info', {}):
                # Fetch HTML content
                import httpx
                timeout = CONFIG.get('http_timeout', 10)
                verify_ssl = CONFIG.get('verify_ssl', False)
                with httpx.Client(follow_redirects=True, timeout=timeout, verify=verify_ssl) as client:
                    response = client.get(normalized_url)
                    html_content = response.text
                    
                    # Parse page
                    page_info = parser.parse_html(
                        html_content,
                        self.results['network_info']['final_url']
                    )
                    
                    # Convert PageInfo to dict
                    self.results['page_info'] = {
                        'title': page_info.title,
                        'meta_description': page_info.meta_description,
                        'canonical': page_info.canonical,
                        'og_tags': page_info.og_tags,
                        'twitter_tags': page_info.twitter_tags,
                        'word_count': page_info.word_count,
                        'page_size': page_info.page_size,
                        'internal_links': page_info.internal_links,
                        'external_links': page_info.external_links,
                        'image_count': page_info.image_count,
                        'script_count': page_info.script_count,
                        'form_count': page_info.form_count,
                        'h1_count': page_info.h1_count,
                        'language': page_info.language
                    }
                    
                    # SEO suggestions
                    self.results['seo_suggestions'] = parser.get_seo_suggestions(page_info)
                    
                    # HTML security issues
                    html_security_issues = parser.check_security_issues_in_html(
                        html_content,
                        self.results['url_info'].get('https_enabled', False)
                    )
                    self.results['html_security_issues'] = html_security_issues
                    
        except Exception as e:
            self.results['page_info'] = {'error': str(e)}
        
        # Step 8: Analyze security headers
        logging.debug("Analyzing security headers...")
        try:
            if 'headers' in self.results.get('network_info', {}):
                headers_analysis = security_utils.analyze_security_headers(
                    self.results['network_info']['headers'],
                    self.results['network_info'].get('set_cookies')
                )
                self.results['security_headers'] = headers_analysis
        except Exception as e:
            self.results['security_headers'] = {'error': str(e)}
        
        # Step 9: Calculate risk score
        logging.debug("Calculating risk score...")
        try:
            risk_level, risk_factors, risk_score = security_utils.calculate_risk_score(
                https_enabled=self.results['url_info'].get('https_enabled', False),
                cert_info=self.results.get('ssl_certificate', {}),
                security_headers=self.results.get('security_headers', {}),
                redirect_chain=self.results['network_info'].get('redirect_chain', []),
                domain_age_days=self.results.get('whois', {}).get('domain_age_days'),
                is_suspicious_tld=url_utils.is_suspicious_tld(domain_info['suffix']),
                config=CONFIG
            )
            
            self.results['risk_assessment'] = {
                'level': risk_level,
                'score': risk_score,
                'factors': risk_factors
            }
        except Exception as e:
            self.results['risk_assessment'] = {'error': str(e)}
        
        logging.info("Scan complete")

        # Generate recommendations
        try:
            self.results['recommendations'] = generate_recommendations(self.results)
        except Exception as e:
            logging.warning(f"Failed to generate recommendations: {e}")
        
        # Check compliance
        try:
            checker = ComplianceChecker(self.results)
            self.results['compliance'] = checker.check_all()
        except Exception as e:
            logging.warning(f"Failed to check compliance: {e}")
        
        # Advanced granular scoring
        try:
            from advanced_scoring import AdvancedScorer
            scorer = AdvancedScorer(self.results)
            self.results['advanced_score'] = scorer.calculate_advanced_score()
        except Exception as e:
            logging.warning(f"Failed to calculate advanced score: {e}")

        # Auto-save report and update history if enabled
        if CONFIG.get('auto_save_reports', True):
            try:
                save_report_and_history(self.results)
            except Exception as e:
                logging.warning(f"Failed to auto-save report: {e}")
        return self.results
    
    def export_json(self, filepath: str):
        """Export results to JSON file."""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"✓ Results exported to {filepath}")
    
    def export_csv(self, filepath: str):
        """Export basic results to CSV file."""
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow(['Property', 'Value'])
            
            # Flatten some key results
            url_info = self.results.get('url_info', {})
            writer.writerow(['URL', url_info.get('original_url', '')])
            writer.writerow(['Domain', url_info.get('domain', '')])
            writer.writerow(['HTTPS', 'Yes' if url_info.get('https_enabled') else 'No'])
            
            network = self.results.get('network_info', {})
            writer.writerow(['IP Address', network.get('ip_address', '')])
            writer.writerow(['Status Code', network.get('status_code', '')])
            
            whois = self.results.get('whois', {})
            writer.writerow(['Registrar', whois.get('registrar', '')])
            writer.writerow(['Domain Age', whois.get('domain_age', '')])
            
            risk = self.results.get('risk_assessment', {})
            writer.writerow(['Risk Level', risk.get('level', '')])
            writer.writerow(['Risk Score', risk.get('score', '')])
        
        print(f"✓ Results exported to {filepath}")


def main():
    """Main entry point for CLI application."""
    
    # Display disclaimer
    print("\n" + "="*80)
    print("Website Information & Security Scanner")
    print("="*80)
    print("\n⚠️  DISCLAIMER:")
    print("This tool performs only passive, legal checks:")
    print("  - Simple HTTP GET requests")
    print("  - DNS lookups")
    print("  - WHOIS queries")
    print("  - SSL certificate verification")
    print("\nIt does NOT perform:")
    print("  - Intrusive scanning (port scanning, vulnerability scanning)")
    print("  - Brute-forcing or penetration testing")
    print("  - Any illegal or harmful activities")
    print("\nUse responsibly and only on websites you own or have permission to analyze.")
    print("="*80 + "\n")
    
    # Get URL from command line or prompt
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("Enter website URL to scan: ").strip()
    
    if not url:
        print("❌ No URL provided. Exiting.")
        sys.exit(1)
    
    # Create scanner and run
    scanner = WebsiteScanner()
    results = scanner.scan(url)
    
    # Check for errors
    if 'error' in results:
        print(f"❌ Error: {results['error']}")
        sys.exit(1)
    
    # Display results
    ui.display_report_rich(results)
    
    # Ask about export
    export = input("Would you like to export results? (json/csv/no): ").strip().lower()
    
    if export in ('json', 'csv'):
        # Create reports directory
        reports_dir = Path('reports')
        reports_dir.mkdir(exist_ok=True)
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = results['url_info']['domain']
        filename = f"{domain}_{timestamp}.{export}"
        filepath = reports_dir / filename
        
        # Export
        if export == 'json':
            scanner.export_json(str(filepath))
        else:
            scanner.export_csv(str(filepath))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
