"""External API integrations for threat intelligence."""
import httpx
import hashlib
import time
from typing import Dict, Optional
import os


class VirusTotalAPI:
    """VirusTotal API integration for URL reputation checks."""
    
    def __init__(self, api_key: Optional[str] = None, config: Dict = None):
        """Initialize with API key and optional config."""
        self.api_key = api_key or os.getenv('VT_API_KEY')
        self.base_url = "https://www.virustotal.com/api/v3"
        
        # Load config for rate limits
        if config is None:
            import yaml
            from pathlib import Path
            config_path = Path(__file__).parent / 'config.yaml'
            try:
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
            except:
                config = {}
        
        self.rate_limit_delay = config.get('virustotal_rate_limit', 15)
    
    def check_url(self, url: str) -> Dict:
        """Check URL reputation on VirusTotal."""
        if not self.api_key:
            return {'error': 'VirusTotal API key not configured', 'available': False}
        
        try:
            # URL needs to be base64 encoded without padding
            url_id = self._encode_url(url)
            
            headers = {
                'x-apikey': self.api_key,
                'Accept': 'application/json'
            }
            
            # Check if URL already analyzed
            response = httpx.get(
                f"{self.base_url}/urls/{url_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_vt_response(data)
            elif response.status_code == 404:
                # URL not found, submit for analysis
                return self._submit_url(url)
            else:
                return {'error': f'VirusTotal API error: {response.status_code}', 'available': False}
        
        except Exception as e:
            return {'error': str(e), 'available': False}
    
    def _encode_url(self, url: str) -> str:
        """Encode URL for VirusTotal API."""
        import base64
        url_bytes = url.encode('utf-8')
        encoded = base64.urlsafe_b64encode(url_bytes).decode('utf-8')
        return encoded.rstrip('=')  # Remove padding
    
    def _submit_url(self, url: str) -> Dict:
        """Submit URL for analysis."""
        headers = {
            'x-apikey': self.api_key,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        response = httpx.post(
            f"{self.base_url}/urls",
            headers=headers,
            data={'url': url},
            timeout=10
        )
        
        if response.status_code == 200:
            return {
                'status': 'queued',
                'message': 'URL submitted for analysis. Check back in a few minutes.',
                'available': True
            }
        else:
            return {'error': 'Failed to submit URL', 'available': False}
    
    def _parse_vt_response(self, data: Dict) -> Dict:
        """Parse VirusTotal response."""
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        total = sum(stats.values())
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        
        return {
            'available': True,
            'scan_date': attributes.get('last_analysis_date'),
            'total_engines': total,
            'malicious': malicious,
            'suspicious': suspicious,
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'reputation': attributes.get('reputation', 0),
            'threat_level': 'HIGH' if malicious > 0 else 'MEDIUM' if suspicious > 0 else 'LOW',
            'categories': attributes.get('categories', {}),
            'permalink': f"https://www.virustotal.com/gui/url/{self._encode_url(attributes.get('url', ''))}"
        }


class SSLLabsAPI:
    """SSL Labs API for SSL/TLS configuration analysis."""
    
    def __init__(self, config: Dict = None):
        """Initialize with optional config."""
        self.base_url = "https://api.ssllabs.com/api/v3"
        
        # Load config for rate limits
        if config is None:
            import yaml
            from pathlib import Path
            config_path = Path(__file__).parent / 'config.yaml'
            try:
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
            except:
                config = {}
        
        self.rate_limit_delay = config.get('sslabs_rate_limit', 10)
    
    def analyze_ssl(self, hostname: str, from_cache: bool = True) -> Dict:
        """Analyze SSL/TLS configuration."""
        try:
            # Start analysis
            params = {
                'host': hostname,
                'fromCache': 'on' if from_cache else 'off',
                'all': 'done'
            }
            
            response = httpx.get(
                f"{self.base_url}/analyze",
                params=params,
                timeout=30
            )
            
            if response.status_code != 200:
                return {'error': f'SSL Labs API error: {response.status_code}', 'available': False}
            
            data = response.json()
            status = data.get('status')
            
            # If analysis is in progress, return status
            if status in ['DNS', 'IN_PROGRESS']:
                return {
                    'status': status,
                    'message': 'SSL analysis in progress. This may take 1-2 minutes.',
                    'available': True
                }
            
            # If complete, parse results
            if status == 'READY':
                return self._parse_ssl_labs_response(data)
            
            return {'error': f'Unexpected status: {status}', 'available': False}
        
        except Exception as e:
            return {'error': str(e), 'available': False}
    
    def _parse_ssl_labs_response(self, data: Dict) -> Dict:
        """Parse SSL Labs response."""
        endpoints = data.get('endpoints', [])
        if not endpoints:
            return {'error': 'No endpoints found', 'available': False}
        
        # Get best grade
        grades = [ep.get('grade', 'T') for ep in endpoints if ep.get('grade')]
        best_grade = min(grades) if grades else 'T'
        
        # Get protocol support
        protocols = set()
        for ep in endpoints:
            details = ep.get('details', {})
            for protocol in details.get('protocols', []):
                protocols.add(f"{protocol.get('name')} {protocol.get('version')}")
        
        return {
            'available': True,
            'grade': best_grade,
            'endpoints': len(endpoints),
            'protocols': sorted(list(protocols)),
            'certificate_chain_issues': any(ep.get('details', {}).get('certChains', [{}])[0].get('issues', 0) for ep in endpoints),
            'supports_forward_secrecy': any(ep.get('details', {}).get('forwardSecrecy', 0) > 0 for ep in endpoints),
            'vulnerable_to_heartbleed': any(ep.get('details', {}).get('heartbleed', False) for ep in endpoints),
            'vulnerable_to_poodle': any(ep.get('details', {}).get('poodle', False) for ep in endpoints),
            'report_url': f"https://www.ssllabs.com/ssltest/analyze.html?d={data.get('host')}"
        }


class ThreatIntelligence:
    """Combined threat intelligence from multiple sources."""
    
    def __init__(self, vt_api_key: Optional[str] = None, config: Dict = None):
        """Initialize with optional API keys and config."""
        self.vt = VirusTotalAPI(vt_api_key, config)
        self.ssl_labs = SSLLabsAPI(config)
    
    def enrich_scan(self, scan_results: Dict) -> Dict:
        """Enrich scan results with threat intelligence."""
        enriched = {
            'threat_intel': {
                'virustotal': {},
                'ssllabs': {}
            }
        }
        
        # VirusTotal check
        url = scan_results.get('url_info', {}).get('original_url')
        if url:
            print("Checking VirusTotal...")
            vt_result = self.vt.check_url(url)
            enriched['threat_intel']['virustotal'] = vt_result
            
            if vt_result.get('available'):
                time.sleep(self.vt.rate_limit_delay)  # Rate limiting
        
        # SSL Labs check (only for HTTPS)
        if scan_results.get('url_info', {}).get('https_enabled'):
            domain = scan_results.get('url_info', {}).get('domain')
            if domain:
                print("Checking SSL Labs...")
                ssl_result = self.ssl_labs.analyze_ssl(domain)
                enriched['threat_intel']['ssllabs'] = ssl_result
        
        return enriched


def format_threat_intel_report(threat_intel: Dict) -> str:
    """Format threat intelligence as readable text."""
    report = f"\n{'='*70}\nTHREAT INTELLIGENCE\n{'='*70}\n"
    
    # VirusTotal
    vt = threat_intel.get('virustotal', {})
    if vt.get('available'):
        report += f"\nVirusTotal:\n"
        report += f"  Threat Level: {vt.get('threat_level', 'UNKNOWN')}\n"
        report += f"  Malicious:    {vt.get('malicious', 0)}/{vt.get('total_engines', 0)} engines\n"
        report += f"  Suspicious:   {vt.get('suspicious', 0)}/{vt.get('total_engines', 0)} engines\n"
        if vt.get('permalink'):
            report += f"  Report:       {vt['permalink']}\n"
    else:
        report += f"\nVirusTotal: Not available ({vt.get('error', 'Unknown')})\n"
    
    # SSL Labs
    ssl = threat_intel.get('ssllabs', {})
    if ssl.get('available'):
        report += f"\nSSL Labs:\n"
        report += f"  Grade:                {ssl.get('grade', 'Unknown')}\n"
        report += f"  Forward Secrecy:      {'Yes' if ssl.get('supports_forward_secrecy') else 'No'}\n"
        report += f"  Heartbleed:           {'VULNERABLE' if ssl.get('vulnerable_to_heartbleed') else 'Not vulnerable'}\n"
        report += f"  POODLE:               {'VULNERABLE' if ssl.get('vulnerable_to_poodle') else 'Not vulnerable'}\n"
        if ssl.get('report_url'):
            report += f"  Full Report:          {ssl['report_url']}\n"
    else:
        report += f"\nSSL Labs: Not available ({ssl.get('error', 'Unknown')})\n"
    
    return report
