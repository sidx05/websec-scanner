"""
Network utilities for DNS lookups, HTTP requests, and SSL certificate checks.
Enhanced with retry logic and comprehensive error handling.
"""

import socket
import ssl
import time
import logging
import re
from datetime import datetime
from typing import Optional
import dns.resolver
import httpx
from urllib.parse import urlparse, urljoin
from retry_utils import retry_with_backoff, is_retryable_error

logger = logging.getLogger(__name__)


class NetworkInfo:
    """Container for network-related information."""
    
    def __init__(self):
        self.dns_records = {}
        self.ip_address = None
        self.redirect_chain = []
        self.final_url = None
        self.status_code = None
        self.response_time = None
        self.headers = {}
        self.set_cookies = []
        self.ssl_cert = None
        self.https_enabled = False
        self.error = None


def perform_dns_lookup(domain: str) -> dict:
    """
    Perform DNS lookups for various record types with error handling.
    
    Args:
        domain: Domain name to lookup
        
    Returns:
        Dictionary with DNS records (A, AAAA, NS, MX) and error info
    """
    records = {
        'A': [],
        'AAAA': [],
        'NS': [],
        'MX': [],
        'errors': {}
    }
    
    if not domain:
        records['errors']['general'] = "Empty domain provided"
        return records
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
    except Exception as e:
        records['errors']['general'] = f"Failed to create DNS resolver: {str(e)}"
        return records
    
    # A records (IPv4)
    try:
        answers = resolver.resolve(domain, 'A')
        records['A'] = [str(rdata) for rdata in answers]
        logger.debug(f"Found {len(records['A'])} A records for {domain}")
    except dns.resolver.NXDOMAIN:
        records['errors']['A'] = "Domain does not exist"
        logger.warning(f"Domain {domain} does not exist (NXDOMAIN)")
    except dns.resolver.NoAnswer:
        records['errors']['A'] = "No A records found"
    except dns.resolver.Timeout:
        records['errors']['A'] = "DNS query timeout"
        logger.warning(f"DNS timeout for {domain} A records")
    except Exception as e:
        records['errors']['A'] = f"Lookup failed: {str(e)}"
    
    # AAAA records (IPv6)
    try:
        answers = resolver.resolve(domain, 'AAAA')
        records['AAAA'] = [str(rdata) for rdata in answers]
    except dns.resolver.NoAnswer:
        records['errors']['AAAA'] = "No AAAA records found"
    except Exception:
        pass  # IPv6 not critical
    
    # NS records (nameservers)
    try:
        answers = resolver.resolve(domain, 'NS')
        records['NS'] = [str(rdata) for rdata in answers]
    except dns.resolver.NoAnswer:
        records['errors']['NS'] = "No NS records found"
    except Exception as e:
        records['errors']['NS'] = f"Lookup failed: {str(e)}"
    
    # MX records (mail servers)
    try:
        answers = resolver.resolve(domain, 'MX')
        records['MX'] = [f"{rdata.preference} {rdata.exchange}" for rdata in answers]
    except dns.resolver.NoAnswer:
        records['errors']['MX'] = "No MX records found"
    except Exception:
        pass  # MX not critical
    
    # Clean up empty errors dict
    if not records['errors']:
        del records['errors']
    
    return records


def extract_meta_refresh_url(html_content: str, base_url: str) -> Optional[str]:
    """
    Extract redirect URL from HTML meta refresh tag or JavaScript redirects.
    
    Args:
        html_content: HTML content as string
        base_url: Base URL for resolving relative URLs
        
    Returns:
        Redirect URL if found, None otherwise
    """
    try:
        # Pattern 1: <meta http-equiv="refresh" content="0; URL=https://example.com">
        # Handles various formats with/without quotes, spaces, etc.
        patterns = [
            r'<meta[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\']?\d+\s*;\s*url\s*=\s*["\']?([^"\'>\s]+)',
            r'<meta[^>]*content\s*=\s*["\']?\d+\s*;\s*url\s*=\s*["\']?([^"\'>\s]+)["\']?[^>]*http-equiv\s*=\s*["\']?refresh',
            # Pattern 2: JavaScript window.location redirects
            r'window\.location(?:\s*=\s*|\.\s*(?:href|replace)\s*\(\s*)["\']([^"\']+)["\']',
            r'location\.(?:href|replace)\s*(?:=\s*["\']|[\(]\s*["\'])([^"\']+)',
            r'document\.location\s*=\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html_content, re.IGNORECASE | re.DOTALL)
            if match:
                redirect_url = match.group(1).strip()
                # Remove any trailing characters
                redirect_url = redirect_url.rstrip('";\')')
                # Resolve relative URLs
                absolute_url = urljoin(base_url, redirect_url)
                redirect_type = 'meta refresh' if 'meta' in pattern else 'JavaScript'
                logger.info(f"{redirect_type} redirect detected: {base_url} -> {absolute_url}")
                return absolute_url
            
    except Exception as e:
        logger.debug(f"Error parsing redirect: {e}")
    
    return None


def fetch_http_info(url: str, timeout: int = 10, max_retries: int = 2) -> NetworkInfo:
    """
    Fetch HTTP response information with retry logic and comprehensive error handling.
    
    Args:
        url: URL to fetch
        timeout: Request timeout in seconds
        max_retries: Maximum number of retry attempts
        
    Returns:
        NetworkInfo object with response details and error info
    """
    info = NetworkInfo()
    
    for attempt in range(1, max_retries + 1):
        try:
            start_time = time.time()
            
            # Configure httpx client with sensible defaults
            with httpx.Client(
                follow_redirects=True,
                timeout=timeout,
                verify=False,  # Allow self-signed certs for scanning
                limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
            ) as client:
                response = client.get(url)
                
                info.response_time = time.time() - start_time
                info.status_code = response.status_code
                info.final_url = str(response.url)
                
                # Preserve headers
                info.headers = dict(response.headers)
                
                # Extract cookies
                try:
                    info.set_cookies = response.headers.get_list('set-cookie')
                except Exception:
                    # Fallback for single cookie header
                    sc = response.headers.get('set-cookie')
                    if sc:
                        info.set_cookies = [c.strip() for c in sc.split(',') if c.strip()]
                
                # Build redirect chain
                for resp in response.history:
                    info.redirect_chain.append({
                        'url': str(resp.url),
                        'status': resp.status_code
                    })
                
                # Check for client-side redirects (meta refresh, JavaScript) in HTML
                max_client_redirects = 3  # Limit to prevent infinite loops
                current_url = str(response.url)
                current_response = response
                client_redirect_count = 0
                visited_urls = {url, current_url}  # Track visited URLs to detect loops
                
                while 'text/html' in current_response.headers.get('content-type', '').lower():
                    try:
                        html_content = current_response.text
                        redirect_url = extract_meta_refresh_url(html_content, current_url)
                        
                        if not redirect_url or redirect_url in visited_urls:
                            break  # No redirect found or loop detected
                        
                        if client_redirect_count >= max_client_redirects:
                            logger.warning(f"Max client-side redirects ({max_client_redirects}) reached")
                            break
                        
                        # Add current page to redirect chain
                        info.redirect_chain.append({
                            'url': current_url,
                            'status': current_response.status_code,
                            'type': 'client-side'
                        })
                        
                        # Follow the redirect
                        logger.info(f"Following client-side redirect to: {redirect_url}")
                        current_response = client.get(redirect_url)
                        current_url = str(current_response.url)
                        visited_urls.add(redirect_url)
                        visited_urls.add(current_url)
                        client_redirect_count += 1
                        
                        # Update info with the new destination
                        info.final_url = current_url
                        info.status_code = current_response.status_code
                        info.https_enabled = current_response.url.scheme == 'https'
                        
                        # Add any HTTP redirects from this request
                        for resp in current_response.history:
                            info.redirect_chain.append({
                                'url': str(resp.url),
                                'status': resp.status_code
                            })
                        
                    except Exception as e:
                        logger.warning(f"Failed to follow client-side redirect: {e}")
                        break
                
                # Check protocol
                info.https_enabled = current_response.url.scheme == 'https'
                
                logger.info(f"HTTP fetch successful: {url} (status={response.status_code}, time={info.response_time:.2f}s)")
                return info
                
        except httpx.TimeoutException as e:
            info.error = f"Request timeout after {timeout}s"
            logger.warning(f"HTTP timeout for {url} (attempt {attempt}/{max_retries})")
            if attempt < max_retries:
                time.sleep(1 * attempt)  # Exponential backoff
                continue
                
        except httpx.ConnectError as e:
            info.error = f"Connection failed: {str(e)}"
            logger.warning(f"Connection error for {url} (attempt {attempt}/{max_retries}): {e}")
            if attempt < max_retries:
                time.sleep(1 * attempt)
                continue
                
        except httpx.TooManyRedirects:
            info.error = "Too many redirects (possible redirect loop)"
            logger.error(f"Redirect loop detected for {url}")
            break  # Don't retry redirect loops
            
        except httpx.InvalidURL:
            info.error = "Invalid URL format"
            logger.error(f"Invalid URL: {url}")
            break  # Don't retry invalid URLs
            
        except httpx.HTTPStatusError as e:
            info.error = f"HTTP error: {e.response.status_code}"
            info.status_code = e.response.status_code
            logger.warning(f"HTTP error {e.response.status_code} for {url}")
            break  # Don't retry HTTP errors
            
        except Exception as e:
            error_msg = str(e)
            info.error = f"Unexpected error: {error_msg}"
            logger.error(f"Unexpected error fetching {url}: {error_msg}")
            if attempt < max_retries and is_retryable_error(e):
                time.sleep(1 * attempt)
                continue
            break
    
    return info


def get_ssl_certificate(domain: str, port: int = 443, timeout: int = 10) -> Optional[dict]:
    """
    Retrieve and parse SSL certificate information with comprehensive error handling.
    
    Args:
        domain: Domain name
        port: SSL port (default 443)
        timeout: Connection timeout in seconds
        
    Returns:
        Dictionary with certificate details, error info, or None if unavailable
    """
    if not domain:
        return {'error': 'Empty domain provided'}
    
    try:
        context = ssl.create_default_context()
        
        # Attempt connection with timeout
        try:
            sock = socket.create_connection((domain, port), timeout=timeout)
        except socket.gaierror as e:
            return {'error': f'DNS resolution failed: {str(e)}'}
        except socket.timeout:
            return {'error': f'Connection timeout after {timeout}s'}
        except ConnectionRefusedError:
            return {'error': f'Connection refused on port {port}'}
        except OSError as e:
            return {'error': f'Connection error: {str(e)}'}
        
        try:
            with sock:
                with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                    cert = secure_sock.getpeercert()
                    
                    if not cert:
                        return {'error': 'No certificate received from server'}
                    
                    # Parse certificate
                    cert_info = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'sans': []
                    }
                    
                    # Extract Subject Alternative Names
                    if 'subjectAltName' in cert:
                        cert_info['sans'] = [san[1] for san in cert['subjectAltName']]
                    
                    # Check expiration status
                    try:
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                        now = datetime.now()
                        
                        cert_info['is_expired'] = not_after < now
                        cert_info['not_yet_valid'] = not_before > now
                        cert_info['days_until_expiry'] = (not_after - now).days
                        
                        if cert_info['is_expired']:
                            logger.warning(f"Certificate for {domain} expired {abs(cert_info['days_until_expiry'])} days ago")
                        elif cert_info['days_until_expiry'] < 30:
                            logger.warning(f"Certificate for {domain} expires in {cert_info['days_until_expiry']} days")
                            
                    except Exception as e:
                        cert_info['is_expired'] = None
                        cert_info['days_until_expiry'] = None
                        logger.error(f"Failed to parse certificate dates: {e}")
                    
                    logger.info(f"Retrieved SSL certificate for {domain}")
                    return cert_info
                    
        except ssl.SSLCertVerificationError as e:
            return {'error': f'Certificate verification failed: {str(e)}', 'verification_failed': True}
        except ssl.SSLError as e:
            error_msg = str(e)
            if 'CERTIFICATE_VERIFY_FAILED' in error_msg:
                return {'error': 'Certificate verification failed (self-signed or invalid)', 'verification_failed': True}
            return {'error': f'SSL error: {error_msg}'}
                
    except socket.timeout:
        return {'error': f'Connection timeout after {timeout}s'}
    except Exception as e:
        logger.error(f"Unexpected error retrieving certificate for {domain}: {e}")
        return {'error': f'Unexpected error: {str(e)}'}
    
    return {'error': 'Failed to retrieve certificate'}


def resolve_ip_address(domain: str) -> Optional[str]:
    """
    Resolve domain to IP address.
    
    Args:
        domain: Domain name
        
    Returns:
        IP address string or None
    """
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception:
        return None


def get_ip_info(ip: str) -> dict:
    """
    Get basic IP information (placeholder for offline mapping).
    
    In a full implementation, you could use a local GeoIP database
    or ASN database for offline lookups.
    
    Args:
        ip: IP address
        
    Returns:
        Dictionary with IP info (placeholder implementation)
    """
    # This is a placeholder. For full functionality, integrate:
    # - MaxMind GeoLite2 database for geolocation
    # - PyASN for ASN lookups
    # Both can work offline after initial database download
    
    return {
        'ip': ip,
        'note': 'Offline ASN/GeoIP mapping not implemented (requires local database)'
    }
