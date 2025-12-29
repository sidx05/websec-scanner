"""
URL validation and normalization utilities.
"""

import re
from urllib.parse import urlparse, urlunparse
import tldextract

def normalize_url(url: str) -> str:
    """
    Normalize URL, adding scheme if missing. Accepts ANY URL format for scanning.
    
    Args:
        url: Raw URL string from user input
        
    Returns:
        Normalized URL with scheme
        
    Raises:
        ValueError: Only if URL is completely invalid
    """
    url = url.strip()
    
    if not url:
        raise ValueError("Empty URL")
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://', 'ftp://')):
        url = 'https://' + url
    
    # Parse - be very lenient
    try:
        parsed = urlparse(url)
        
        # Very basic check - just ensure we have something that looks like a host
        if not parsed.netloc and not parsed.path:
            raise ValueError(f"Cannot extract host from URL: {url}")
        
        # Reconstruct normalized URL
        normalized = urlunparse((
            parsed.scheme or 'https',
            parsed.netloc or parsed.path.split('/')[0],
            parsed.path or '/',
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        return normalized
    except Exception as e:
        # If parsing fails completely, just return the URL as-is with scheme
        if not url.startswith(('http://', 'https://')):
            return 'https://' + url
        return url

def extract_domain(url: str) -> dict:
    """
    Extract domain components from URL - handles ANY URL format.
    
    Args:
        url: Normalized URL
        
    Returns:
        Dictionary with domain, subdomain, suffix, and registered_domain
    """
    try:
        parsed = urlparse(url)
        
        # Get the hostname/netloc
        netloc = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
        
        # Handle @ symbol (phishing) - take the part after @
        if '@' in netloc:
            netloc = netloc.split('@')[-1]
        
        # Remove port if present
        if ':' in netloc:
            netloc = netloc.split(':')[0]
        
        # Extract domain parts
        extracted = tldextract.extract(netloc)
        
        # Use top_domain_under_public_suffix to avoid deprecated registered_domain
        registered = extracted.top_domain_under_public_suffix or extracted.domain or netloc
        
        return {
            'subdomain': extracted.subdomain or '',
            'domain': extracted.domain or netloc,
            'suffix': extracted.suffix or '',
            'registered_domain': registered,
            'fqdn': extracted.fqdn or netloc
        }
    except Exception as e:
        # Fallback - return whatever we can
        return {
            'subdomain': '',
            'domain': url,
            'suffix': '',
            'registered_domain': url,
            'fqdn': url
        }

def is_suspicious_tld(suffix: str) -> bool:
    """
    Check if TLD is commonly associated with suspicious sites.
    
    Args:
        suffix: Top-level domain (e.g., 'com', 'tk', 'xyz')
        
    Returns:
        True if suspicious
    """
    suspicious_tlds = [
        'tk', 'ml', 'ga', 'cf', 'gq',  # Free domains
        'xyz', 'top', 'work', 'click', 'link',  # Often used for spam
        'download', 'stream', 'win'
    ]
    
    return suffix.lower() in suspicious_tlds


def validate_url_format(url: str) -> tuple[bool, str]:
    """
    Validate URL format - EXTREMELY LENIENT to accept all URLs for scanning.
    
    Args:
        url: URL to validate
        
    Returns:
        Tuple of (is_valid, error_message) - Always returns True unless completely malformed
    """
    try:
        # Just check if we can parse it at all
        parsed = urlparse(url)
        
        # Accept http, https, and ftp
        if parsed.scheme and parsed.scheme not in ('http', 'https', 'ftp'):
            # Still allow it, just warn
            pass
        
        # Check if we have SOMETHING that resembles a host
        if not parsed.netloc and not parsed.path:
            return False, "No host or path found"
        
        # If we got here, accept it - let the network layer handle connection failures
        return True, ""
        
    except Exception as e:
        # Even on exception, try to accept it
        # Only reject if completely empty or malformed
        if url.strip():
            return True, ""  # Accept anyway, let scan handle errors
        return False, str(e)
