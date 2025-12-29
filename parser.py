"""
HTML parsing utilities for extracting page metadata and content analysis.
"""

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Tuple


class PageInfo:
    """Container for parsed page information."""
    
    def __init__(self):
        self.title = None
        self.meta_description = None
        self.canonical = None
        self.og_tags = {}
        self.twitter_tags = {}
        self.word_count = 0
        self.page_size = 0
        self.internal_links = 0
        self.external_links = 0
        self.image_count = 0
        self.script_count = 0
        self.form_count = 0
        self.h1_count = 0
        self.has_viewport = False
        self.language = None


def parse_html(html_content: str, base_url: str) -> PageInfo:
    """
    Parse HTML content and extract metadata and statistics.
    
    Args:
        html_content: Raw HTML string
        base_url: Base URL for resolving relative links
        
    Returns:
        PageInfo object with parsed data
    """
    info = PageInfo()
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Page size
        info.page_size = len(html_content.encode('utf-8'))
        
        # Title
        title_tag = soup.find('title')
        if title_tag:
            info.title = title_tag.get_text().strip()
        
        # Meta description
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc:
            info.meta_description = meta_desc.get('content', '').strip()
        
        # Canonical URL
        canonical = soup.find('link', attrs={'rel': 'canonical'})
        if canonical:
            info.canonical = canonical.get('href', '').strip()
        
        # Language
        html_tag = soup.find('html')
        if html_tag:
            info.language = html_tag.get('lang')
        
        # Viewport meta tag
        viewport = soup.find('meta', attrs={'name': 'viewport'})
        info.has_viewport = viewport is not None
        
        # OpenGraph tags
        og_tags = soup.find_all('meta', property=lambda x: x and x.startswith('og:'))
        for tag in og_tags:
            prop = tag.get('property', '').replace('og:', '')
            content = tag.get('content', '')
            info.og_tags[prop] = content
        
        # Twitter Card tags
        twitter_tags = soup.find_all('meta', attrs={'name': lambda x: x and x.startswith('twitter:')})
        for tag in twitter_tags:
            name = tag.get('name', '').replace('twitter:', '')
            content = tag.get('content', '')
            info.twitter_tags[name] = content
        
        # Word count (visible text only)
        text_content = soup.get_text(separator=' ', strip=True)
        info.word_count = len(text_content.split())
        
        # Count elements
        info.h1_count = len(soup.find_all('h1'))
        info.image_count = len(soup.find_all('img'))
        info.script_count = len(soup.find_all('script'))
        info.form_count = len(soup.find_all('form'))
        
        # Analyze links
        links = soup.find_all('a', href=True)
        base_domain = urlparse(base_url).netloc
        
        for link in links:
            href = link.get('href', '').strip()
            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue
            
            # Resolve relative URLs
            absolute_url = urljoin(base_url, href)
            link_domain = urlparse(absolute_url).netloc
            
            if link_domain == base_domain:
                info.internal_links += 1
            else:
                info.external_links += 1
        
    except Exception as e:
        # Gracefully handle parsing errors
        pass
    
    return info


def extract_all_links(html_content: str, base_url: str) -> Tuple[List[str], List[str]]:
    """
    Extract all internal and external links.
    
    Args:
        html_content: Raw HTML string
        base_url: Base URL for resolving relative links
        
    Returns:
        Tuple of (internal_links, external_links)
    """
    internal = []
    external = []
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        links = soup.find_all('a', href=True)
        base_domain = urlparse(base_url).netloc
        
        for link in links:
            href = link.get('href', '').strip()
            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue
            
            absolute_url = urljoin(base_url, href)
            link_domain = urlparse(absolute_url).netloc
            
            if link_domain == base_domain:
                internal.append(absolute_url)
            else:
                external.append(absolute_url)
    
    except Exception:
        pass
    
    return internal, external


def analyze_forms(html_content: str, base_url: str) -> List[Dict]:
    """
    Analyze forms on the page.
    
    Args:
        html_content: Raw HTML string
        base_url: Base URL
        
    Returns:
        List of form information dictionaries
    """
    forms = []
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        form_tags = soup.find_all('form')
        
        for form in form_tags:
            form_info = {
                'method': form.get('method', 'GET').upper(),
                'action': form.get('action', ''),
                'has_password': bool(form.find('input', type='password')),
                'input_count': len(form.find_all('input')),
            }
            
            # Check if action URL is absolute or relative
            if form_info['action']:
                form_info['action'] = urljoin(base_url, form_info['action'])
            
            forms.append(form_info)
    
    except Exception:
        pass
    
    return forms


def check_security_issues_in_html(html_content: str, is_https: bool) -> List[str]:
    """
    Check for security issues in HTML content.
    
    Args:
        html_content: Raw HTML string
        is_https: Whether page is served over HTTPS
        
    Returns:
        List of security issues found
    """
    issues = []
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Check for mixed content (HTTP resources on HTTPS page)
        if is_https:
            # Check images
            for img in soup.find_all('img', src=True):
                if img['src'].startswith('http://'):
                    issues.append("Mixed content: HTTP images on HTTPS page")
                    break
            
            # Check scripts
            for script in soup.find_all('script', src=True):
                if script['src'].startswith('http://'):
                    issues.append("Mixed content: HTTP scripts on HTTPS page")
                    break
        
        # Check for forms submitting over HTTP
        for form in soup.find_all('form'):
            action = form.get('action', '')
            if action.startswith('http://'):
                issues.append("Insecure form: Submits data over HTTP")
                break
        
        # Check for inline JavaScript (potential XSS risk)
        inline_scripts = soup.find_all('script', src=False)
        if len(inline_scripts) > 10:
            issues.append(f"Many inline scripts ({len(inline_scripts)}) - potential XSS risk")
    
    except Exception:
        pass
    
    return issues


def get_seo_suggestions(page_info: PageInfo) -> List[str]:
    """
    Generate SEO suggestions based on page analysis.
    
    Args:
        page_info: PageInfo object
        
    Returns:
        List of SEO suggestions
    """
    suggestions = []
    
    if not page_info.title:
        suggestions.append("Missing page title")
    elif len(page_info.title) < 30:
        suggestions.append("Page title is too short (< 30 characters)")
    elif len(page_info.title) > 60:
        suggestions.append("Page title is too long (> 60 characters)")
    
    if not page_info.meta_description:
        suggestions.append("Missing meta description")
    elif len(page_info.meta_description) < 120:
        suggestions.append("Meta description is too short (< 120 characters)")
    elif len(page_info.meta_description) > 160:
        suggestions.append("Meta description is too long (> 160 characters)")
    
    if page_info.h1_count == 0:
        suggestions.append("No H1 heading found")
    elif page_info.h1_count > 1:
        suggestions.append(f"Multiple H1 headings ({page_info.h1_count}) - should have only one")
    
    if not page_info.canonical:
        suggestions.append("Missing canonical URL")
    
    if not page_info.has_viewport:
        suggestions.append("Missing viewport meta tag (not mobile-friendly)")
    
    if not page_info.language:
        suggestions.append("Missing language attribute on <html> tag")
    
    if page_info.word_count < 300:
        suggestions.append(f"Low word count ({page_info.word_count}) - consider adding more content")
    
    return suggestions
