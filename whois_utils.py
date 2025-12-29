"""
WHOIS lookup utilities.
"""

import whois

# python-whois variants may expose different exception names
try:  # Preferred
    from whois.parser import PywhoisError  # type: ignore
except Exception:  # Fallback for newer versions without PywhoisError
    class PywhoisError(Exception):
        pass
from datetime import datetime
from typing import Optional, Dict


def get_whois_info(domain: str) -> Dict:
    """
    Perform WHOIS lookup and extract registration information.
    
    Args:
        domain: Domain name (without http/https)
        
    Returns:
        Dictionary with WHOIS information
    """
    info = {
        'registrar': None,
        'creation_date': None,
        'expiration_date': None,
        'updated_date': None,
        'name_servers': [],
        'status': [],
        'registrant': None,
        'error': None
    }
    
    try:
        w = whois.whois(domain)
        
        # Registrar
        info['registrar'] = w.registrar
        
        # Dates - handle both single date and list of dates
        info['creation_date'] = _normalize_date(w.creation_date)
        info['expiration_date'] = _normalize_date(w.expiration_date)
        info['updated_date'] = _normalize_date(w.updated_date)
        
        # Name servers
        if w.name_servers:
            if isinstance(w.name_servers, list):
                info['name_servers'] = [str(ns).lower() for ns in w.name_servers]
            else:
                info['name_servers'] = [str(w.name_servers).lower()]
        
        # Status
        if w.status:
            if isinstance(w.status, list):
                info['status'] = w.status
            else:
                info['status'] = [w.status]
        
        # Registrant (if available)
        if hasattr(w, 'registrant_name'):
            info['registrant'] = w.registrant_name
        
    except PywhoisError as e:
        info['error'] = f"WHOIS lookup failed: {str(e)}"
    except Exception as e:
        info['error'] = f"WHOIS error: {str(e)}"
    
    return info


def _normalize_date(date_value) -> Optional[datetime]:
    """
    Normalize date value (can be datetime, list of datetimes, or None).
    
    Args:
        date_value: Date value from WHOIS
        
    Returns:
        Single datetime object or None
    """
    if not date_value:
        return None
    
    if isinstance(date_value, list):
        # Return first non-None date
        for d in date_value:
            if d:
                return d
        return None
    
    return date_value
