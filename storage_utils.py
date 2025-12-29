"""
Report storage and history management.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict
from config import get_config


def save_report_and_history(results: Dict) -> str:
    """
    Save full JSON report and append a summary entry to history.

    Returns path to saved report.
    """
    cfg = get_config()
    reports_dir = Path(cfg.get('reports_dir', 'reports'))
    reports_dir.mkdir(exist_ok=True)

    domain = results.get('url_info', {}).get('domain', 'scan')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{domain}_{timestamp}.json"
    report_path = reports_dir / filename

    with report_path.open('w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, default=str)

    # Update history index
    history_path = reports_dir / 'history.json'
    entry = {
        'domain': domain,
        'url': results.get('url_info', {}).get('original_url'),
        'final_url': results.get('url_info', {}).get('final_url'),
        'risk_level': results.get('risk_assessment', {}).get('level'),
        'risk_score': results.get('risk_assessment', {}).get('score'),
        'status_code': results.get('network_info', {}).get('status_code'),
        'created_at': datetime.now().isoformat(timespec='seconds'),
        'file': filename,
    }

    history = []
    if history_path.exists():
        try:
            with history_path.open('r', encoding='utf-8') as f:
                history = json.load(f) or []
        except Exception:
            history = []
    history.insert(0, entry)
    # Keep last 200 entries
    history = history[:200]
    with history_path.open('w', encoding='utf-8') as f:
        json.dump(history, f, indent=2)

    return str(report_path)


def read_history(limit: int = 50) -> list:
    cfg = get_config()
    history_path = Path(cfg.get('reports_dir', 'reports')) / 'history.json'
    if not history_path.exists():
        return []
    try:
        with history_path.open('r', encoding='utf-8') as f:
            items = json.load(f) or []
            return items[:limit]
    except Exception:
        return []
