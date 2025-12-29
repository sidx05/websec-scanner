"""
Security dashboard API - aggregates scan data and security metrics.
"""

from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from pathlib import Path
import json

from storage_utils import read_history
from log_parser import LogParser


dashboard_app = FastAPI(title="Security Dashboard API")


@dashboard_app.get("/dashboard/overview")
def get_overview():
    """Get high-level security dashboard overview."""
    history = read_history(limit=100)
    
    total_scans = len(history)
    risk_distribution = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
    domains = set()
    
    for scan in history:
        risk = scan.get('risk_level', 'UNKNOWN')
        risk_distribution[risk] = risk_distribution.get(risk, 0) + 1
        domains.add(scan.get('domain'))
    
    # Recent activity (last 24h)
    now = datetime.now()
    recent = [s for s in history if (now - datetime.fromisoformat(s['created_at'])).days < 1]
    
    return {
        'total_scans': total_scans,
        'unique_domains': len(domains),
        'risk_distribution': risk_distribution,
        'recent_activity': {
            'last_24h': len(recent),
            'latest_scan': history[0] if history else None,
        },
        'timestamp': datetime.now().isoformat(),
    }


if __name__ == '__main__':
    import uvicorn
    print("🚀 Starting Security Dashboard API on http://127.0.0.1:8001")
    print("📊 Endpoints:")
    print("  - GET /dashboard/overview")
    print("  - GET /dashboard/risks")
    print("  - GET /dashboard/compliance")
    print("  - GET /dashboard/trends")
    print("  - GET /dashboard/top-domains")
    print("  - GET /dashboard/health")
    print("\n📖 API Docs: http://127.0.0.1:8001/docs\n")
    uvicorn.run(dashboard_app, host="127.0.0.1", port=8001)

@dashboard_app.get("/dashboard/risks")
def get_risk_summary():
    """Get detailed risk analysis."""
    history = read_history(limit=200)
    
    high_risk = [s for s in history if s.get('risk_level') == 'HIGH']
    medium_risk = [s for s in history if s.get('risk_level') == 'MEDIUM']
    
    return {
        'high_risk_domains': [
            {
                'domain': s['domain'],
                'url': s['url'],
                'score': s.get('risk_score'),
                'timestamp': s['created_at'],
            }
            for s in high_risk[:10]
        ],
        'medium_risk_domains': [
            {
                'domain': s['domain'],
                'url': s['url'],
                'score': s.get('risk_score'),
                'timestamp': s['created_at'],
            }
            for s in medium_risk[:10]
        ],
        'totals': {
            'high': len(high_risk),
            'medium': len(medium_risk),
        },
    }


@dashboard_app.get("/dashboard/logs/alerts")
def get_log_alerts(hours: int = 24):
    """Get SIEM-style log alerts."""
    parser = LogParser()
    stats = parser.parse_logs(hours=hours)
    
    return {
        'timeframe_hours': hours,
        'alerts': stats.get('alerts', []),
        'summary': parser.get_alert_summary(),
        'statistics': {
            'total_scans': stats.get('scans_completed', 0),
            'errors': stats.get('error_count', 0),
            'warnings': stats.get('warning_count', 0),
        },
    }


@dashboard_app.get("/dashboard/trends")
def get_trends():
    """Get security trends over time."""
    history = read_history(limit=500)
    
    # Group by date
    daily_stats = {}
    for scan in history:
        date = scan['created_at'][:10]  # YYYY-MM-DD
        if date not in daily_stats:
            daily_stats[date] = {'scans': 0, 'high_risk': 0, 'medium_risk': 0, 'low_risk': 0}
        
        daily_stats[date]['scans'] += 1
        risk = scan.get('risk_level', 'UNKNOWN')
        if risk == 'HIGH':
            daily_stats[date]['high_risk'] += 1
        elif risk == 'MEDIUM':
            daily_stats[date]['medium_risk'] += 1
        elif risk == 'LOW':
            daily_stats[date]['low_risk'] += 1
    
    # Sort by date
    trend_data = [
        {'date': date, **stats}
        for date, stats in sorted(daily_stats.items(), reverse=True)[:30]
    ]
    
    return {
        'daily_trends': trend_data,
        'total_days': len(daily_stats),
    }


@dashboard_app.get("/dashboard/domains/top")
def get_top_domains(limit: int = 20):
    """Get most scanned domains."""
    history = read_history(limit=1000)
    
    domain_counts = {}
    domain_risks = {}
    
    for scan in history:
        domain = scan.get('domain')
        if domain:
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
            if domain not in domain_risks:
                domain_risks[domain] = scan.get('risk_level', 'UNKNOWN')
    
    top = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    return {
        'top_domains': [
            {
                'domain': domain,
                'scan_count': count,
                'latest_risk': domain_risks.get(domain, 'UNKNOWN'),
            }
            for domain, count in top
        ],
    }

@dashboard_app.get("/dashboard/health")
def get_system_health():
    """Get system health metrics."""
    reports_dir = Path('reports')
    logs_dir = Path('logs')
    
    report_count = len(list(reports_dir.glob('*.json'))) if reports_dir.exists() else 0
    log_size = logs_dir.joinpath('app.log').stat().st_size if logs_dir.joinpath('app.log').exists() else 0
    
    # Parse recent logs for errors
    parser = LogParser()
    stats = parser.parse_logs(hours=1)
    
    health_status = 'healthy'
    if stats.get('error_count', 0) > 10:
        health_status = 'degraded'
    if len([a for a in stats.get('alerts', []) if a['severity'] in ('HIGH', 'CRITICAL')]) > 0:
        health_status = 'warning'
    
    return {
        'status': health_status,
        'metrics': {
            'stored_reports': report_count,
            'log_size_bytes': log_size,
            'recent_errors': stats.get('error_count', 0),
            'recent_scans': stats.get('scans_completed', 0),
        },
        'timestamp': datetime.now().isoformat(),
    }
