"""
Log parser and SIEM-style alert generator.

Analyzes application logs for patterns indicating security concerns.
"""

import re
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict
from collections import Counter


class LogAlert:
    """Container for log-based alerts."""
    
    def __init__(self, severity: str, message: str, count: int = 1, examples: List[str] = None):
        self.severity = severity  # LOW, MEDIUM, HIGH, CRITICAL
        self.message = message
        self.count = count
        self.examples = examples or []
        self.timestamp = datetime.now()


class LogParser:
    """Parse and analyze application logs."""
    
    def __init__(self, log_path: str = 'logs/app.log'):
        self.log_path = Path(log_path)
        self.alerts: List[LogAlert] = []
    
    def parse_logs(self, hours: int = 24) -> Dict:
        """
        Parse recent logs and generate statistics and alerts.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            Dictionary with stats and alerts
        """
        if not self.log_path.exists():
            return {'error': 'Log file not found'}
        
        cutoff = datetime.now() - timedelta(hours=hours)
        
        stats = {
            'total_lines': 0,
            'scans_started': 0,
            'scans_completed': 0,
            'http_errors': [],
            'domains_scanned': [],
            'error_count': 0,
            'warning_count': 0,
            'timeframe_hours': hours,
        }
        
        http_status_codes = Counter()
        domains = []
        errors = []
        
        with self.log_path.open('r', encoding='utf-8') as f:
            for line in f:
                stats['total_lines'] += 1
                
                # Parse timestamp
                ts_match = re.match(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                if ts_match:
                    try:
                        line_time = datetime.strptime(ts_match.group(1), '%Y-%m-%d %H:%M:%S')
                        if line_time < cutoff:
                            continue
                    except ValueError:
                        pass
                
                # Scan lifecycle
                if 'Scanning:' in line:
                    stats['scans_started'] += 1
                    # Extract domain
                    domain_match = re.search(r'Scanning: https?://([^\s/]+)', line)
                    if domain_match:
                        domains.append(domain_match.group(1))
                
                if 'Scan complete' in line:
                    stats['scans_completed'] += 1
                
                # HTTP responses
                http_match = re.search(r'"HTTP/1\.\d (\d{3}) ', line)
                if http_match:
                    code = int(http_match.group(1))
                    http_status_codes[code] += 1
                    if code >= 400:
                        stats['http_errors'].append({'code': code, 'line': line.strip()})
                
                # Errors and warnings
                if ' ERROR ' in line:
                    stats['error_count'] += 1
                    errors.append(line.strip())
                if ' WARNING ' in line:
                    stats['warning_count'] += 1
        
        stats['domains_scanned'] = list(set(domains))
        stats['http_status_distribution'] = dict(http_status_codes)
        
        # Generate alerts
        self._generate_alerts(stats, errors)
        
        stats['alerts'] = [
            {
                'severity': a.severity,
                'message': a.message,
                'count': a.count,
                'examples': a.examples[:3],
            }
            for a in self.alerts
        ]
        
        return stats
    
    def _generate_alerts(self, stats: Dict, errors: List[str]):
        """Generate alerts based on log patterns."""
        self.alerts = []
        
        # High error rate
        if stats['error_count'] > 10:
            self.alerts.append(LogAlert(
                'HIGH',
                f"High error count: {stats['error_count']} errors in {stats['timeframe_hours']}h",
                count=stats['error_count'],
                examples=errors[:3]
            ))
        
        # Many HTTP errors
        http_errors = len(stats['http_errors'])
        if http_errors > 5:
            self.alerts.append(LogAlert(
                'MEDIUM',
                f"Multiple HTTP errors: {http_errors} failed requests",
                count=http_errors,
                examples=[e['line'] for e in stats['http_errors'][:3]]
            ))
        
        # Incomplete scans
        incomplete = stats['scans_started'] - stats['scans_completed']
        if incomplete > 0:
            self.alerts.append(LogAlert(
                'LOW',
                f"Incomplete scans detected: {incomplete} scans did not complete",
                count=incomplete
            ))
        
        # High volume scanning (possible abuse)
        if stats['scans_completed'] > 100:
            self.alerts.append(LogAlert(
                'MEDIUM',
                f"High scan volume: {stats['scans_completed']} scans in {stats['timeframe_hours']}h"
            ))
        
        # Repeated 5xx errors
        server_errors = sum(count for code, count in stats.get('http_status_distribution', {}).items() if code >= 500)
        if server_errors > 5:
            self.alerts.append(LogAlert(
                'HIGH',
                f"Multiple server errors (5xx): {server_errors} occurrences"
            ))
    
    def get_alert_summary(self) -> str:
        """Generate human-readable alert summary."""
        if not self.alerts:
            return "✅ No alerts detected"
        
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_alerts = sorted(self.alerts, key=lambda a: severity_order.get(a.severity, 4))
        
        lines = [f"🚨 {len(self.alerts)} Alert(s) Detected:\n"]
        for alert in sorted_alerts:
            icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(alert.severity, '⚪')
            lines.append(f"{icon} [{alert.severity}] {alert.message}")
            if alert.examples:
                for ex in alert.examples[:2]:
                    lines.append(f"    └─ {ex[:100]}")
        
        return '\n'.join(lines)
