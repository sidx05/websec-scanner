"""Historical tracking and trend analysis."""
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict
import statistics


class HistoricalAnalyzer:
    """Analyze security trends over time."""
    
    def __init__(self, reports_dir: str = "reports"):
        self.reports_dir = Path(reports_dir)
    
    def get_domain_history(self, domain: str, days: int = 30) -> List[Dict]:
        """Get all scans for a domain in the last N days."""
        cutoff_date = datetime.now() - timedelta(days=days)
        scans = []
        
        for report_file in self.reports_dir.glob(f"{domain}_*.json"):
            try:
                with open(report_file) as f:
                    data = json.load(f)
                    
                    # Handle both old and new scan formats
                    if 'scan_timestamp' in data:
                        scan_date = datetime.fromisoformat(data['scan_timestamp'])
                    else:
                        # Use file modification time as fallback
                        scan_date = datetime.fromtimestamp(report_file.stat().st_mtime)
                    
                    if scan_date >= cutoff_date:
                        scans.append({
                            'timestamp': data.get('scan_timestamp') or scan_date.isoformat(),
                            'compliance_score': data.get('compliance', {}).get('overall_score', 0),
                            'risk_level': data.get('risk_assessment', {}).get('level', 'UNKNOWN'),
                            'risk_score': data.get('risk_assessment', {}).get('score', 0),
                            'recommendations_count': len(data.get('recommendations', [])),
                            'critical_issues': len([r for r in data.get('recommendations', []) if r['priority'] == 'CRITICAL']),
                            'high_issues': len([r for r in data.get('recommendations', []) if r['priority'] == 'HIGH']),
                            'file': str(report_file)
                        })
            except Exception as e:
                print(f"Error reading {report_file}: {e}")
        
        return sorted(scans, key=lambda x: x['timestamp'])
    
    def calculate_trends(self, history: List[Dict]) -> Dict:
        """Calculate trend statistics."""
        if len(history) < 2:
            return {'error': 'Insufficient data for trend analysis (need at least 2 scans)'}
        
        # Extract time series data
        compliance_scores = [s['compliance_score'] for s in history]
        risk_scores = [s['risk_score'] for s in history]
        critical_counts = [s['critical_issues'] for s in history]
        
        # Calculate trends
        compliance_trend = self._calculate_slope(compliance_scores)
        risk_trend = self._calculate_slope(risk_scores)
        
        return {
            'scan_count': len(history),
            'date_range': {
                'start': history[0]['timestamp'],
                'end': history[-1]['timestamp']
            },
            'compliance': {
                'current': compliance_scores[-1],
                'average': statistics.mean(compliance_scores),
                'min': min(compliance_scores),
                'max': max(compliance_scores),
                'trend': 'improving' if compliance_trend > 0 else 'declining' if compliance_trend < 0 else 'stable',
                'change': compliance_scores[-1] - compliance_scores[0]
            },
            'risk': {
                'current': risk_scores[-1],
                'average': statistics.mean(risk_scores),
                'trend': 'improving' if risk_trend < 0 else 'worsening' if risk_trend > 0 else 'stable',
                'change': risk_scores[-1] - risk_scores[0]
            },
            'critical_issues': {
                'current': critical_counts[-1],
                'average': statistics.mean(critical_counts),
                'max': max(critical_counts),
                'trend': 'improving' if critical_counts[-1] < critical_counts[0] else 'worsening'
            }
        }
    
    def _calculate_slope(self, values: List[float]) -> float:
        """Calculate simple linear trend (slope)."""
        n = len(values)
        if n < 2:
            return 0.0
        
        x = list(range(n))
        x_mean = statistics.mean(x)
        y_mean = statistics.mean(values)
        
        numerator = sum((x[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        return numerator / denominator if denominator != 0 else 0.0
    
    def generate_chart_data(self, history: List[Dict]) -> Dict:
        """Generate data for charting libraries."""
        return {
            'labels': [s['timestamp'][:10] for s in history],  # Dates
            'datasets': {
                'compliance': [s['compliance_score'] for s in history],
                'risk': [s['risk_score'] for s in history],
                'critical_issues': [s['critical_issues'] for s in history],
                'high_issues': [s['high_issues'] for s in history]
            }
        }
    
    def get_all_domains(self) -> List[str]:
        """Get list of all scanned domains."""
        domains = set()
        for report_file in self.reports_dir.glob("*.json"):
            # Extract domain from filename (domain_YYYYMMDD_HHMMSS.json)
            parts = report_file.stem.split('_')
            if len(parts) >= 3:
                domain = '_'.join(parts[:-2])  # Everything except timestamp
                domains.add(domain)
        return sorted(list(domains))
    
    def generate_multi_domain_comparison(self, domains: List[str] = None, days: int = 7) -> Dict:
        """Compare multiple domains over time."""
        if domains is None:
            domains = self.get_all_domains()[:5]  # Top 5 domains
        
        comparison = {}
        for domain in domains:
            history = self.get_domain_history(domain, days)
            if history:
                trends = self.calculate_trends(history)
                comparison[domain] = {
                    'current_compliance': history[-1]['compliance_score'],
                    'current_risk': history[-1]['risk_level'],
                    'trend': trends.get('compliance', {}).get('trend', 'unknown'),
                    'scan_count': len(history)
                }
        
        return comparison


def format_trends_report(trends: Dict) -> str:
    """Format trends as readable text."""
    if 'error' in trends:
        return f"Error: {trends['error']}"
    
    report = f"""
HISTORICAL TREND ANALYSIS
{'='*70}

Scan Period: {trends['date_range']['start'][:10]} to {trends['date_range']['end'][:10]}
Total Scans: {trends['scan_count']}

COMPLIANCE SCORE
  Current:  {trends['compliance']['current']:.1f}%
  Average:  {trends['compliance']['average']:.1f}%
  Range:    {trends['compliance']['min']:.1f}% - {trends['compliance']['max']:.1f}%
  Change:   {trends['compliance']['change']:+.1f}%
  Trend:    {trends['compliance']['trend'].upper()}

RISK SCORE
  Current:  {trends['risk']['current']}
  Average:  {trends['risk']['average']:.1f}
  Change:   {trends['risk']['change']:+.1f}
  Trend:    {trends['risk']['trend'].upper()}

CRITICAL ISSUES
  Current:  {trends['critical_issues']['current']}
  Average:  {trends['critical_issues']['average']:.1f}
  Peak:     {trends['critical_issues']['max']}
  Trend:    {trends['critical_issues']['trend'].upper()}
"""
    return report
