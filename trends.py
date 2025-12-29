"""CLI tool for historical trend analysis."""
import sys
from historical_analysis import HistoricalAnalyzer, format_trends_report
import json


def main():
    if len(sys.argv) < 2:
        print("Usage: python trends.py <domain> [days]")
        print("Example: python trends.py example.com 30")
        sys.exit(1)
    
    domain = sys.argv[1]
    days = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    
    analyzer = HistoricalAnalyzer()
    
    print(f"Analyzing {domain} over last {days} days...\n")
    
    # Get history
    history = analyzer.get_domain_history(domain, days)
    
    if not history:
        print(f"No scan history found for {domain}")
        sys.exit(1)
    
    # Calculate trends
    trends = analyzer.calculate_trends(history)
    
    # Display report
    print(format_trends_report(trends))
    
    # Generate chart data
    chart_data = analyzer.generate_chart_data(history)
    print("\nCHART DATA (for visualization):")
    print(json.dumps(chart_data, indent=2))
    
    # Show individual scans
    print(f"\n{'='*70}")
    print(f"SCAN HISTORY ({len(history)} scans)")
    print(f"{'='*70}")
    for scan in history:
        print(f"{scan['timestamp'][:10]} | Compliance: {scan['compliance_score']:.1f}% | Risk: {scan['risk_level']} | Critical: {scan['critical_issues']}")


if __name__ == '__main__':
    main()
