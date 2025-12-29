"""
Automation scripts for batch scanning and reporting.
"""

import sys
import json
import csv
from pathlib import Path
from datetime import datetime
from typing import List

from main import WebsiteScanner


def batch_scan(urls: List[str], output_format: str = 'json') -> List[dict]:
    """
    Scan multiple URLs and save results.
    
    Args:
        urls: List of URLs to scan
        output_format: 'json' or 'csv'
        
    Returns:
        List of scan results
    """
    scanner = WebsiteScanner()
    results = []
    
    print(f"🚀 Starting batch scan of {len(urls)} URLs...\n")
    
    for i, url in enumerate(urls, 1):
        print(f"[{i}/{len(urls)}] Scanning {url}...")
        try:
            result = scanner.scan(url)
            results.append(result)
            
            risk = result.get('risk_assessment', {}).get('level', 'UNKNOWN')
            print(f"  ✓ Complete - Risk: {risk}\n")
        except Exception as e:
            print(f"  ✗ Error: {e}\n")
            results.append({'url': url, 'error': str(e)})
    
    # Save batch results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    reports_dir = Path('reports')
    reports_dir.mkdir(exist_ok=True)
    
    if output_format == 'json':
        output_file = reports_dir / f'batch_scan_{timestamp}.json'
        with output_file.open('w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"📄 Results saved to {output_file}")
    
    elif output_format == 'csv':
        output_file = reports_dir / f'batch_scan_{timestamp}.csv'
        with output_file.open('w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Domain', 'Risk Level', 'Risk Score', 'HTTPS', 'Status Code'])
            
            for result in results:
                if 'error' in result:
                    writer.writerow([result.get('url'), '', 'ERROR', '', '', ''])
                else:
                    url_info = result.get('url_info', {})
                    risk = result.get('risk_assessment', {})
                    network = result.get('network_info', {})
                    
                    writer.writerow([
                        url_info.get('original_url'),
                        url_info.get('domain'),
                        risk.get('level'),
                        risk.get('score'),
                        'Yes' if url_info.get('https_enabled') else 'No',
                        network.get('status_code'),
                    ])
        print(f"📄 Results saved to {output_file}")
    
    return results


def scan_from_file(input_file: str, output_format: str = 'json'):
    """
    Scan URLs from a text file (one URL per line).
    
    Args:
        input_file: Path to file containing URLs
        output_format: 'json' or 'csv'
    """
    file_path = Path(input_file)
    
    if not file_path.exists():
        print(f"❌ Error: File not found: {input_file}")
        return
    
    with file_path.open('r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    if not urls:
        print("❌ No URLs found in file")
        return
    
    batch_scan(urls, output_format)


def compare_scans(domain: str):
    """
    Compare all historical scans for a domain.
    
    Args:
        domain: Domain to analyze
    """
    reports_dir = Path('reports')
    
    # Find all reports for this domain
    reports = sorted(reports_dir.glob(f'{domain}_*.json'))
    
    if len(reports) < 2:
        print(f"❌ Need at least 2 scans for comparison. Found: {len(reports)}")
        return
    
    print(f"📊 Comparing {len(reports)} scans for {domain}\n")
    
    comparison = []
    for report_file in reports:
        with report_file.open('r', encoding='utf-8') as f:
            data = json.load(f)
            
            timestamp = report_file.stem.split('_', 1)[1]  # Extract timestamp
            risk = data.get('risk_assessment', {})
            
            comparison.append({
                'timestamp': timestamp,
                'risk_level': risk.get('level'),
                'risk_score': risk.get('score'),
                'https': data.get('url_info', {}).get('https_enabled'),
                'cert_days': data.get('ssl_certificate', {}).get('days_until_expiry'),
                'headers_score': data.get('security_headers', {}).get('score'),
            })
    
    # Display comparison
    print(f"{'Timestamp':<20} {'Risk':<8} {'Score':<6} {'HTTPS':<6} {'Cert Days':<10} {'Headers'}")
    print('-' * 70)
    
    for entry in comparison:
        print(f"{entry['timestamp']:<20} "
              f"{entry['risk_level']:<8} "
              f"{entry['risk_score']:<6} "
              f"{'Yes' if entry['https'] else 'No':<6} "
              f"{str(entry['cert_days'] or 'N/A'):<10} "
              f"{entry['headers_score'] or 'N/A'}%")
    
    # Trend analysis
    print("\n📈 Trend Analysis:")
    
    risk_scores = [e['risk_score'] for e in comparison if e['risk_score'] is not None]
    if len(risk_scores) >= 2:
        if risk_scores[-1] > risk_scores[0]:
            print("  ⚠️  Risk score increasing over time")
        elif risk_scores[-1] < risk_scores[0]:
            print("  ✅ Risk score decreasing over time")
        else:
            print("  ➡️  Risk score stable")


def generate_summary_report():
    """Generate a summary report of all scans."""
    from storage_utils import read_history
    
    history = read_history(limit=1000)
    
    if not history:
        print("❌ No scan history found")
        return
    
    print("="*80)
    print("📊 SECURITY SCAN SUMMARY REPORT")
    print("="*80)
    print(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Overall stats
    total = len(history)
    high_risk = sum(1 for s in history if s.get('risk_level') == 'HIGH')
    medium_risk = sum(1 for s in history if s.get('risk_level') == 'MEDIUM')
    low_risk = sum(1 for s in history if s.get('risk_level') == 'LOW')
    
    print(f"Total Scans:     {total}")
    print(f"High Risk:       {high_risk} ({high_risk/total*100:.1f}%)")
    print(f"Medium Risk:     {medium_risk} ({medium_risk/total*100:.1f}%)")
    print(f"Low Risk:        {low_risk} ({low_risk/total*100:.1f}%)")
    
    # Top domains
    from collections import Counter
    domain_counts = Counter(s['domain'] for s in history)
    
    print("\n🔝 Top 10 Scanned Domains:")
    for domain, count in domain_counts.most_common(10):
        print(f"  {count:3d}x  {domain}")
    
    # Recent high-risk
    recent_high = [s for s in history[:50] if s.get('risk_level') == 'HIGH']
    if recent_high:
        print("\n⚠️  Recent High-Risk Domains:")
        for scan in recent_high[:5]:
            print(f"  • {scan['domain']} - {scan['created_at']}")
    
    print("\n" + "="*80)


def schedule_monitoring(frequency: str, time_str: str, url: str):
    """
    Set up scheduled monitoring for a URL.
    
    Args:
        frequency: 'daily', 'weekly', or 'hourly'
        time_str: Time in HH:MM format (for daily/weekly)
        url: URL to monitor
    """
    print(f"⏰ Scheduled Monitoring Setup")
    print(f"  Frequency: {frequency}")
    print(f"  Time: {time_str}")
    print(f"  URL: {url}\n")
    
    # Create scheduled task configuration
    from pathlib import Path
    schedule_dir = Path('schedules')
    schedule_dir.mkdir(exist_ok=True)
    
    schedule_file = schedule_dir / f"monitor_{url.replace('https://', '').replace('http://', '').replace('/', '_')}.json"
    
    schedule_config = {
        'url': url,
        'frequency': frequency,
        'time': time_str,
        'created_at': datetime.now().isoformat(),
        'enabled': True,
    }
    
    with schedule_file.open('w', encoding='utf-8') as f:
        json.dump(schedule_config, f, indent=2)
    
    print(f"✅ Schedule saved to: {schedule_file}")
    print(f"\n💡 To run scheduled scans, use:")
    print(f"   python automation_scripts.py run-schedules")
    print(f"\nOr set up a system cron job/Task Scheduler to run:")
    print(f"   python automation_scripts.py run-schedules\n")


def run_scheduled_scans():
    """Execute all scheduled scans."""
    from pathlib import Path
    
    schedule_dir = Path('schedules')
    if not schedule_dir.exists():
        print("❌ No schedules directory found")
        return
    
    schedules = list(schedule_dir.glob('*.json'))
    if not schedules:
        print("❌ No scheduled scans configured")
        return
    
    print(f"🔄 Running {len(schedules)} scheduled scan(s)...\n")
    
    for schedule_file in schedules:
        with schedule_file.open('r', encoding='utf-8') as f:
            config = json.load(f)
        
        if not config.get('enabled', True):
            print(f"⏭️  Skipping disabled schedule: {schedule_file.name}")
            continue
        
        url = config['url']
        print(f"📍 Scanning: {url}")
        
        scanner = WebsiteScanner()
        try:
            result = scanner.scan(url)
            print(f"   ✅ Risk: {result['risk_assessment']['level']}")
        except Exception as e:
            print(f"   ❌ Error: {e}")
        
        print()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("""
Usage:
  python automation_scripts.py batch <url1> <url2> ...
  python automation_scripts.py batch-file <input.txt> [json|csv]
  python automation_scripts.py compare <domain>
  python automation_scripts.py summary [reports/]
  python automation_scripts.py schedule <daily|weekly|hourly> <HH:MM> <url>
  python automation_scripts.py run-schedules
        """)
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'batch':
        urls = sys.argv[2:]
        batch_scan(urls)
    
    elif command == 'batch-file':
        if len(sys.argv) < 3:
            print("❌ Missing input file")
            sys.exit(1)
        input_file = sys.argv[2]
        output_format = sys.argv[3] if len(sys.argv) > 3 else 'json'
        scan_from_file(input_file, output_format)
    
    elif command == 'compare':
        if len(sys.argv) < 3:
            print("❌ Missing domain")
            sys.exit(1)
        compare_scans(sys.argv[2])
    
    elif command == 'summary':
        reports_dir = sys.argv[2] if len(sys.argv) > 2 else None
        generate_summary_report()
    
    elif command == 'schedule':
        if len(sys.argv) < 5:
            print("❌ Usage: schedule <daily|weekly|hourly> <HH:MM> <url>")
            sys.exit(1)
        schedule_monitoring(sys.argv[2], sys.argv[3], sys.argv[4])
    
    elif command == 'run-schedules':
        run_scheduled_scans()
    
    else:
        print(f"❌ Unknown command: {command}")
        sys.exit(1)
