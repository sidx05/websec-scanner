"""
Automated batch scanner for multiple URLs.
Scans all URLs from a file and generates reports.
"""

import sys
import time
from pathlib import Path
from datetime import datetime
from main import WebsiteScanner
import json

def scan_urls_from_file(filepath: str, delay: float = None):
    """
    Scan multiple URLs from a text file.
    
    Args:
        filepath: Path to file containing URLs (one per line)
        delay: Delay between scans in seconds (uses config default if None)
    """
    # Load config for default delay
    if delay is None:
        import yaml
        config_path = Path(__file__).parent / 'config.yaml'
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        delay = config.get('batch_delay', 2.0)
    
    # Read URLs from file
    url_file = Path(filepath)
    if not url_file.exists():
        print(f"❌ File not found: {filepath}")
        sys.exit(1)
    
    # Parse URLs (skip comments and empty lines)
    urls = []
    with open(url_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                urls.append(line)
    
    if not urls:
        print("❌ No URLs found in file")
        sys.exit(1)
    
    print(f"\n{'='*80}")
    print(f"🔄 BATCH SCANNER - {len(urls)} URLs to scan")
    print(f"{'='*80}\n")
    
    # Create reports directory
    reports_dir = Path('reports')
    reports_dir.mkdir(exist_ok=True)
    
    batch_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    batch_dir = reports_dir / f"batch_{batch_timestamp}"
    batch_dir.mkdir(exist_ok=True)
    
    # Scan results
    results_summary = []
    scanner = WebsiteScanner()
    
    for idx, url in enumerate(urls, 1):
        print(f"\n[{idx}/{len(urls)}] Scanning: {url}")
        print(f"{'-'*80}")
        
        try:
            # Perform scan
            result = scanner.scan(url)
            
            # Check for errors
            if 'error' in result:
                print(f"❌ Error: {result['error']}")
                results_summary.append({
                    'url': url,
                    'status': 'error',
                    'error': result['error']
                })
                continue
            
            # Extract key metrics
            domain = result.get('url_info', {}).get('domain', 'unknown')
            https_enabled = result.get('url_info', {}).get('https_enabled', False)
            risk_level = result.get('risk_assessment', {}).get('level', 'UNKNOWN')
            risk_score = result.get('risk_assessment', {}).get('score', 0)
            compliance_score = result.get('compliance', {}).get('overall_score', 0)
            
            # Save individual report
            filename = f"{domain}_{batch_timestamp}.json"
            filepath = batch_dir / filename
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, default=str)
            
            # Display summary
            print(f"✅ Scan complete:")
            print(f"   HTTPS: {'✅ Enabled' if https_enabled else '❌ Disabled'}")
            print(f"   Risk: {risk_level} ({risk_score})")
            print(f"   Compliance: {compliance_score:.1f}%")
            print(f"   Report: {filepath}")
            
            results_summary.append({
                'url': url,
                'domain': domain,
                'status': 'success',
                'https_enabled': https_enabled,
                'risk_level': risk_level,
                'risk_score': risk_score,
                'compliance_score': compliance_score,
                'report_file': str(filepath)
            })
            
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            results_summary.append({
                'url': url,
                'status': 'error',
                'error': str(e)
            })
        
        # Delay between scans
        if idx < len(urls):
            print(f"\n⏳ Waiting {delay}s before next scan...")
            time.sleep(delay)
    
    # Generate summary report
    print(f"\n{'='*80}")
    print("📊 BATCH SCAN SUMMARY")
    print(f"{'='*80}\n")
    
    successful = sum(1 for r in results_summary if r['status'] == 'success')
    failed = sum(1 for r in results_summary if r['status'] == 'error')
    
    print(f"Total scanned: {len(urls)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}\n")
    
    # Show results table
    print(f"{'URL':<40} {'Risk':<10} {'Compliance':<12} {'Status'}")
    print(f"{'-'*80}")
    for r in results_summary:
        url_short = r['url'][:40]
        if r['status'] == 'success':
            risk = r['risk_level']
            compliance = f"{r['compliance_score']:.1f}%"
            status = "✅ OK"
        else:
            risk = "N/A"
            compliance = "N/A"
            status = "❌ Error"
        
        print(f"{url_short:<40} {risk:<10} {compliance:<12} {status}")
    
    # Save summary
    summary_file = batch_dir / "summary.json"
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump({
            'batch_timestamp': batch_timestamp,
            'total_urls': len(urls),
            'successful': successful,
            'failed': failed,
            'results': results_summary
        }, f, indent=2, default=str)
    
    print(f"\n📁 All reports saved to: {batch_dir}")
    print(f"📄 Summary: {summary_file}\n")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python batch_scan.py <url_file> [delay_seconds]")
        print("\nExample: python batch_scan.py example_urls.txt 2")
        sys.exit(1)
    
    url_file = sys.argv[1]
    delay = float(sys.argv[2]) if len(sys.argv) > 2 else None  # None uses config default
    
    try:
        scan_urls_from_file(url_file, delay)
    except KeyboardInterrupt:
        print("\n\n⚠️  Batch scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
