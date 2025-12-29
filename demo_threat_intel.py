#!/usr/bin/env python3
"""
Simple demonstration of threat intelligence integrations.
Shows how to use external APIs when API keys are configured.
"""

import sys
from threat_intel import VirusTotalAPI, PhishTankAPI, URLhausAPI

def demo_threat_intel(url: str):
    """
    Demonstrate threat intelligence checks for a URL.
    
    Args:
        url: URL to check
    """
    print(f"🔍 Threat Intelligence Demo for: {url}\n")
    
    # VirusTotal
    print("=" * 60)
    print("1. VirusTotal Reputation Check")
    print("=" * 60)
    vt = VirusTotalAPI()
    vt_result = vt.check_url(url)
    
    if 'error' in vt_result:
        print(f"⚠️  {vt_result['error']}")
        if not vt_result.get('available', False):
            print("💡 Set VT_API_KEY environment variable to enable")
    else:
        print(f"Status: {vt_result.get('status', 'unknown')}")
        if 'reputation' in vt_result:
            print(f"Reputation: {vt_result['reputation']}")
        if 'detections' in vt_result:
            print(f"Detections: {vt_result['detections']}")
    
    print()
    
    # PhishTank
    print("=" * 60)
    print("2. PhishTank Phishing Database Check")
    print("=" * 60)
    pt = PhishTankAPI()
    pt_result = pt.check_url(url)
    
    if 'error' in pt_result:
        print(f"⚠️  {pt_result['error']}")
    else:
        is_phish = pt_result.get('is_phishing', False)
        if is_phish:
            print(f"🚨 PHISHING DETECTED!")
            print(f"   Verified: {pt_result.get('verified', 'unknown')}")
            print(f"   PhishTank ID: {pt_result.get('phish_id', 'N/A')}")
        else:
            print(f"✅ Not found in PhishTank database")
    
    print()
    
    # URLhaus
    print("=" * 60)
    print("3. URLhaus Malware Database Check")
    print("=" * 60)
    uh = URLhausAPI()
    uh_result = uh.check_url(url)
    
    if 'error' in uh_result:
        print(f"⚠️  {uh_result['error']}")
    else:
        if uh_result.get('is_malware', False):
            print(f"🚨 MALWARE DETECTED!")
            print(f"   Threat Type: {uh_result.get('threat_type', 'unknown')}")
            print(f"   Tags: {', '.join(uh_result.get('tags', []))}")
        else:
            print(f"✅ Not found in URLhaus database")
    
    print("\n" + "=" * 60)
    print("📋 Summary")
    print("=" * 60)
    
    threats_found = []
    if vt_result.get('detections', 0) > 0:
        threats_found.append("VirusTotal detections")
    if pt_result.get('is_phishing', False):
        threats_found.append("PhishTank phishing")
    if uh_result.get('is_malware', False):
        threats_found.append("URLhaus malware")
    
    if threats_found:
        print(f"⚠️  Threats found: {', '.join(threats_found)}")
    else:
        print("✅ No threats detected across all sources")
    
    print()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python demo_threat_intel.py <url>")
        print("\nExample:")
        print("  python demo_threat_intel.py https://example.com")
        print("\nNote: Some APIs require API keys:")
        print("  - VirusTotal: Set VT_API_KEY environment variable")
        print("  - PhishTank: Public API, no key required")
        print("  - URLhaus: Public API, no key required")
        sys.exit(1)
    
    demo_threat_intel(sys.argv[1])
