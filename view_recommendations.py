"""Quick script to view recommendations from a scan report."""
import json
import sys

if len(sys.argv) < 2:
    print("Usage: python view_recommendations.py <scan_report.json>")
    sys.exit(1)

with open(sys.argv[1]) as f:
    data = json.load(f)

recs = data.get('recommendations', [])
print(f"\n{'='*70}")
print(f"RECOMMENDATIONS ({len(recs)} total)")
print(f"{'='*70}\n")

for i, rec in enumerate(recs, 1):
    print(f"{i}. [{rec['priority']}] {rec['issue']}")
    print(f"   Impact: {rec['impact']}")
    print(f"   Fix: {rec['fix']}")
    if rec.get('references'):
        print(f"   References: {', '.join(rec['references'])}")
    print()

compliance = data.get('compliance', {})
if compliance:
    print(f"\n{'='*70}")
    print(f"COMPLIANCE REPORT (Overall Score: {compliance.get('overall_score', 0)}%)")
    print(f"{'='*70}\n")
    
    for std_name, std_data in compliance.get('standards', {}).items():
        print(f"{std_data['standard']}: {std_data['score']}%")
        print(f"  Passed {std_data['passed']}/{std_data['total']} checks\n")
