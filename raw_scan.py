#!/usr/bin/env python3
"""Raw scanner - minimal output, JSON only."""
import sys
import json
from main import WebsiteScanner

if len(sys.argv) < 2:
    print("Usage: python raw_scan.py <url>")
    sys.exit(1)

url = sys.argv[1]
scanner = WebsiteScanner()

# Suppress all output during scan
import logging
logging.disable(logging.CRITICAL)

# Scan
results = scanner.scan(url)

# Output raw JSON
print(json.dumps(results, indent=2, default=str))
