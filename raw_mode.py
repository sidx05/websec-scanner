"""Raw output mode - minimal formatting."""
import sys

# Disable all emojis and fancy formatting
RAW_MODE = '--raw' in sys.argv or '-r' in sys.argv

def print_raw(msg):
    """Print without formatting."""
    print(msg)

def print_section(title):
    """Print section header."""
    if RAW_MODE:
        print(f"\n{title}")
    else:
        print(f"\n{'='*60}")
        print(title)
        print('='*60)
