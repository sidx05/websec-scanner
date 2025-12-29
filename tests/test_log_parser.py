import pytest
from pathlib import Path
from log_parser import LogParser


def test_log_parser_basic():
    # Assumes logs/app.log exists with some content
    parser = LogParser()
    stats = parser.parse_logs(hours=720)  # 30 days
    assert 'total_lines' in stats
    assert 'scans_completed' in stats


def test_alert_generation():
    parser = LogParser()
    stats = parser.parse_logs(hours=720)
    assert 'alerts' in stats
    summary = parser.get_alert_summary()
    assert isinstance(summary, str)
