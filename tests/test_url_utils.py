import pytest

from url_utils import normalize_url, validate_url_format, extract_domain


def test_normalize_adds_scheme():
    assert normalize_url('example.com').startswith('https://')


def test_validate_good_url():
    ok, err = validate_url_format('https://example.com')
    assert ok and err == ''


def test_extract_domain():
    info = extract_domain('https://sub.example.co.uk/path')
    assert info['registered_domain'] == 'example.co.uk'
    assert info['subdomain'] == 'sub'
