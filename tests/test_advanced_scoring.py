"""
Unit tests for advanced_scoring.py
Tests 10-category scoring system and weighting
"""
import pytest
from advanced_scoring import AdvancedScorer


class TestAdvancedScorer:
    """Test AdvancedScorer class"""
    
    def test_scorer_initialization(self):
        """Should initialize with scan results"""
        results = {'url_info': {'https_enabled': True}}
        scorer = AdvancedScorer(results)
        assert scorer.results == results
        assert scorer.WEIGHTS is not None
    
    def test_weights_sum_to_100(self):
        """All category weights should sum to 100%"""
        results = {}
        scorer = AdvancedScorer(results)
        total = sum(scorer.WEIGHTS.values())
        assert total == 100
    
    def test_all_categories_present(self):
        """Should have weights for all 10 categories"""
        results = {}
        scorer = AdvancedScorer(results)
        expected_categories = [
            'https',
            'ssl_quality',
            'security_headers',
            'certificate_validation',
            'domain_reputation',
            'redirect_safety',
            'cookie_security',
            'content_security',
            'dns_security',
            'response_security'
        ]
        for category in expected_categories:
            assert category in scorer.WEIGHTS


class TestScoreCalculation:
    """Test score calculation"""
    
    def test_perfect_score(self):
        """Should score high for secure sites (not necessarily 100)"""
        results = {
            'url_info': {'https_enabled': True},
            'ssl_certificate': {
                'valid': True,
                'days_until_expiry': 365,
                'issuer': "Let's Encrypt"
            },
            'security_headers': {
                'score': 100,
                'present': ['strict-transport-security', 'content-security-policy']
            },
            'cookies': {'score': 100},
            'whois': {'domain_age_days': 3650},
            'dns_records': {'a_records': ['1.2.3.4']},
            'network_info': {},
            'page_info': {}
        }
        scorer = AdvancedScorer(results)
        score_result = scorer.calculate_advanced_score()
        assert 'overall_score' in score_result
        # Should score reasonably high for secure site
        assert score_result['overall_score'] >= 50
    
    def test_failing_score(self):
        """Should score low for insecure sites"""
        results = {
            'url_info': {'https_enabled': False},
            'ssl_certificate': {},
            'security_headers': {'score': 0},
            'cookies': {'score': 0},
            'whois': {'domain_age_days': 1},
            'dns_records': {},
            'network_info': {},
            'page_info': {}
        }
        scorer = AdvancedScorer(results)
        score_result = scorer.calculate_advanced_score()
        assert score_result['overall_score'] < 50
    
    def test_category_scores_present(self):
        """Should include individual category scores"""
        results = {
            'url_info': {'https_enabled': True},
            'ssl_certificate': {'valid': True},
            'security_headers': {'score': 75},
            'cookies': {'score': 50},
            'whois': {},
            'dns_records': {},
            'network_info': {},
            'page_info': {}
        }
        scorer = AdvancedScorer(results)
        score_result = scorer.calculate_advanced_score()
        assert 'category_scores' in score_result
        assert len(score_result['category_scores']) > 0
    
    def test_handles_missing_data(self):
        """Should handle missing data gracefully"""
        results = {}
        scorer = AdvancedScorer(results)
        score_result = scorer.calculate_advanced_score()
        assert 'overall_score' in score_result
        assert 0 <= score_result['overall_score'] <= 100
