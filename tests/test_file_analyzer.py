import pytest
from pathlib import Path
from file_analyzer import FileAnalyzer


def test_file_analyzer_hash():
    # Create a test file
    test_file = Path('tests/test_file.txt')
    test_file.write_text('Hello World')
    
    analyzer = FileAnalyzer(str(test_file))
    result = analyzer.analyze()
    
    assert 'hashes' in result
    assert 'md5' in result['hashes']
    assert 'sha256' in result['hashes']
    assert result['size_bytes'] > 0
    
    test_file.unlink()


def test_entropy_calculation():
    # Low entropy file
    test_file = Path('tests/test_entropy.txt')
    test_file.write_bytes(b'A' * 1000)
    
    analyzer = FileAnalyzer(str(test_file))
    result = analyzer.analyze()
    
    assert result['entropy'] < 1.0  # All same byte = low entropy
    
    test_file.unlink()
