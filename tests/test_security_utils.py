from security_utils import analyze_security_headers, analyze_csp_policy, analyze_cookie_flags


def test_headers_score_and_lists():
    headers = {
        'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
    }
    res = analyze_security_headers(headers, [])
    assert 'score' in res
    assert len(res['present']) >= 3
    assert 'Content-Security-Policy' in res['missing']


def test_csp_analysis_flags_unsafe():
    findings = analyze_csp_policy("default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval' * data:")
    assert any('unsafe-inline' in f for f in findings)
    assert any('unsafe-eval' in f for f in findings)
    assert any('wildcard' in f or '*' in f for f in findings)


def test_cookie_flags():
    cookies = [
        'sessionid=abc; Path=/; HttpOnly; Secure; SameSite=Lax',
        'auth=def; Path=/; SameSite=None',
    ]
    findings = analyze_cookie_flags(cookies)
    # Second cookie should flag SameSite=None without Secure
    assert any('SameSite=None' in f for f in findings)
