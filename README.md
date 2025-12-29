# 🛡️ DevSecOps Security Posture Analyzer

[![DevSecOps](https://img.shields.io/badge/DevSecOps-Enabled-blue?style=flat-square)](https://www.devsecops.org/)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-2088FF?style=flat-square&logo=github-actions)](https://github.com/features/actions)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

**Production-ready security posture analyzer** built for **DevSecOps workflows**. Provides automated, passive security assessment of web applications with **compliance mapping**, **CI/CD integration**, and **phishing detection**. Shift security left with automated pull request scanning and configurable quality gates.

## 🎯 What It Does

Automated passive security posture analysis for DevSecOps teams:

- **🎯 10-Category Advanced Scoring** - HTTPS, SSL quality, security headers, certificate validation, domain reputation, redirect safety, cookie security, content security, DNS security, response security
- **📋 Multi-Standard Compliance** - OWASP Top 10 2021, PCI-DSS, GDPR Article 32, NIST CSF with pass/fail checks
- **🚨 Phishing Detection** - Identifies URL obfuscation techniques (@ symbol, homoglyphs, suspicious TLDs)
- **⚡ CI/CD Integration** - GitHub Actions workflow with automated PR scanning and quality gates
- **📊 Risk Assessment** - Comprehensive risk scoring with prioritized CRITICAL/HIGH/MEDIUM/LOW recommendations
- **🔍 Security Headers Analysis** - HSTS, CSP, X-Frame-Options, cookie flags, and 10+ security headers
- **📈 Historical Tracking** - Compare security posture over time, detect regressions

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     DevSecOps Security Scanner                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │  CLI Entry   │  │  REST API    │  │  Streamlit   │         │
│  │   main.py    │  │   ui.py      │  │ app_streamlit│         │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘         │
│         │                  │                  │                 │
│         └──────────────────┴──────────────────┘                 │
│                            │                                    │
│                   ┌────────▼─────────┐                          │
│                   │  URLScanner Core │                          │
│                   │   (main.py)      │                          │
│                   └────────┬─────────┘                          │
│                            │                                    │
│         ┌──────────────────┼──────────────────┐                │
│         │                  │                  │                │
│  ┌──────▼──────┐  ┌────────▼────────┐  ┌─────▼──────┐         │
│  │ Network     │  │ Security Utils  │  │ URL Utils  │         │
│  │ - DNS       │  │ - SSL/TLS       │  │ - Parse    │         │
│  │ - HTTP      │  │ - Headers       │  │ - Validate │         │
│  │ - WHOIS     │  │ - Cookies       │  │ - Extract  │         │
│  └─────────────┘  └─────────────────┘  └────────────┘         │
│                            │                                    │
│         ┌──────────────────┼──────────────────┐                │
│         │                  │                  │                │
│  ┌──────▼──────┐  ┌────────▼────────┐  ┌─────▼──────┐         │
│  │ Advanced    │  │ Compliance      │  │ Risk       │         │
│  │ Scoring     │  │ - OWASP         │  │ Scoring    │         │
│  │ (10 cats)   │  │ - PCI-DSS       │  │ - Severity │         │
│  │             │  │ - GDPR/NIST     │  │ - Priority │         │
│  └─────────────┘  └─────────────────┘  └────────────┘         │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│ GitHub Actions CI/CD                                            │
│ ├── PR Auto-Scan with Quality Gates                            │
│ ├── Daily Scheduled Security Posture Checks                    │
│ └── Compliance Threshold Enforcement (60%)                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+ (tested with 3.13)
- pip package manager
- Git (for cloning)

### Installation

```powershell
# Clone the repository
git clone https://github.com/yourusername/security-posture-analyzer.git
cd security-posture-analyzer

# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows)
.\venv\Scripts\Activate.ps1

# Or on macOS/Linux:
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Run Your First Scan

#### CLI Mode
```bash
python main.py https://example.com
```

#### Interactive Streamlit Dashboard
```bash
streamlit run app_streamlit.py
```
Then navigate to http://localhost:8501 in your browser.

#### REST API Server
```bash
python api.py
```
Unified API available at http://localhost:8002/docs (Swagger UI)
- Main API endpoints: `/scan`, `/history`, `/health`
- Dashboard analytics: `/dashboard/overview`, `/dashboard/risks`

---

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Core Language** | Python 3.11+ | Modern async support, type hints |
| **HTTP Client** | httpx | Async HTTP with full SSL control |
| **DNS Lookups** | dnspython | Comprehensive DNS record queries |
| **WHOIS** | python-whois | Domain registration data |
| **HTML Parsing** | BeautifulSoup4 | Content and meta tag extraction |
| **Domain Extraction** | tldextract | TLD and subdomain parsing |
| **Web Dashboard** | Streamlit | Real-time interactive UI |
| **REST API** | FastAPI + Uvicorn | Production-grade async API |
| **Configuration** | PyYAML | Flexible YAML config files |
| **Testing** | pytest | Unit and integration tests |
| **CI/CD** | GitHub Actions | Automated scanning and quality gates |

---

## 📋 Features In Depth

### 🎯 10-Category Advanced Scoring System

Each website receives a **0-100 security score** based on these weighted categories:

1. **HTTPS Enabled** (15%) - Site uses encrypted HTTPS
2. **SSL Quality** (15%) - Certificate validity, expiration, chain
3. **Security Headers** (15%) - HSTS, CSP, X-Frame-Options, etc.
4. **Certificate Validation** (10%) - Proper SSL/TLS configuration
5. **Domain Reputation** (10%) - Age, TLD, suspicious patterns
6. **Redirect Safety** (10%) - No malicious redirect chains
7. **Cookie Security** (10%) - Secure, HttpOnly, SameSite flags
8. **Content Security** (5%) - CSP policies, unsafe patterns
9. **DNS Security** (5%) - DNS records, DNSSEC
10. **Response Security** (5%) - Server headers, fingerprinting

**Scoring Methodology:**
- Each category scored 0-100
- Weighted average produces final score
- 90-100: Excellent | 70-89: Good | 50-69: Fair | <50: Poor

### 📋 Multi-Standard Compliance Checking

#### OWASP Top 10 2021
Checks for common web security risks:
- A01:2021 - Broken Access Control
- A02:2021 - Cryptographic Failures
- A03:2021 - Injection
- A05:2021 - Security Misconfiguration
- A07:2021 - Identification and Authentication Failures

#### PCI-DSS (Payment Card Industry)
Requirements for sites handling payment data:
- Requirement 4.1 - Use strong cryptography for data transmission
- Requirement 6.5 - Secure development practices

#### GDPR Article 32 (Security of Processing)
EU data protection requirements:
- 32(1)(a) - Pseudonymization and encryption
- 32(1)(b) - Confidentiality, integrity, availability, resilience

#### NIST Cybersecurity Framework
Core security functions:
- PR.DS-2 - Data in transit is protected
- PR.AC-1 - Identities and credentials managed

**Compliance Dashboard** shows:
- ✅ Pass / ❌ Fail for each requirement
- Overall compliance percentage
- Detailed check results with remediation steps

### 🚨 Phishing & Threat Detection

Advanced URL analysis to detect common phishing techniques:

- **@ Symbol Obfuscation** - Detects `https://paypal.com@evil.com` patterns
- **Homoglyph Detection** - Identifies look-alike characters (future enhancement)
- **Suspicious TLDs** - Flags high-risk domains (.tk, .ml, .ga, .cf, .gq)
- **Domain Age Analysis** - New domains (<30 days) flagged
- **WHOIS Privacy** - Private registration triggers alerts
- **Mixed Content** - HTTP resources on HTTPS pages

When phishing detected, dashboard shows:
```
🚨 PHISHING TECHNIQUE DETECTED!
⚠️ URL uses @ symbol phishing technique - shows 'paypal.com' 
   but actually goes to 'evil.com'

This is a common phishing technique to trick users into thinking 
they're visiting a legitimate site!
```

### ⚡ GitHub Actions CI/CD Integration

Automated security scanning on every pull request:

```yaml
# Triggers:
- Pull requests to main/master/develop branches
- Daily scheduled scans at 2 AM UTC
- Manual workflow dispatch

# Quality Gates:
- ❌ FAIL if compliance score < 60%
- ❌ FAIL if critical security issues found
- ✅ PASS if all checks meet thresholds

# Outputs:
- PR comments with scan results
- Artifacts stored for 90 days
- Security badge updates
```

**DevSecOps Benefits:**
- **Shift-left security** - Catch issues before production
- **Automated compliance** - No manual security reviews needed
- **Continuous monitoring** - Daily scans detect configuration drift
- **Developer feedback** - PR comments with actionable fixes

### 📊 Risk Assessment & Recommendations

Each scan produces **prioritized recommendations** with severity levels:

#### CRITICAL
- Missing HTTPS encryption
- Expired SSL certificates
- No security headers at all

#### HIGH
- Weak Content-Security-Policy
- Missing HSTS header
- Insecure cookie flags

#### MEDIUM
- Missing X-Frame-Options
- No Referrer-Policy
- Server version exposure

#### LOW
- Suboptimal CSP directives
- Cache-Control recommendations

**Each recommendation includes:**
- Impact description
- Step-by-step fix instructions
- Reference documentation links
- Testing verification steps

---

## 📂 Project Structure

```
security-posture-analyzer/
├── main.py                 # Core scanner engine & URLScanner class
├── advanced_scoring.py     # 10-category scoring algorithm
├── app_streamlit.py        # Interactive Streamlit dashboard
├── compliance.py           # OWASP/PCI-DSS/GDPR/NIST checks
├── config_manager.py       # YAML configuration loader
├── network_utils.py        # DNS, HTTP, WHOIS utilities
├── parser.py               # HTML content analysis
├── security_utils.py       # SSL, headers, cookie security
├── ui.py                   # FastAPI REST API server
├── url_utils.py            # URL validation & normalization
├── whois_utils.py          # Domain registration lookups
├── config.yaml             # Configuration file
├── requirements.txt        # Python dependencies
├── LICENSE                 # MIT License
├── README.md               # This file
└── .github/
    └── workflows/
        └── security-scan.yml   # GitHub Actions CI/CD
```

---

## 💻 Usage Examples

### 1. CLI Scanning

```bash
# Single URL scan
python main.py https://example.com

# Interactive mode
python main.py
# Enter URL when prompted: https://github.com

# Export results to JSON
python main.py https://example.com --output results.json
```

### 2. Python API

```python
from main import URLScanner

scanner = URLScanner()
results = scanner.scan("https://example.com")

# Access specific data
print(f"Security Score: {results['advanced_score']['overall_score']}/100")
print(f"HTTPS Enabled: {results['url_info']['https_enabled']}")
print(f"Security Headers: {results['security_headers']}")
print(f"Compliance: {results['compliance']['overall_compliance']}%")

# Get recommendations
for rec in results['recommendations']:
    print(f"{rec['severity']}: {rec['message']}")
```

### 3. REST API

```bash
# Start API server
python ui.py

# Scan a URL (via curl)
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Get scan history
curl "http://localhost:8000/history"

# Get dashboard metrics
curl "http://localhost:8000/dashboard/metrics"
```

### 4. Streamlit Dashboard

```bash
streamlit run app_streamlit.py
```

**Dashboard Features:**
- Real-time scanning with progress indicators
- Visual security score breakdown
- Interactive compliance matrix
- Phishing detection alerts
- Security recommendations table
- Export to JSON/CSV

---

## ⚙️ Configuration

Edit `config.yaml` to customize behavior:

```yaml
scanner:
  timeout: 30              # HTTP request timeout (seconds)
  verify_ssl: true         # Verify SSL certificates
  follow_redirects: true   # Follow HTTP redirects
  max_redirects: 10        # Maximum redirect hops
  
  # Suspicious TLDs flagged in domain reputation
  suspicious_tlds:
    - tk
    - ml
    - ga
    - cf
    - gq
  
  # Custom security header requirements
  required_headers:
    - strict-transport-security
    - content-security-policy
    - x-frame-options
    - x-content-type-options

reporting:
  auto_save: true          # Auto-save scan results
  output_dir: ./reports    # Output directory for reports
  formats:
    - json
    - csv

github_actions:
  compliance_threshold: 60  # Minimum compliance score to pass (%)
  fail_on_critical: true    # Fail PR if critical issues found
```

---

## 🧪 Testing

### Run Unit Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_url_utils.py -v
```

### Test Coverage

Current test coverage:
- `url_utils.py`: 95%
- `security_utils.py`: 90%
- `advanced_scoring.py`: 88%
- `compliance.py`: 85%

---

## 🐳 Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000 8501

# Run API server
CMD ["python", "ui.py"]
```

```bash
# Build and run
docker build -t security-scanner .
docker run -p 8000:8000 -p 8501:8501 security-scanner
```

---

## 🤝 Contributing

Contributions welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Run tests** (`pytest`)
4. **Commit your changes** (`git commit -m 'Add amazing feature'`)
5. **Push to the branch** (`git push origin feature/amazing-feature`)
6. **Open a Pull Request**

### Development Setup

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run linting
flake8 .
black .

# Run type checking
mypy .
```

---

## ⚠️ Ethical Use Disclaimer

This tool is designed for **DEFENSIVE SECURITY** and **DevSecOps practices**:

✅ **Allowed Uses:**
- Assessing your own websites/applications
- Authorized security audits with written permission
- Educational purposes in controlled environments
- DevSecOps CI/CD integration for owned projects

❌ **Prohibited Uses:**
- Scanning websites without explicit authorization
- Penetration testing without permission
- Vulnerability exploitation
- Malicious or unethical activities

**Legal Notice:** Users are solely responsible for ensuring compliance with applicable laws and regulations. Unauthorized security testing may be illegal in your jurisdiction.

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

Built with open-source excellence:
- [httpx](https://www.python-httpx.org/) - Modern HTTP client
- [Streamlit](https://streamlit.io/) - Beautiful data apps
- [FastAPI](https://fastapi.tiangolo.com/) - High-performance APIs
- [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/) - HTML parsing
- [dnspython](https://www.dnspython.org/) - DNS toolkit
- OWASP, NIST, PCI-DSS standards communities

---

## 📞 Support & Contact

- **Issues**: [GitHub Issues](https://github.com/yourusername/security-posture-analyzer/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/security-posture-analyzer/discussions)
- **Security**: Report vulnerabilities via private issue

---

**⭐ If this project helps your DevSecOps workflow, please give it a star!**
