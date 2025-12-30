"""
Optional Streamlit web UI for the Website Scanner.

Run with: streamlit run app_streamlit.py
"""

import streamlit as st
import json
import io
import csv
import time
from datetime import datetime
from pathlib import Path

# Import scanner modules
import url_utils
import network_utils
import security_utils
import parser
import whois_utils
from main import WebsiteScanner
from storage_utils import read_history
from recommendations import format_recommendations_text
from compliance import format_compliance_report


def format_bytes(size_bytes: int) -> str:
    """Format bytes into human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


def format_date(dt) -> str:
    """Format datetime object to string."""
    if not dt:
        return "Unknown"
    try:
        return dt.strftime("%Y-%m-%d")
    except:
        return str(dt)


def _parse_urls_from_text(text: str) -> list[str]:
    urls: list[str] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        urls.append(line)
    # Preserve order; de-duplicate
    seen: set[str] = set()
    deduped: list[str] = []
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        deduped.append(url)
    return deduped


def _safe_slug(value: str) -> str:
    keep = []
    for ch in (value or ""):
        keep.append(ch if ch.isalnum() or ch in ('-', '_', '.') else '_')
    return ''.join(keep).strip('_') or 'item'


def _write_schedule_file(schedule_path: Path, config: dict) -> None:
    schedule_path.parent.mkdir(exist_ok=True)
    with schedule_path.open('w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)


def main():
    """Main Streamlit app."""
    
    # Page config
    st.set_page_config(
        page_title="Website Security Scanner",
        page_icon="🔍",
        layout="wide"
    )
    
    # Header
    st.title("🔍 Website Information & Security Scanner")
    st.markdown("**Passive analysis tool - Non-intrusive checks only**")
    
    # Feature Comparison Info
    with st.expander("ℹ️ How to Use - Single Scan vs. Batch Scan"):
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            ### 🔍 Single Scan (Below)
            **Best for:**
            - Quick security check of one website
            - Detailed analysis of a single domain
            - Interactive real-time results
            - Exploring all security metrics in depth
            
            **Features:**
            - ✅ Live progress with 9-step visualization
            - ✅ Detailed tabs (Overview, Network, Security, etc.)
            - ✅ Full scan report with recommendations
            - ✅ Certificate, headers, WHOIS analysis
            - ✅ Export individual scan results
            
            **Use when:** You want comprehensive details about ONE website.
            """)
        
        with col2:
            st.markdown("""
            ### 📊 Batch Scan (DevSecOps Section)
            **Best for:**
            - Scanning multiple websites at once (2-100+ URLs)
            - Security posture comparison across domains
            - Infrastructure-wide security assessment
            - Compliance reporting for multiple sites
            
            **Features:**
            - ✅ Upload file or paste multiple URLs
            - ✅ Executive summary dashboard
            - ✅ Risk distribution & comparison matrix
            - ✅ Aggregate compliance scores
            - ✅ Export consolidated reports (JSON/CSV/Summary)
            
            **Use when:** You need to assess MULTIPLE websites and compare them.
            """)
    
    # Disclaimer in expandable section
    with st.expander("⚠️ Important Disclaimer - Please Read"):
        st.warning("""
        This tool performs **only passive, legal checks**:
        - ✅ Simple HTTP GET requests
        - ✅ DNS lookups
        - ✅ WHOIS queries
        - ✅ SSL certificate verification
        
        It does **NOT** perform:
        - ❌ Intrusive scanning (port scanning, vulnerability testing)
        - ❌ Brute-forcing or penetration testing
        - ❌ Any illegal or harmful activities
        
        **Use responsibly** and only on websites you own or have permission to analyze.
        """)

    # DevSecOps (Batch + Monitoring) — visible in UI but optional
    with st.expander("🛠️ DevSecOps: Batch Scanning & Continuous Monitoring"):
        dev_tab1, dev_tab2 = st.tabs(["📁 Batch Scan", "⏱️ Monitoring (Schedules)"])

        with dev_tab1:
            st.subheader("Batch Scan")
            st.caption("Scan multiple URLs and export a combined report.")

            uploaded = st.file_uploader(
                "Upload URLs file (any text-based format)", 
                type=["txt", "csv", "log", "conf", "json", "xml", "html", "md", "text", "js", "py", "yaml", "yml", "ini", "cfg", "properties"],
                key="batch_file"
            )
            urls_text = st.text_area("Or paste URLs (one per line)", height=140, key="batch_text")
            delay_seconds = st.number_input(
                "Delay between scans (seconds)",
                min_value=0.0,
                max_value=60.0,
                value=2.0,
                step=0.5,
                key="batch_delay",
            )

            file_urls: list[str] = []
            if uploaded is not None:
                try:
                    file_urls = _parse_urls_from_text(uploaded.getvalue().decode('utf-8', errors='ignore'))
                except Exception as e:
                    st.error(f"❌ Could not read file: {str(e)}. Please upload a valid text file.")
                    file_urls = []

            text_urls = _parse_urls_from_text(urls_text)
            batch_urls = file_urls or text_urls

            st.write(f"URLs ready: **{len(batch_urls)}**")
            
            if batch_urls:
                st.info("📝 **Valid URL Examples:** `https://google.com`, `http://example.com`, `www.github.com`")
            else:
                st.warning("⚠️ No valid URLs detected. Make sure your file/text contains actual website URLs, not random text.")

            if st.button("🚀 Run Batch Scan", type="primary", key="run_batch"):
                if not batch_urls:
                    st.error("❌ **No valid URLs found!** Please provide URLs in format: `https://example.com` or `www.example.com`")
                else:
                    scanner = WebsiteScanner()
                    started_at = datetime.now()
                    progress = st.progress(0)
                    status = st.empty()
                    results_summary: list[dict] = []

                    for idx, url in enumerate(batch_urls, 1):
                        status.info(f"[{idx}/{len(batch_urls)}] Scanning: {url}")
                        progress.progress(int((idx - 1) / max(len(batch_urls), 1) * 100))
                        try:
                            result = scanner.scan(url)
                            if 'error' in result:
                                results_summary.append({
                                    'url': url,
                                    'status': 'error',
                                    'error': result.get('error'),
                                })
                            else:
                                url_info = result.get('url_info', {})
                                risk = result.get('risk_assessment', {})
                                compliance = result.get('compliance', {})
                                security_headers = result.get('security_headers', {})
                                ssl_cert = result.get('ssl_certificate', {})
                                recommendations = result.get('recommendations', [])
                                network = result.get('network_info', {})
                                whois = result.get('whois', {})
                                domain_info = result.get('domain_info', {})
                                advanced_score = result.get('advanced_score', {})
                                
                                # Extract missing security headers
                                missing_headers = security_headers.get('missing', [])
                                present_headers = security_headers.get('headers', {})
                                
                                # SSL/Certificate details
                                ssl_issuer = 'Unknown'
                                try:
                                    if ssl_cert and isinstance(ssl_cert, dict) and not ssl_cert.get('error'):
                                        issuer = ssl_cert.get('issuer', {})
                                        if isinstance(issuer, dict):
                                            ssl_issuer = issuer.get('organizationName', 'Unknown')
                                except (AttributeError, TypeError, KeyError):
                                    ssl_issuer = 'N/A'
                                ssl_valid_from = ssl_cert.get('not_before', 'N/A') if ssl_cert and not ssl_cert.get('error') else 'N/A'
                                
                                # Network metrics
                                response_time = network.get('response_time', 0)
                                status_code = network.get('status_code', 0)
                                ip_address = network.get('ip_address', 'Unknown')
                                redirect_count = url_info.get('redirect_count', 0)
                                
                                # Domain age and registrar
                                domain_age = whois.get('domain_age', 'Unknown')
                                registrar = whois.get('registrar', 'Unknown')
                                
                                # Advanced category scores
                                category_scores = advanced_score.get('category_scores', {})
                                if not isinstance(category_scores, dict):
                                    category_scores = {}
                                
                                # Extract compliance standards (fixed to use correct nested path)
                                compliance_standards = compliance.get('standards', {})
                                
                                # Specific compliance details - checks are stored as dicts, not lists
                                owasp_checks = compliance_standards.get('owasp_top10', {}).get('checks', {})
                                if not isinstance(owasp_checks, dict):
                                    owasp_checks = {}
                                owasp_failures = [name for name, check in owasp_checks.items() if isinstance(check, dict) and not check.get('compliant', False)]
                                
                                pci_checks = compliance_standards.get('pci_dss', {}).get('checks', {})
                                if not isinstance(pci_checks, dict):
                                    pci_checks = {}
                                pci_failures = [check.get('name', name) for name, check in pci_checks.items() if isinstance(check, dict) and not check.get('compliant', False)]
                                
                                gdpr_checks = compliance_standards.get('gdpr', {}).get('checks', {})
                                if not isinstance(gdpr_checks, dict):
                                    gdpr_checks = {}
                                gdpr_failures = [check.get('name', name) for name, check in gdpr_checks.items() if isinstance(check, dict) and not check.get('compliant', False)]
                                
                                # Phishing indicators
                                phishing_indicators = url_info.get('phishing_indicators', [])
                                if not isinstance(phishing_indicators, list):
                                    phishing_indicators = []
                                
                                results_summary.append({
                                    'url': url_info.get('original_url', url),
                                    'domain': url_info.get('domain'),
                                    'https_enabled': bool(url_info.get('https_enabled')),
                                    'risk_level': risk.get('level'),
                                    'risk_score': risk.get('score'),
                                    'risk_factors': risk.get('factors', []),
                                    'compliance_score': compliance.get('overall_score'),
                                    'headers_score': security_headers.get('score', 0),
                                    'missing_headers': missing_headers,
                                    'present_headers': list(present_headers.keys()),
                                    'ssl_valid': not ssl_cert.get('error') and not ssl_cert.get('is_expired', True) if ssl_cert else False,
                                    'ssl_days': ssl_cert.get('days_until_expiry', 0) if ssl_cert and not ssl_cert.get('error') else 0,
                                    'ssl_issuer': ssl_issuer,
                                    'ssl_valid_from': ssl_valid_from,
                                    'critical_issues': len([r for r in recommendations if r.get('priority') == 'CRITICAL']),
                                    'high_issues': len([r for r in recommendations if r.get('priority') == 'HIGH']),
                                    'medium_issues': len([r for r in recommendations if r.get('priority') == 'MEDIUM']),
                                    'low_issues': len([r for r in recommendations if r.get('priority') == 'LOW']),
                                    'all_recommendations': [{'issue': r.get('issue'), 'priority': r.get('priority'), 'impact': r.get('impact')} for r in recommendations],
                                    'owasp_score': compliance_standards.get('owasp_top10', {}).get('score', 0) if isinstance(compliance_standards.get('owasp_top10'), dict) else 0,
                                    'pci_score': compliance_standards.get('pci_dss', {}).get('score', 0) if isinstance(compliance_standards.get('pci_dss'), dict) else 0,
                                    'gdpr_score': compliance_standards.get('gdpr', {}).get('score', 0) if isinstance(compliance_standards.get('gdpr'), dict) else 0,
                                    'nist_score': compliance_standards.get('nist_csf', {}).get('score', 0) if isinstance(compliance_standards.get('nist_csf'), dict) else 0,
                                    'owasp_failures': owasp_failures,
                                    'pci_failures': pci_failures,
                                    'gdpr_failures': gdpr_failures,
                                    'response_time': response_time,
                                    'status_code': status_code,
                                    'ip_address': ip_address,
                                    'redirect_count': redirect_count,
                                    'domain_age': domain_age,
                                    'registrar': registrar,
                                    'tld': domain_info.get('tld', 'Unknown'),
                                    'phishing_indicators': phishing_indicators,
                                    'category_scores': category_scores,
                                    'advanced_grade': advanced_score.get('grade', 'N/A'),
                                    'status': 'success',
                                    'full_result': result,
                                })
                        except Exception as e:
                            results_summary.append({
                                'url': url,
                                'status': 'error',
                                'error': str(e),
                            })

                        if idx < len(batch_urls) and delay_seconds > 0:
                            time.sleep(float(delay_seconds))

                    progress.progress(100)
                    status.success("✅ Batch scan complete")

                    ended_at = datetime.now()
                    successful = sum(1 for r in results_summary if r.get('status') == 'success')
                    failed = sum(1 for r in results_summary if r.get('status') == 'error')
                    
                    # Initialize critical_sites early for use throughout
                    successful_scans = [r for r in results_summary if r.get('status') == 'success']
                    critical_sites = [r for r in successful_scans if r.get('risk_level') == 'HIGH']

                    # Enhanced Summary Statistics
                    st.markdown("---")
                    st.subheader("📊 Batch Scan Summary")
                    
                    col_a, col_b, col_c, col_d = st.columns(4)
                    with col_a:
                        st.metric("Total Scans", len(results_summary))
                    with col_b:
                        st.metric("✅ Successful", successful)
                    with col_c:
                        st.metric("❌ Failed", failed)
                    with col_d:
                        duration = (ended_at - started_at).total_seconds()
                        st.metric("Duration", f"{duration:.1f}s")

                    # Risk Distribution (only for successful scans)
                    if successful_scans:
                        # Calculate all metrics first
                        high_risk = sum(1 for r in successful_scans if r.get('risk_level') == 'HIGH')
                        medium_risk = sum(1 for r in successful_scans if r.get('risk_level') == 'MEDIUM')
                        low_risk = sum(1 for r in successful_scans if r.get('risk_level') == 'LOW')
                        https_enabled = sum(1 for r in successful_scans if r.get('https_enabled'))
                        ssl_valid = sum(1 for r in successful_scans if r.get('ssl_valid'))
                        avg_compliance = sum(r.get('compliance_score', 0) for r in successful_scans) / len(successful_scans) if successful_scans else 0
                        avg_headers = sum(r.get('headers_score', 0) for r in successful_scans) / len(successful_scans) if successful_scans else 0
                        total_critical = sum(r.get('critical_issues', 0) for r in successful_scans)
                        avg_owasp = sum(r.get('owasp_score', 0) for r in successful_scans) / len(successful_scans) if successful_scans else 0
                        avg_pci = sum(r.get('pci_score', 0) for r in successful_scans) / len(successful_scans) if successful_scans else 0
                        
                        # Executive Summary Box
                        st.markdown("---")
                        # Calculate overall health based on multiple factors (not just compliance score)
                        if high_risk > 0 or total_critical > 0:
                            overall_health = "🔴 CRITICAL"
                            health_desc = f"Identified {high_risk} high-risk site(s) and {total_critical} critical issue(s) requiring immediate attention."
                        elif medium_risk > 0 or avg_compliance < 60 or avg_headers < 40:
                            overall_health = "🟡 NEEDS IMPROVEMENT"
                            health_desc = f"Found {medium_risk} medium-risk site(s) with compliance at {avg_compliance:.1f}%. Security improvements recommended."
                        elif avg_compliance >= 80 and avg_headers >= 70:
                            overall_health = "🟢 EXCELLENT"
                            health_desc = f"All {successful} site(s) show strong security posture with {avg_compliance:.1f}% compliance."
                        else:
                            overall_health = "🟢 GOOD"
                            health_desc = f"Scanned {successful} site(s) - security posture is acceptable with {avg_compliance:.1f}% compliance."
                        
                        st.markdown(f"""
                        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px; color: white; margin: 10px 0;">
                            <h2 style="margin: 0; color: white;">📊 Executive Summary</h2>
                            <h3 style="margin: 10px 0; color: white;">Overall Security Health: {overall_health}</h3>
                            <p style="margin: 5px 0;">{health_desc}</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        st.markdown("---")
                        st.subheader("🎯 Risk Analysis")
                        
                        risk_col1, risk_col2, risk_col3, risk_col4 = st.columns(4)
                        with risk_col1:
                            st.metric("🔴 HIGH Risk", high_risk, delta=f"{(high_risk/successful)*100:.0f}%" if successful > 0 else "0%")
                        with risk_col2:
                            st.metric("🟡 MEDIUM Risk", medium_risk, delta=f"{(medium_risk/successful)*100:.0f}%" if successful > 0 else "0%")
                        with risk_col3:
                            st.metric("🟢 LOW Risk", low_risk, delta=f"{(low_risk/successful)*100:.0f}%" if successful > 0 else "0%")
                        with risk_col4:
                            st.metric("🚨 Critical Issues", total_critical)
                        
                        # Security Posture Overview
                        st.markdown("---")
                        st.subheader("🔒 Security Posture")
                        
                        sec_col1, sec_col2, sec_col3, sec_col4 = st.columns(4)
                        with sec_col1:
                            st.metric("🔐 HTTPS", f"{https_enabled}/{successful}", delta=f"{(https_enabled/successful)*100:.0f}%" if successful > 0 else "0%")
                        with sec_col2:
                            st.metric("🔒 Valid SSL", f"{ssl_valid}/{successful}", delta=f"{(ssl_valid/successful)*100:.0f}%" if successful > 0 else "0%")
                        with sec_col3:
                            st.metric("📋 Avg Compliance", f"{avg_compliance:.1f}%", delta="Good" if avg_compliance >= 70 else "Poor" if avg_compliance < 40 else "Fair")
                        with sec_col4:
                            st.metric("🛡️ Avg Headers", f"{avg_headers:.0f}%", delta="Strong" if avg_headers >= 70 else "Weak" if avg_headers < 40 else "OK")
                        
                        # Compliance Framework Breakdown
                        st.markdown("---")
                        st.subheader("✅ Compliance Framework Scores")
                        
                        with st.expander("❓ What are OWASP & PCI-DSS scores?"):
                            st.markdown("""
                            **Compliance Framework Scores:**
                            
                            🔐 **OWASP Top 10 (2021)**  
                            Tests your sites against the 10 most critical web application security risks:
                            - A01: Broken Access Control
                            - A02: Cryptographic Failures (HTTPS/SSL)
                            - A03: Injection vulnerabilities
                            - A04: Insecure Design
                            - A05: Security Misconfiguration (Headers)
                            - And more...
                            
                            **Score Meaning:**
                            - 80-100%: ✅ **Pass** - Strong OWASP compliance
                            - 0-79%: ❌ **Fail** - Critical OWASP gaps detected
                            
                            💳 **PCI-DSS (Payment Card Industry)**  
                            Checks web security requirements for sites handling payment data:
                            - Requirement 4.1: Strong cryptography (HTTPS)
                            - Requirement 6.5: Secure coding practices
                            - Requirement 6.6: Web application firewall indicators
                            
                            **Score Meaning:**
                            - 80-100%: ✅ **Pass** - Meets PCI-DSS web standards
                            - 0-79%: ❌ **Fail** - Does not meet PCI-DSS requirements
                            
                            **Why 0%?**  
                            If your sites have no HTTPS, missing security headers, or critical vulnerabilities,  
                            they fail these compliance frameworks completely (0% score).
                            """)
                        
                        comp_col1, comp_col2 = st.columns(2)
                        with comp_col1:
                            st.metric("🔐 OWASP Top 10", f"{avg_owasp:.1f}%", delta="Pass" if avg_owasp >= 80 else "Fail")
                            st.progress(avg_owasp / 100)
                        with comp_col2:
                            st.metric("💳 PCI-DSS", f"{avg_pci:.1f}%", delta="Pass" if avg_pci >= 80 else "Fail")
                            st.progress(avg_pci / 100)
                        
                        # SSL Certificate Status
                        st.markdown("---")
                        st.subheader("🔒 SSL/TLS Certificate Status")
                        
                        ssl_expiring_soon = sum(1 for r in successful_scans if 0 < r.get('ssl_days', 0) <= 30)
                        ssl_expired = sum(1 for r in successful_scans if r.get('ssl_days', 0) <= 0 and r.get('https_enabled'))
                        ssl_healthy = sum(1 for r in successful_scans if r.get('ssl_days', 0) > 30)
                        
                        ssl_col1, ssl_col2, ssl_col3 = st.columns(3)
                        with ssl_col1:
                            st.metric("✅ Healthy (>30 days)", ssl_healthy)
                        with ssl_col2:
                            if ssl_expiring_soon > 0:
                                st.metric("⚠️ Expiring Soon (≤30 days)", ssl_expiring_soon, delta="Warning", delta_color="inverse")
                            else:
                                st.metric("⚠️ Expiring Soon", 0)
                        with ssl_col3:
                            if ssl_expired > 0:
                                st.metric("❌ Expired", ssl_expired, delta="Critical", delta_color="inverse")
                            else:
                                st.metric("❌ Expired", 0)
                        
                        # Security Issues Breakdown with explanation
                        st.markdown("---")
                        st.subheader("🔍 Security Issues Breakdown")
                        
                        with st.expander("❓ What do these priorities mean?"):
                            st.markdown("""
                            **Issue Priority Levels:**
                            
                            - 🔴 **CRITICAL**: Severe vulnerabilities that pose immediate security risks. These must be fixed ASAP.
                              - Examples: No HTTPS encryption, exposed admin panels, SQL injection vulnerabilities
                              
                            - 🟠 **HIGH**: Significant security concerns that should be addressed urgently.
                              - Examples: Missing critical security headers, weak SSL/TLS, outdated software
                              
                            - 🟡 **MEDIUM**: Moderate security issues that should be fixed but aren't immediately exploitable.
                              - Examples: Missing optional security headers, suboptimal configurations
                              
                            - 🟢 **LOW**: Minor security improvements that enhance overall posture.
                              - Examples: Best practice recommendations, documentation suggestions
                            
                            **These are generated from actual scan findings, not generic warnings!**
                            """)
                        
                        total_high = sum(r.get('high_issues', 0) for r in successful_scans)
                        total_medium = sum(r.get('medium_issues', 0) for r in successful_scans)
                        total_issues = total_critical + total_high + total_medium
                        
                        issue_col1, issue_col2, issue_col3, issue_col4 = st.columns(4)
                        with issue_col1:
                            st.metric("🔴 Critical", total_critical)
                        with issue_col2:
                            st.metric("🟠 High", total_high)
                        with issue_col3:
                            st.metric("🟡 Medium", total_medium)
                        with issue_col4:
                            st.metric("📊 Total Issues", total_issues)
                        
                        # Critical Findings - Enhanced with detailed vulnerability data
                        if critical_sites:
                            st.markdown("---")
                            st.error(f"### ⚠️ {len(critical_sites)} Critical Finding(s) - Immediate Action Required")
                            for site in critical_sites:
                                with st.expander(f"🔴 {site.get('domain', 'Unknown')} - HIGH RISK (Score: {site.get('risk_score', 0)})"):
                                    # Overview Section
                                    st.markdown("#### 🎯 Overview")
                                    over_col1, over_col2, over_col3 = st.columns(3)
                                    with over_col1:
                                        st.write(f"**URL:** {site.get('url')}")
                                        st.write(f"**IP Address:** {site.get('ip_address', 'Unknown')}")
                                        st.write(f"**Response Time:** {site.get('response_time', 0):.2f}s")
                                    with over_col2:
                                        st.write(f"**Risk Score:** {site.get('risk_score', 0)}")
                                        st.write(f"**Compliance:** {site.get('compliance_score', 0):.1f}%")
                                        st.write(f"**Advanced Grade:** {site.get('advanced_grade', 'N/A')}")
                                    with over_col3:
                                        st.write(f"**Domain Age:** {site.get('domain_age', 'Unknown')}")
                                        registrar = site.get('registrar', 'Unknown')
                                        st.write(f"**Registrar:** {str(registrar)[:30]}")
                                        st.write(f"**TLD:** {site.get('tld', 'Unknown')}")
                                    
                                    # Risk Factors
                                    risk_factors = site.get('risk_factors', [])
                                    if not isinstance(risk_factors, list):
                                        risk_factors = []
                                    if risk_factors:
                                        st.markdown("#### ⚠️ Risk Factors")
                                        for factor in risk_factors:
                                            if factor != "No significant issues detected":
                                                st.warning(f"• {factor}")
                                    
                                    # Phishing Indicators
                                    phishing = site.get('phishing_indicators', [])
                                    if not isinstance(phishing, list):
                                        phishing = []
                                    if phishing:
                                        st.markdown("#### 🚨 Phishing Techniques Detected")
                                        for indicator in phishing:
                                            st.error(f"• {indicator}")
                                    
                                    # Security Gaps
                                    st.markdown("#### 🔒 Security Analysis")
                                    sec_col1, sec_col2 = st.columns(2)
                                    with sec_col1:
                                        st.write(f"**HTTPS:** {'✅ Enabled' if site.get('https_enabled') else '❌ Disabled'}")
                                        st.write(f"**SSL Valid:** {'✅ Yes' if site.get('ssl_valid') else '❌ No'}")
                                        if site.get('ssl_issuer') != 'N/A':
                                            st.write(f"**SSL Issuer:** {site.get('ssl_issuer', 'N/A')}")
                                        st.write(f"**Security Headers:** {site.get('headers_score', 0):.0f}%")
                                    with sec_col2:
                                        st.write(f"**Status Code:** {site.get('status_code', 'N/A')}")
                                        st.write(f"**Redirects:** {site.get('redirect_count', 0)}")
                                        missing_hdrs = site.get('missing_headers', [])
                                        if not isinstance(missing_hdrs, list):
                                            missing_hdrs = []
                                        if missing_hdrs:
                                            st.write(f"**Missing Headers:** {len(missing_hdrs)}")
                                    
                                    # Missing Headers Detail
                                    if missing_hdrs:
                                        with st.expander(f"❌ Missing Security Headers ({len(missing_hdrs)})"):
                                            for hdr in missing_hdrs:
                                                st.write(f"• {hdr}")
                                    
                                    # Security Issues Breakdown
                                    st.markdown("#### 📋 Issues by Priority")
                                    issue_col1, issue_col2, issue_col3, issue_col4 = st.columns(4)
                                    with issue_col1:
                                        st.metric("Critical", site.get('critical_issues', 0))
                                    with issue_col2:
                                        st.metric("High", site.get('high_issues', 0))
                                    with issue_col3:
                                        st.metric("Medium", site.get('medium_issues', 0))
                                    with issue_col4:
                                        st.metric("Low", site.get('low_issues', 0))
                                    
                                    # Top Recommendations
                                    all_recs = site.get('all_recommendations', [])
                                    if not isinstance(all_recs, list):
                                        all_recs = []
                                    critical_recs = [r for r in all_recs if isinstance(r, dict) and r.get('priority') == 'CRITICAL']
                                    high_recs = [r for r in all_recs if isinstance(r, dict) and r.get('priority') == 'HIGH']
                                    
                                    if critical_recs:
                                        st.markdown("#### 🔴 Critical Recommendations")
                                        for rec in critical_recs[:3]:  # Show top 3
                                            st.error(f"**{rec.get('issue')}**")
                                            st.write(f"_{rec.get('impact')}_")
                                    
                                    if high_recs:
                                        st.markdown("#### 🟠 High Priority Recommendations")
                                        for rec in high_recs[:3]:  # Show top 3
                                            st.warning(f"**{rec.get('issue')}**")
                                            st.write(f"_{rec.get('impact')}_")
                                    
                                    # Compliance Failures
                                    st.markdown("#### ✅ Compliance Analysis")
                                    comp_col1, comp_col2, comp_col3, comp_col4 = st.columns(4)
                                    with comp_col1:
                                        st.metric("OWASP", f"{site.get('owasp_score', 0):.0f}%")
                                    with comp_col2:
                                        st.metric("PCI-DSS", f"{site.get('pci_score', 0):.0f}%")
                                    with comp_col3:
                                        st.metric("GDPR", f"{site.get('gdpr_score', 0):.0f}%")
                                    with comp_col4:
                                        st.metric("NIST", f"{site.get('nist_score', 0):.0f}%")
                                    
                                    owasp_fail = site.get('owasp_failures', [])
                                    if not isinstance(owasp_fail, list):
                                        owasp_fail = []
                                    if owasp_fail:
                                        with st.expander(f"❌ OWASP Failures ({len(owasp_fail)})"):
                                            for fail in owasp_fail:
                                                st.write(f"• {fail}")
                                    
                                    pci_fail = site.get('pci_failures', [])
                                    if not isinstance(pci_fail, list):
                                        pci_fail = []
                                    if pci_fail:
                                        with st.expander(f"❌ PCI-DSS Failures ({len(pci_fail)})"):
                                            for fail in pci_fail:
                                                st.write(f"• {fail}")
                        
                        # Best Performing Sites
                        best_sites = sorted([r for r in successful_scans if r.get('risk_level') == 'LOW'], 
                                          key=lambda x: x.get('compliance_score', 0), reverse=True)[:3]
                        if best_sites:
                            st.markdown("---")
                            st.success(f"### 🏆 Top {len(best_sites)} Best Performing Site(s)")
                            for site in best_sites:
                                with st.expander(f"🟢 {site.get('domain', 'Unknown')} - LOW RISK (Compliance: {site.get('compliance_score', 0):.1f}%)"):
                                    col_left, col_right = st.columns(2)
                                    with col_left:
                                        st.write(f"**URL:** {site.get('url')}")
                                        st.write(f"**Risk Score:** {site.get('risk_score', 0)}")
                                        st.write(f"**Compliance:** {site.get('compliance_score', 0):.1f}%")
                                        st.write(f"**HTTPS:** ✅ Enabled")
                                    with col_right:
                                        st.write(f"**Security Headers:** {site.get('headers_score', 0):.0f}%")
                                        st.write(f"**SSL Days Remaining:** {site.get('ssl_days', 0)}")
                                        st.write(f"**OWASP Score:** {site.get('owasp_score', 0):.1f}%")
                                        st.write(f"**PCI-DSS Score:** {site.get('pci_score', 0):.1f}%")
                        
                        # Visual Analytics Section - MIND-BLOWING CHARTS!
                        st.markdown("---")
                        st.subheader("📊 Visual Analytics & Insights")
                        
                        # Create tabs for different visualizations
                        viz_tab1, viz_tab2, viz_tab3, viz_tab4 = st.tabs([
                            "📈 Risk Distribution", 
                            "🔒 Compliance Scores", 
                            "🎯 Vulnerability Heatmap",
                            "⚡ Performance Metrics"
                        ])
                        
                        with viz_tab1:
                            try:
                                import plotly.graph_objects as go
                                
                                col_chart1, col_chart2 = st.columns(2)
                                
                                with col_chart1:
                                    # Risk distribution donut chart
                                    fig_risk = go.Figure(data=[go.Pie(
                                        labels=['HIGH', 'MEDIUM', 'LOW'],
                                        values=[high_risk, medium_risk, low_risk],
                                        marker=dict(colors=['#ff4444', '#ffaa00', '#44ff44']),
                                        hole=0.5,
                                        textinfo='label+percent+value',
                                        textfont_size=13
                                    )])
                                    fig_risk.update_layout(
                                        title="Risk Level Distribution",
                                        height=350,
                                        showlegend=True,
                                        annotations=[dict(text=f'{successful}<br>Sites', x=0.5, y=0.5, font_size=20, showarrow=False)]
                                    )
                                    st.plotly_chart(fig_risk, use_container_width=True)
                                
                                with col_chart2:
                                    # Security issues bar chart
                                    fig_issues = go.Figure(data=[go.Bar(
                                        x=['Critical', 'High', 'Medium'],
                                        y=[total_critical, total_high, total_medium],
                                        marker_color=['#cc0000', '#ff6600', '#ffcc00'],
                                        text=[total_critical, total_high, total_medium],
                                        textposition='outside'
                                    )])
                                    fig_issues.update_layout(
                                        title="Security Issues by Severity",
                                        xaxis_title="Severity",
                                        yaxis_title="Count",
                                        height=350
                                    )
                                    st.plotly_chart(fig_issues, use_container_width=True)
                            except ImportError:
                                st.warning("Install `plotly` for advanced visualizations: `pip install plotly`")
                        
                        with viz_tab2:
                            try:
                                import plotly.graph_objects as go
                                import pandas as pd
                                
                                # Compliance scores grouped bar chart
                                compliance_data = []
                                for site in successful_scans[:10]:  # Limit to first 10 for readability
                                    compliance_data.append({
                                        'Domain': site.get('domain', 'Unknown')[:15],
                                        'OWASP': site.get('owasp_score', 0),
                                        'PCI-DSS': site.get('pci_score', 0),
                                        'GDPR': site.get('gdpr_score', 0),
                                        'NIST': site.get('nist_score', 0)
                                    })
                                
                                if compliance_data:
                                    df = pd.DataFrame(compliance_data)
                                    
                                    fig_compliance = go.Figure()
                                    fig_compliance.add_trace(go.Bar(name='OWASP', x=df['Domain'], y=df['OWASP'], marker_color='#667eea'))
                                    fig_compliance.add_trace(go.Bar(name='PCI-DSS', x=df['Domain'], y=df['PCI-DSS'], marker_color='#764ba2'))
                                    fig_compliance.add_trace(go.Bar(name='GDPR', x=df['Domain'], y=df['GDPR'], marker_color='#f093fb'))
                                    fig_compliance.add_trace(go.Bar(name='NIST', x=df['Domain'], y=df['NIST'], marker_color='#4facfe'))
                                    
                                    fig_compliance.update_layout(
                                        title="Compliance Framework Scores",
                                        xaxis_title="Domain",
                                        yaxis_title="Score (%)",
                                        barmode='group',
                                        height=450,
                                        yaxis=dict(range=[0, 100])
                                    )
                                    st.plotly_chart(fig_compliance, use_container_width=True)
                                    
                                    # Radar chart for average scores
                                    avg_gdpr = sum(r.get('gdpr_score', 0) for r in successful_scans) / len(successful_scans)
                                    avg_nist = sum(r.get('nist_score', 0) for r in successful_scans) / len(successful_scans)
                                    
                                    fig_radar = go.Figure(data=go.Scatterpolar(
                                        r=[avg_owasp, avg_pci, avg_gdpr, avg_nist],
                                        theta=['OWASP', 'PCI-DSS', 'GDPR', 'NIST'],
                                        fill='toself',
                                        marker=dict(color='#667eea', size=8),
                                        line=dict(color='#667eea', width=2)
                                    ))
                                    fig_radar.update_layout(
                                        polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
                                        title="Average Compliance Radar",
                                        height=400
                                    )
                                    st.plotly_chart(fig_radar, use_container_width=True)
                            except ImportError:
                                st.warning("Install `plotly` and `pandas` for visualizations")
                        
                        with viz_tab3:
                            try:
                                import plotly.graph_objects as go
                                import pandas as pd
                                
                                # Vulnerability heatmap
                                heatmap_data = []
                                for site in successful_scans[:15]:
                                    heatmap_data.append({
                                        'Domain': site.get('domain', 'Unknown')[:12],
                                        'Critical': site.get('critical_issues', 0),
                                        'High': site.get('high_issues', 0),
                                        'Medium': site.get('medium_issues', 0),
                                        'Header Gaps': 100 - site.get('headers_score', 0),
                                        'SSL Risk': 0 if site.get('ssl_valid') else 100
                                    })
                                
                                if heatmap_data:
                                    df_heatmap = pd.DataFrame(heatmap_data)
                                    
                                    fig_heatmap = go.Figure(data=go.Heatmap(
                                        z=[df_heatmap['Critical'], df_heatmap['High'], df_heatmap['Medium'], 
                                           df_heatmap['Header Gaps'], df_heatmap['SSL Risk']],
                                        x=df_heatmap['Domain'].tolist(),
                                        y=['Critical', 'High', 'Medium', 'Headers', 'SSL'],
                                        colorscale='Reds',
                                        text=[df_heatmap['Critical'], df_heatmap['High'], df_heatmap['Medium'], 
                                              df_heatmap['Header Gaps'].round(), df_heatmap['SSL Risk']],
                                        texttemplate='%{text}',
                                        textfont={"size": 11},
                                        hoverongaps=False,
                                        colorbar=dict(title="Severity")
                                    ))
                                    fig_heatmap.update_layout(
                                        title="Vulnerability Heatmap (Darker = More Severe)",
                                        height=400,
                                        xaxis_title="Domain",
                                        yaxis_title="Vulnerability Category"
                                    )
                                    st.plotly_chart(fig_heatmap, use_container_width=True)
                            except ImportError:
                                st.warning("Install required packages for heatmap visualization")
                        
                        with viz_tab4:
                            try:
                                import plotly.graph_objects as go
                                
                                col_p1, col_p2 = st.columns(2)
                                
                                with col_p1:
                                    # Response time comparison
                                    perf_data = [(s.get('domain', 'Unknown')[:12], s.get('response_time', 0)) 
                                                for s in successful_scans[:10]]
                                    domains, times = zip(*perf_data) if perf_data else ([], [])
                                    
                                    colors = ['#ff4444' if t > 2 else '#ffaa00' if t > 1 else '#44ff44' for t in times]
                                    
                                    fig_perf = go.Figure(data=[go.Bar(
                                        x=list(domains),
                                        y=list(times),
                                        marker_color=colors,
                                        text=[f"{t:.2f}s" for t in times],
                                        textposition='outside'
                                    )])
                                    fig_perf.update_layout(
                                        title="Response Time",
                                        xaxis_title="Domain",
                                        yaxis_title="Seconds",
                                        height=350
                                    )
                                    st.plotly_chart(fig_perf, use_container_width=True)
                                
                                with col_p2:
                                    # HTTPS adoption gauge
                                    https_pct = (https_enabled / len(successful_scans) * 100) if successful_scans else 0
                                    
                                    fig_gauge = go.Figure(go.Indicator(
                                        mode="gauge+number",
                                        value=https_pct,
                                        domain={'x': [0, 1], 'y': [0, 1]},
                                        title={'text': "HTTPS Adoption %"},
                                        number={'suffix': "%"},
                                        gauge={
                                            'axis': {'range': [None, 100]},
                                            'bar': {'color': "#44ff44" if https_pct >= 80 else "#ffaa00" if https_pct >= 50 else "#ff4444"},
                                            'steps': [
                                                {'range': [0, 50], 'color': "#2a2a2a"},
                                                {'range': [50, 80], 'color': "#3a3a3a"},
                                                {'range': [80, 100], 'color': "#1a4a1a"}
                                            ],
                                            'threshold': {
                                                'line': {'color': "white", 'width': 2},
                                                'thickness': 0.75,
                                                'value': https_pct
                                            }
                                        }
                                    ))
                                    fig_gauge.update_layout(height=350)
                                    st.plotly_chart(fig_gauge, use_container_width=True)
                            except ImportError:
                                st.warning("Install `plotly` for performance visualizations")
                        
                        # Smart Action Dashboard - Priority Fixes
                        st.markdown("---")
                        st.subheader("🎯 Smart Action Dashboard - Priority Recommendations")
                        
                        # Generate smart recommendations based on scan results
                        action_col1, action_col2, action_col3 = st.columns(3)
                        
                        with action_col1:
                            st.markdown("#### 🔴 CRITICAL Actions")
                            critical_actions = []
                            
                            # Check for critical issues
                            no_https_sites = [s for s in successful_scans if not s.get('https_enabled')]
                            if no_https_sites:
                                critical_actions.append({
                                    'action': 'Enable HTTPS',
                                    'affected': len(no_https_sites),
                                    'impact': 'HIGH',
                                    'sites': [s.get('domain', 'Unknown')[:20] for s in no_https_sites[:3]]
                                })
                            
                            expired_ssl = [s for s in successful_scans if s.get('ssl_days', 999) <= 0 and s.get('https_enabled')]
                            if expired_ssl:
                                critical_actions.append({
                                    'action': 'Renew SSL Certificates',
                                    'affected': len(expired_ssl),
                                    'impact': 'CRITICAL',
                                    'sites': [s.get('domain', 'Unknown')[:20] for s in expired_ssl[:3]]
                                })
                            
                            zero_owasp = [s for s in successful_scans if s.get('owasp_score', 0) == 0]
                            if zero_owasp:
                                critical_actions.append({
                                    'action': 'Fix OWASP Failures',
                                    'affected': len(zero_owasp),
                                    'impact': 'CRITICAL',
                                    'sites': [s.get('domain', 'Unknown')[:20] for s in zero_owasp[:3]]
                                })
                            
                            if critical_actions:
                                for action in critical_actions[:3]:
                                    with st.expander(f"⚠️ {action['action']} ({action['affected']} sites)"):
                                        st.error(f"**Impact:** {action['impact']}")
                                        st.write("**Affected sites:**")
                                        for site in action['sites']:
                                            st.write(f"• {site}")
                                        if len(action['sites']) < action['affected']:
                                            st.caption(f"... and {action['affected'] - len(action['sites'])} more")
                            else:
                                st.success("✅ No critical actions needed!")
                        
                        with action_col2:
                            st.markdown("#### 🟡 HIGH Priority")
                            high_actions = []
                            
                            # Missing security headers
                            low_headers = [s for s in successful_scans if s.get('headers_score', 0) < 50]
                            if low_headers:
                                high_actions.append({
                                    'action': 'Add Security Headers',
                                    'affected': len(low_headers),
                                    'benefit': 'Prevent XSS, clickjacking',
                                    'sites': [s.get('domain', 'Unknown')[:20] for s in low_headers[:3]]
                                })
                            
                            # SSL expiring soon
                            expiring_ssl = [s for s in successful_scans if 0 < s.get('ssl_days', 999) <= 30]
                            if expiring_ssl:
                                high_actions.append({
                                    'action': 'Renew Expiring SSL',
                                    'affected': len(expiring_ssl),
                                    'benefit': 'Avoid service disruption',
                                    'sites': [s.get('domain', 'Unknown')[:20] for s in expiring_ssl[:3]]
                                })
                            
                            # PCI-DSS failures
                            low_pci = [s for s in successful_scans if s.get('pci_score', 0) < 50]
                            if low_pci:
                                high_actions.append({
                                    'action': 'PCI-DSS Compliance',
                                    'affected': len(low_pci),
                                    'benefit': 'Payment security',
                                    'sites': [s.get('domain', 'Unknown')[:20] for s in low_pci[:3]]
                                })
                            
                            if high_actions:
                                for action in high_actions[:3]:
                                    with st.expander(f"⚡ {action['action']} ({action['affected']} sites)"):
                                        st.warning(f"**Benefit:** {action['benefit']}")
                                        st.write("**Affected sites:**")
                                        for site in action['sites']:
                                            st.write(f"• {site}")
                            else:
                                st.success("✅ No high priority actions!")
                        
                        with action_col3:
                            st.markdown("#### 🟢 MEDIUM Priority")
                            medium_actions = []
                            
                            # Slow response times
                            slow_sites = [s for s in successful_scans if s.get('response_time', 0) > 2]
                            if slow_sites:
                                medium_actions.append({
                                    'action': 'Optimize Performance',
                                    'affected': len(slow_sites),
                                    'benefit': 'Better user experience',
                                    'metric': f"Avg: {sum(s.get('response_time', 0) for s in slow_sites) / len(slow_sites):.2f}s"
                                })
                            
                            # Missing HSTS
                            no_hsts = [s for s in successful_scans 
                                      if s.get('https_enabled') and 'Strict-Transport-Security' not in str(s.get('present_headers', []))]
                            if len(no_hsts) > len(successful_scans) // 2:
                                medium_actions.append({
                                    'action': 'Enable HSTS Header',
                                    'affected': len(no_hsts),
                                    'benefit': 'Force HTTPS connections',
                                    'metric': f"{len(no_hsts)} sites"
                                })
                            
                            # GDPR improvements
                            low_gdpr = [s for s in successful_scans if s.get('gdpr_score', 0) < 60]
                            if low_gdpr:
                                medium_actions.append({
                                    'action': 'GDPR Compliance',
                                    'affected': len(low_gdpr),
                                    'benefit': 'Data protection compliance',
                                    'metric': f"Avg score: {sum(s.get('gdpr_score', 0) for s in low_gdpr) / len(low_gdpr):.1f}%"
                                })
                            
                            if medium_actions:
                                for action in medium_actions[:3]:
                                    with st.expander(f"ℹ️ {action['action']} ({action['affected']} sites)"):
                                        st.info(f"**Benefit:** {action['benefit']}")
                                        st.write(f"**Metric:** {action['metric']}")
                            else:
                                st.success("✅ All medium priority items addressed!")
                        
                        # Quick Stats Summary
                        st.markdown("---")
                        st.info(f"""
                        **💡 Quick Summary:**  
                        • Total sites scanned: **{successful}**  
                        • High-risk sites: **{high_risk}** ({(high_risk/successful)*100:.1f}% of total)  
                        • Average compliance: **{avg_compliance:.1f}%**  
                        • HTTPS adoption: **{(https_enabled/successful)*100:.1f}%**  
                        • Sites needing immediate action: **{len(critical_sites)}**
                        """)
                        
                        # Comparison Table by Risk Level - Enhanced
                        st.markdown("---")
                        st.subheader("📊 Site Comparison Matrix")
                        
                        comparison_data = []
                        for r in successful_scans:
                            comparison_data.append({
                                'Domain': r.get('domain', 'Unknown'),
                                'Risk': r.get('risk_level', 'UNKNOWN'),
                                'Score': r.get('risk_score', 0),
                                'Grade': r.get('advanced_grade', 'N/A'),
                                'Compliance': f"{r.get('compliance_score', 0):.1f}%",
                                'HTTPS': '✅' if r.get('https_enabled') else '❌',
                                'SSL': '✅' if r.get('ssl_valid') else '❌',
                                'SSL Days': r.get('ssl_days', 0),
                                'Headers': f"{r.get('headers_score', 0):.0f}%",
                                'Response': f"{r.get('response_time', 0):.2f}s",
                                'Critical': r.get('critical_issues', 0),
                                'High': r.get('high_issues', 0),
                                'Total Issues': r.get('critical_issues', 0) + r.get('high_issues', 0) + r.get('medium_issues', 0),
                            })
                        
                        # Sort by risk level and score
                        risk_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'UNKNOWN': 3}
                        comparison_data.sort(key=lambda x: (risk_order.get(x['Risk'], 3), -x['Score']))
                        
                        st.dataframe(comparison_data, use_container_width=True, hide_index=True)
                        
                        # Additional Intelligence Sections
                        st.markdown("---")
                        st.subheader("🔍 Security Intelligence")
                        
                        intel_tab1, intel_tab2, intel_tab3 = st.tabs(["🛡️ Headers Analysis", "🌐 Network Insights", "⚖️ Compliance Details"])
                        
                        with intel_tab1:
                            st.markdown("#### Security Headers Coverage")
                            
                            # Aggregate headers data
                            all_missing = {}
                            all_present = {}
                            for r in successful_scans:
                                for hdr in r.get('missing_headers', []):
                                    all_missing[hdr] = all_missing.get(hdr, 0) + 1
                                for hdr in r.get('present_headers', []):
                                    all_present[hdr] = all_present.get(hdr, 0) + 1
                            
                            if all_missing:
                                st.markdown("**Most Commonly Missing Headers:**")
                                sorted_missing = sorted(all_missing.items(), key=lambda x: x[1], reverse=True)
                                for hdr, count in sorted_missing[:10]:
                                    pct = (count / successful) * 100
                                    st.write(f"• **{hdr}**: Missing from {count}/{successful} sites ({pct:.0f}%)")
                            
                            if all_present:
                                st.markdown("**Most Commonly Implemented Headers:**")
                                sorted_present = sorted(all_present.items(), key=lambda x: x[1], reverse=True)
                                for hdr, count in sorted_present[:10]:
                                    pct = (count / successful) * 100
                                    st.success(f"✅ **{hdr}**: Present on {count}/{successful} sites ({pct:.0f}%)")
                        
                        with intel_tab2:
                            st.markdown("#### Network & Performance Metrics")
                            
                            # Response time analysis
                            response_times = [r.get('response_time', 0) for r in successful_scans]
                            avg_response = sum(response_times) / len(response_times) if response_times else 0
                            max_response = max(response_times) if response_times else 0
                            min_response = min(response_times) if response_times else 0
                            
                            perf_col1, perf_col2, perf_col3 = st.columns(3)
                            with perf_col1:
                                st.metric("Avg Response Time", f"{avg_response:.2f}s")
                            with perf_col2:
                                st.metric("Fastest", f"{min_response:.2f}s")
                            with perf_col3:
                                st.metric("Slowest", f"{max_response:.2f}s")
                            
                            # Redirect analysis
                            total_redirects = sum(r.get('redirect_count', 0) for r in successful_scans)
                            sites_with_redirects = sum(1 for r in successful_scans if r.get('redirect_count', 0) > 0)
                            
                            st.markdown("**Redirect Analysis:**")
                            st.write(f"• Sites with redirects: {sites_with_redirects}/{successful}")
                            st.write(f"• Total redirects: {total_redirects}")
                            
                            # Domain registrar distribution
                            registrars = {}
                            for r in successful_scans:
                                reg = r.get('registrar', 'Unknown')
                                if reg != 'Unknown':
                                    registrars[reg] = registrars.get(reg, 0) + 1
                            
                            if registrars:
                                st.markdown("**Top Registrars:**")
                                sorted_regs = sorted(registrars.items(), key=lambda x: x[1], reverse=True)
                                for reg, count in sorted_regs[:5]:
                                    st.write(f"• {reg}: {count} domain(s)")
                        
                        with intel_tab3:
                            st.markdown("#### Compliance Framework Breakdown")
                            
                            # Most common compliance failures
                            all_owasp_fails = {}
                            all_pci_fails = {}
                            all_gdpr_fails = {}
                            
                            for r in successful_scans:
                                for fail in r.get('owasp_failures', []):
                                    all_owasp_fails[fail] = all_owasp_fails.get(fail, 0) + 1
                                for fail in r.get('pci_failures', []):
                                    all_pci_fails[fail] = all_pci_fails.get(fail, 0) + 1
                                for fail in r.get('gdpr_failures', []):
                                    all_gdpr_fails[fail] = all_gdpr_fails.get(fail, 0) + 1
                            
                            # Show summary stats first
                            comp_sum_col1, comp_sum_col2, comp_sum_col3 = st.columns(3)
                            with comp_sum_col1:
                                st.metric("🔐 OWASP Failures", len(all_owasp_fails))
                            with comp_sum_col2:
                                st.metric("💳 PCI-DSS Failures", len(all_pci_fails))
                            with comp_sum_col3:
                                st.metric("🇪🇺 GDPR Failures", len(all_gdpr_fails))
                            
                            st.markdown("---")
                            
                            if all_owasp_fails:
                                st.markdown("**🔐 Top OWASP Top 10 Failures:**")
                                sorted_owasp = sorted(all_owasp_fails.items(), key=lambda x: x[1], reverse=True)
                                for fail, count in sorted_owasp[:5]:
                                    st.error(f"• **{fail}**: {count}/{successful} sites affected")
                            else:
                                st.info("✅ No OWASP Top 10 check failures detected, or checks passed successfully.")
                            
                            if all_pci_fails:
                                st.markdown("**💳 Top PCI-DSS Failures:**")
                                sorted_pci = sorted(all_pci_fails.items(), key=lambda x: x[1], reverse=True)
                                for fail, count in sorted_pci[:5]:
                                    st.warning(f"• **{fail}**: {count}/{successful} sites affected")
                            else:
                                st.info("✅ No PCI-DSS check failures detected, or checks passed successfully.")
                            
                            if all_gdpr_fails:
                                st.markdown("**🇪🇺 Top GDPR Security Failures:**")
                                sorted_gdpr = sorted(all_gdpr_fails.items(), key=lambda x: x[1], reverse=True)
                                for fail, count in sorted_gdpr[:5]:
                                    st.warning(f"• **{fail}**: {count}/{successful} sites affected")
                            else:
                                st.info("✅ No GDPR security check failures detected, or checks passed successfully.")
                            
                            # Add explanation if all are empty
                            if not (all_owasp_fails or all_pci_fails or all_gdpr_fails):
                                st.markdown("---")
                                st.info("""
                                **💡 Why is this empty?**
                                
                                This section shows specific compliance check failures. If it's empty, it means either:
                                1. ✅ All compliance checks passed (unlikely with low scores)
                                2. ⚠️ The scan couldn't retrieve detailed failure information
                                
                                Your overall compliance scores above show the actual compliance percentage.
                                Check the "Critical Findings" section for detailed vulnerability information.
                                """)
                    
                    # Detailed Results Table
                    st.markdown("---")
                    st.subheader("📋 Full Detailed Results")
                    st.caption("Complete scan data for all sites")
                    
                    # Display option for detailed view
                    show_full_details = st.checkbox("Show all columns", value=False, key="show_full_batch")
                    
                    if show_full_details:
                        st.dataframe(results_summary, use_container_width=True)
                    else:
                        # Simplified view
                        simplified = []
                        for r in results_summary:
                            if r.get('status') == 'success':
                                simplified.append({
                                    'Domain': r.get('domain'),
                                    'Risk': r.get('risk_level'),
                                    'Compliance': f"{r.get('compliance_score', 0):.1f}%",
                                    'HTTPS': '✅' if r.get('https_enabled') else '❌',
                                    'Status': '✅ Success'
                                })
                            else:
                                error_msg = r.get('error', 'Unknown error')
                                # Make error message more helpful
                                if 'Invalid' in error_msg or 'invalid' in error_msg:
                                    error_msg = f"{error_msg} (Not a valid website URL)"
                                simplified.append({
                                    'Domain': r.get('url', 'Unknown')[:50],
                                    'Risk': 'ERROR',
                                    'Compliance': 'N/A',
                                    'HTTPS': 'N/A',
                                    'Status': f"❌ {error_msg[:60]}"
                                })
                        st.dataframe(simplified, use_container_width=True, hide_index=True)
                    
                    # Export Options
                    st.markdown("---")
                    st.subheader("📥 Export Options")
                    
                    export_col1, export_col2, export_col3 = st.columns(3)

                    batch_payload = {
                        'type': 'batch_scan',
                        'started_at': started_at.isoformat(),
                        'ended_at': ended_at.isoformat(),
                        'duration_seconds': (ended_at - started_at).total_seconds(),
                        'summary': {
                            'total': len(results_summary),
                            'successful': successful,
                            'failed': failed,
                            'high_risk': high_risk if successful_scans else 0,
                            'medium_risk': medium_risk if successful_scans else 0,
                            'low_risk': low_risk if successful_scans else 0,
                            'avg_compliance': avg_compliance if successful_scans else 0,
                            'avg_headers': avg_headers if successful_scans else 0,
                            'total_critical_issues': total_critical if successful_scans else 0,
                        },
                        'results': results_summary,
                    }

                    json_bytes = json.dumps(batch_payload, indent=2, default=str).encode('utf-8')
                    
                    with export_col1:
                        st.download_button(
                            label="📥 Download Full JSON Report",
                            data=json_bytes,
                            file_name=f"batch_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                            mime="application/json",
                            key="dl_batch_json",
                            use_container_width=True,
                        )

                    with export_col2:
                        csv_buf = io.StringIO()
                        writer = csv.DictWriter(
                            csv_buf,
                            fieldnames=[
                                'url', 'domain', 'https_enabled', 'risk_level', 'risk_score', 
                                'compliance_score', 'headers_score', 'ssl_valid', 'ssl_days',
                                'critical_issues', 'high_issues', 'medium_issues', 'status', 'error'
                            ],
                        )
                        writer.writeheader()
                        for row in results_summary:
                            writer.writerow({
                                'url': row.get('url'),
                                'domain': row.get('domain'),
                                'https_enabled': row.get('https_enabled'),
                                'risk_level': row.get('risk_level'),
                                'risk_score': row.get('risk_score'),
                                'compliance_score': row.get('compliance_score'),
                                'headers_score': row.get('headers_score'),
                                'ssl_valid': row.get('ssl_valid'),
                                'ssl_days': row.get('ssl_days'),
                                'critical_issues': row.get('critical_issues'),
                                'high_issues': row.get('high_issues'),
                                'medium_issues': row.get('medium_issues'),
                                'status': row.get('status'),
                                'error': row.get('error'),
                            })
                        st.download_button(
                            label="📥 Download CSV Report",
                            data=csv_buf.getvalue().encode('utf-8'),
                            file_name=f"batch_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            mime="text/csv",
                            key="dl_batch_csv",
                            use_container_width=True,
                        )
                    
                    with export_col3:
                        # Executive Summary Text Report
                        exec_report = f"""BATCH SECURITY SCAN - EXECUTIVE REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY
========
Total Sites Scanned: {len(results_summary)}
Successful: {successful} | Failed: {failed}
Duration: {(ended_at - started_at).total_seconds():.1f}s

RISK DISTRIBUTION
=================
HIGH Risk:   {high_risk if successful_scans else 0} ({(high_risk/successful)*100 if successful > 0 else 0:.0f}%)
MEDIUM Risk: {medium_risk if successful_scans else 0} ({(medium_risk/successful)*100 if successful > 0 else 0:.0f}%)
LOW Risk:    {low_risk if successful_scans else 0} ({(low_risk/successful)*100 if successful > 0 else 0:.0f}%)

SECURITY POSTURE
================
HTTPS Enabled:     {https_enabled if successful_scans else 0}/{successful}
Valid SSL:         {ssl_valid if successful_scans else 0}/{successful}
Avg Compliance:    {avg_compliance if successful_scans else 0:.1f}%
Avg Headers Score: {avg_headers if successful_scans else 0:.0f}%

CRITICAL ISSUES
===============
Total Critical: {total_critical if successful_scans else 0}
Total High:     {total_high if successful_scans else 0}
Total Medium:   {total_medium if successful_scans else 0}

COMPLIANCE FRAMEWORKS
=====================
OWASP Top 10: {avg_owasp if successful_scans else 0:.1f}%
PCI-DSS:      {avg_pci if successful_scans else 0:.1f}%

CRITICAL FINDINGS
=================
"""
                        if critical_sites:
                            for site in critical_sites:
                                exec_report += f"\n🔴 {site.get('domain', 'Unknown')}\n"
                                exec_report += f"   Risk Score: {site.get('risk_score', 0)}\n"
                                exec_report += f"   Compliance: {site.get('compliance_score', 0):.1f}%\n"
                                exec_report += f"   Critical Issues: {site.get('critical_issues', 0)}\n"
                        else:
                            exec_report += "\nNo critical findings.\n"
                        
                        st.download_button(
                            label="📥 Download Executive Summary",
                            data=exec_report.encode('utf-8'),
                            file_name=f"executive_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                            mime="text/plain",
                            key="dl_batch_exec",
                            use_container_width=True,
                        )

        with dev_tab2:
            st.subheader("Continuous Monitoring")
            st.caption("Manage simple schedules (stored as JSON in the schedules/ folder).")

            schedules_dir = Path('schedules')
            schedules_dir.mkdir(exist_ok=True)

            with st.form("create_schedule"):
                sched_url = st.text_input("URL to monitor", placeholder="https://example.com", key="sched_url")
                sched_frequency = st.selectbox("Frequency", ["hourly", "daily", "weekly"], key="sched_freq")
                sched_time = st.text_input("Time (HH:MM)", value="09:00", key="sched_time")
                submitted = st.form_submit_button("💾 Save Schedule")

            if submitted:
                if not sched_url.strip():
                    st.error("Please enter a URL.")
                else:
                    schedule_file = schedules_dir / f"monitor_{_safe_slug(sched_url.replace('https://', '').replace('http://', ''))}.json"
                    config = {
                        'url': sched_url.strip(),
                        'frequency': sched_frequency,
                        'time': sched_time.strip(),
                        'created_at': datetime.now().isoformat(),
                        'enabled': True,
                    }
                    _write_schedule_file(schedule_file, config)
                    st.success(f"Saved: {schedule_file}")

            schedule_files = sorted(schedules_dir.glob('*.json'))
            if not schedule_files:
                st.info("No schedules yet.")
            else:
                st.markdown("---")
                st.write("Existing schedules:")

                for sf in schedule_files:
                    try:
                        with sf.open('r', encoding='utf-8') as f:
                            cfg = json.load(f)
                    except Exception:
                        cfg = {}

                    url = cfg.get('url', 'Unknown')
                    freq = cfg.get('frequency', 'N/A')
                    tval = cfg.get('time', 'N/A')
                    enabled = bool(cfg.get('enabled', True))

                    c1, c2, c3, c4, c5 = st.columns([1, 3, 2, 2, 1])
                    with c1:
                        new_enabled = st.checkbox("On", value=enabled, key=f"en_{sf.name}")
                    with c2:
                        st.write(url)
                    with c3:
                        st.write(freq)
                    with c4:
                        st.write(tval)
                    with c5:
                        if st.button("🗑️", key=f"del_{sf.name}"):
                            try:
                                sf.unlink(missing_ok=True)
                            except Exception as e:
                                st.error(str(e))
                            st.rerun()

                    if new_enabled != enabled:
                        cfg['enabled'] = new_enabled
                        _write_schedule_file(sf, cfg)

                st.markdown("---")
                if st.button("▶ Run Enabled Schedules Now", key="run_schedules"):
                    scanner = WebsiteScanner()
                    enabled_files = []
                    for sf in sorted(schedules_dir.glob('*.json')):
                        try:
                            with sf.open('r', encoding='utf-8') as f:
                                cfg = json.load(f)
                            if cfg.get('enabled', True):
                                enabled_files.append(cfg)
                        except Exception:
                            continue

                    if not enabled_files:
                        st.warning("No enabled schedules to run.")
                    else:
                        # Create reports directory for this scheduled run
                        reports_dir = Path('reports')
                        reports_dir.mkdir(exist_ok=True)
                        scheduled_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        scheduled_run_dir = reports_dir / f"scheduled_{scheduled_timestamp}"
                        scheduled_run_dir.mkdir(exist_ok=True)

                        prog = st.progress(0)
                        out = st.empty()
                        run_results: list[dict] = []
                        for idx, cfg in enumerate(enabled_files, 1):
                            url = cfg.get('url')
                            out.info(f"[{idx}/{len(enabled_files)}] Scanning: {url}")
                            prog.progress(int((idx - 1) / max(len(enabled_files), 1) * 100))
                            try:
                                result = scanner.scan(url)
                                if 'error' in result:
                                    run_results.append({'url': url, 'status': 'error', 'error': result.get('error')})
                                else:
                                    url_info = result.get('url_info', {})
                                    risk = result.get('risk_assessment', {})
                                    domain = url_info.get('domain', 'unknown')
                                    
                                    # Save individual report
                                    report_file = scheduled_run_dir / f"{domain}_{scheduled_timestamp}.json"
                                    with report_file.open('w', encoding='utf-8') as f:
                                        json.dump(result, f, indent=2, default=str)
                                    
                                    run_results.append({
                                        'url': url_info.get('original_url', url),
                                        'domain': domain,
                                        'risk_level': risk.get('level'),
                                        'risk_score': risk.get('score'),
                                        'status': 'success',
                                        'report_file': str(report_file),
                                    })
                            except Exception as e:
                                run_results.append({'url': url, 'status': 'error', 'error': str(e)})

                        prog.progress(100)
                        out.success(f"✅ Scheduled run complete - Reports saved to {scheduled_run_dir}")
                        st.dataframe(run_results, use_container_width=True)
                        
                        # Save summary file
                        summary_file = scheduled_run_dir / "summary.json"
                        with summary_file.open('w', encoding='utf-8') as f:
                            json.dump({
                                'type': 'scheduled_run',
                                'timestamp': scheduled_timestamp,
                                'total': len(run_results),
                                'successful': sum(1 for r in run_results if r.get('status') == 'success'),
                                'failed': sum(1 for r in run_results if r.get('status') == 'error'),
                                'results': run_results,
                            }, f, indent=2, default=str)
                        
                        st.download_button(
                            label="📥 Download Summary JSON",
                            data=json.dumps(run_results, indent=2, default=str).encode('utf-8'),
                            file_name=f"scheduled_run_{scheduled_timestamp}.json",
                            mime="application/json",
                            key="dl_sched_json",
                        )
    
    # Input section
    st.markdown("---")
    url_input = st.text_input(
        "Enter Website URL",
        placeholder="https://example.com",
        help="Enter the full URL including http:// or https://"
    )
    
    col1, col2, col3 = st.columns([1, 1, 4])
    with col1:
        scan_button = st.button("🚀 Start Scan", type="primary")
    with col2:
        clear_button = st.button("🗑️ Clear")
    
    if clear_button:
        st.rerun()
    
    # Scan execution
    if scan_button and url_input:
        # Real-time progress UI
        st.markdown("---")
        st.subheader("🔄 Live Scan Progress")
        
        # Progress indicators
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Live metrics
        metric_cols = st.columns(4)
        with metric_cols[0]:
            https_metric = st.empty()
            https_metric.metric("HTTPS", "⏳ Checking...", delta=None)
        with metric_cols[1]:
            ssl_metric = st.empty()
            ssl_metric.metric("SSL", "⏳ Checking...", delta=None)
        with metric_cols[2]:
            headers_metric = st.empty()
            headers_metric.metric("Headers", "⏳ Checking...", delta=None)
        with metric_cols[3]:
            risk_metric = st.empty()
            risk_metric.metric("Risk", "⏳ Analyzing...", delta=None)
        
        # Live score card
        score_card = st.empty()
        
        # Step 1: Initialize scan
        progress_bar.progress(10)
        status_text.info("📍 Step 1/9: Validating URL...")
        time.sleep(0.3)
        
        # Step 2: DNS
        progress_bar.progress(20)
        status_text.info("📍 Step 2/9: Performing DNS lookups...")
        time.sleep(0.3)
        
        # Step 3: Start scan
        progress_bar.progress(30)
        status_text.info("📍 Step 3/9: Fetching HTTP response...")
        
        # Run actual scan
        scanner = WebsiteScanner()
        results = scanner.scan(url_input)
        
        # Check for errors
        if 'error' in results:
            progress_bar.progress(100)
            status_text.error("❌ Scan failed")
            st.error(f"❌ Error: {results['error']}")
            return
        
        # Step 4: HTTPS Check
        progress_bar.progress(45)
        status_text.info("📍 Step 4/9: Verifying HTTPS...")
        https_enabled = results.get('url_info', {}).get('https_enabled', False)
        https_metric.metric("HTTPS", 
                           "✅ Enabled" if https_enabled else "❌ Disabled",
                           delta="Secure" if https_enabled else "Insecure",
                           delta_color="normal" if https_enabled else "inverse")
        time.sleep(0.2)
        
        # Step 5: SSL Analysis
        progress_bar.progress(55)
        status_text.info("📍 Step 5/9: Analyzing SSL certificate...")
        cert = results.get('ssl_certificate', {})
        if cert and not cert.get('error'):
            days = cert.get('days_until_expiry', 0)
            if days > 60:
                grade, color = "A+", "normal"  # Excellent: 60+ days validity
            elif days > 30:
                grade, color = "B", "off"  # Good: 31-60 days validity
            elif days > 0:
                grade, color = "C", "inverse"  # Warning: 1-30 days validity
            else:
                grade, color = "F", "inverse"  # Critical: Expired certificate
            ssl_metric.metric("SSL Grade", grade,
                            delta=f"{days}d" if days > 0 else "Expired",
                            delta_color=color)
        else:
            ssl_metric.metric("SSL", "N/A", delta="No cert")
        time.sleep(0.2)
        
        # Step 6: Headers
        progress_bar.progress(65)
        status_text.info("📍 Step 6/9: Analyzing security headers...")
        headers = results.get('security_headers', {})
        score = headers.get('score', 0)
        # Headers: 70%+ Strong, 40-69% OK, <40% Weak
        headers_metric.metric("Headers", f"{score:.0f}%",
                             delta="Strong" if score >= 70 else "Weak" if score < 40 else "OK",
                             delta_color="normal" if score >= 70 else "inverse" if score < 40 else "off")
        time.sleep(0.2)
        
        # Step 7: Recommendations
        progress_bar.progress(80)
        status_text.info("📍 Step 7/9: Generating recommendations...")
        time.sleep(0.2)
        
        # Step 8: Compliance
        progress_bar.progress(90)
        status_text.info("📍 Step 8/9: Validating compliance...")
        time.sleep(0.2)
        
        # Step 9: Risk Assessment
        progress_bar.progress(100)
        status_text.success("✅ Step 9/9: Scan complete!")
        
        risk = results.get('risk_assessment', {})
        risk_level = risk.get('level', 'UNKNOWN')
        risk_score = risk.get('score', 0)
        
        if risk_level == 'HIGH':
            risk_metric.metric("Risk", "🔴 HIGH", delta=f"{risk_score}")  # Critical security issues found
        elif risk_level == 'MEDIUM':
            risk_metric.metric("Risk", "🟡 MEDIUM", delta=f"{risk_score}")  # Some security concerns present
        else:
            risk_metric.metric("Risk", "🟢 LOW", delta=f"{risk_score}")  # Good security posture
        
        # Final Score Card (compact version)
        compliance = results.get('compliance', {})
        compliance_score = compliance.get('overall_score', 0)
        recommendations = results.get('recommendations', [])
        critical = len([r for r in recommendations if r['priority'] == 'CRITICAL'])
        high = len([r for r in recommendations if r['priority'] == 'HIGH'])
        
        # Simple metrics display
        score_cols = score_card.columns(4)
        with score_cols[0]:
            st.metric("Compliance", f"{compliance_score:.1f}%")
        with score_cols[1]:
            st.metric("Issues", len(recommendations))
        with score_cols[2]:
            st.metric("Critical", critical)
        with score_cols[3]:
            st.metric("High", high)
        
        # Display results
        st.markdown("---")
        
        # Create tabs for different sections
        tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
            "📊 Overview",
            "🌐 Network",
            "🔒 Security",
            "📄 Page Content",
            "🔍 WHOIS",
            "💡 Recommendations",
            "✅ Compliance",
            "📥 Export"
        ])
        
        # Tab 1: Overview
        with tab1:
            st.header("Overview")
            
            url_info = results.get('url_info', {})
            risk = results.get('risk_assessment', {})
            
            # Risk badge
            risk_level = risk.get('level', 'UNKNOWN')
            risk_score = risk.get('score', 0)
            
            if risk_level == 'HIGH':
                st.error(f"🔴 Risk Level: **{risk_level}** (Score: {risk_score})")
                st.markdown("""<div style="padding: 10px; background-color: rgba(244, 67, 54, 0.1); border-left: 4px solid #f44336; border-radius: 4px; margin: 10px 0;">
                <strong>HIGH RISK:</strong> Critical security vulnerabilities detected. Immediate action required. Site may be vulnerable to attacks or lack essential security protections.
                </div>""", unsafe_allow_html=True)
            elif risk_level == 'MEDIUM':
                st.warning(f"🟡 Risk Level: **{risk_level}** (Score: {risk_score})")
                st.markdown("""<div style="padding: 10px; background-color: rgba(255, 193, 7, 0.1); border-left: 4px solid #FFC107; border-radius: 4px; margin: 10px 0;">
                <strong>MEDIUM RISK:</strong> Some security concerns present. Site has partial security measures but improvements needed to meet best practices.
                </div>""", unsafe_allow_html=True)
            else:
                st.success(f"🟢 Risk Level: **{risk_level}** (Score: {risk_score})")
                st.markdown("""<div style="padding: 10px; background-color: rgba(76, 175, 80, 0.1); border-left: 4px solid #4CAF50; border-radius: 4px; margin: 10px 0;">
                <strong>LOW RISK:</strong> Good security posture detected. Site implements recommended security measures and follows industry best practices.
                </div>""", unsafe_allow_html=True)
            
            # Key metrics in columns
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("HTTPS", "✅" if url_info.get('https_enabled') else "❌")
            
            with col2:
                cert = results.get('ssl_certificate', {})
                if cert and not cert.get('error'):
                    days = cert.get('days_until_expiry', 0)
                    st.metric("Certificate", f"{days} days" if days else "Valid")
                else:
                    st.metric("Certificate", "N/A")
            
            with col3:
                headers = results.get('security_headers', {})
                score = headers.get('score', 0)
                st.metric("Security Headers", f"{score}%")
            
            with col4:
                whois = results.get('whois', {})
                age = whois.get('domain_age', 'Unknown')
                st.metric("Domain Age", age)
            
            # URL info
            st.subheader("URL Information")
            
            # Check for phishing indicators first
            phishing_indicators = url_info.get('phishing_indicators', [])
            if phishing_indicators:
                st.error("🚨 **PHISHING TECHNIQUE DETECTED!**")
                for indicator in phishing_indicators:
                    st.markdown(f"""
                    <div style="padding: 15px; background-color: rgba(244, 67, 54, 0.15); border-left: 5px solid #f44336; border-radius: 4px; margin: 10px 0;">
                        <strong style="color: #d32f2f;">⚠️ {indicator}</strong><br><br>
                        <span style="color: #c62828;">This is a common phishing technique to trick users into thinking they're visiting a legitimate site!</span>
                    </div>
                    """, unsafe_allow_html=True)
            
            st.write(f"**Original URL:** {url_info.get('original_url')}")
            st.write(f"**Final URL:** {url_info.get('final_url')}")
            st.write(f"**Domain:** {url_info.get('domain')}")
            
            if url_info.get('redirect_count', 0) > 0:
                st.write(f"**Redirects:** {url_info['redirect_count']}")
            
            # Risk factors
            st.subheader("Risk Factors")
            factors = risk.get('factors', [])
            for factor in factors:
                if factor == "No significant issues detected":
                    st.success(f"✅ {factor}")
                else:
                    st.warning(f"⚠️ {factor}")
        
        # Tab 2: Network
        with tab2:
            st.header("Network Information")
            
            network = results.get('network_info', {})
            
            # Show HTTP errors if present
            if network.get('http_error'):
                st.error(f"🚨 **HTTP Request Failed:** {network['http_error']}")
                st.markdown("""
                <div style="padding: 10px; background-color: rgba(244, 67, 54, 0.1); border-left: 4px solid #f44336; border-radius: 4px; margin: 10px 0;">
                    <strong>This could indicate:</strong><br>
                    • Connection timeout (server not responding)<br>
                    • Connection refused (service down/blocked)<br>
                    • DNS resolution failure<br>
                    • Invalid URL or redirect loop<br>
                    • Network connectivity issues<br>
                    <br>
                    <strong style="color: #d32f2f;">⚠️ Malicious sites often have connection issues!</strong>
                </div>
                """, unsafe_allow_html=True)
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("HTTP Response")
                st.write(f"**Status Code:** {network.get('status_code', 'N/A')}")
                st.write(f"**Response Time:** {network.get('response_time', 0):.2f}s")
                st.write(f"**IP Address:** {network.get('ip_address', 'N/A')}")
            
            with col2:
                st.subheader("DNS Records")
                dns = network.get('dns_records', {})
                
                # Show DNS errors if present
                dns_errors = dns.get('errors', {})
                if dns_errors:
                    st.warning("⚠️ **DNS Issues Detected:**")
                    for record_type, error in dns_errors.items():
                        if record_type != 'general':
                            st.write(f"• {record_type}: {error}")
                        else:
                            st.error(f"❌ {error}")
                
                if dns.get('A'):
                    st.write(f"**A Records:** {', '.join(dns['A'][:3])}")
                elif not dns_errors.get('A'):
                    st.write("**A Records:** None found")
                    
                if dns.get('AAAA'):
                    st.write(f"**AAAA Records:** {', '.join(dns['AAAA'][:3])}")
                    
                if dns.get('NS'):
                    st.write(f"**Name Servers:** {', '.join(dns['NS'][:3])}")
                elif not dns_errors.get('NS'):
                    st.write("**Name Servers:** None found")
                    
                if dns.get('MX'):
                    st.write(f"**MX Records:** {', '.join(dns['MX'][:3])}")
            
            # Redirect chain
            redirect_chain = network.get('redirect_chain', [])
            if redirect_chain:
                st.subheader("Redirect Chain")
                for i, redirect in enumerate(redirect_chain, 1):
                    st.write(f"{i}. {redirect['url']} → {redirect['status']}")
        
        # Tab 3: Security
        with tab3:
            st.header("Security Analysis")
            
            # Advanced Score Display
            adv_score = results.get('advanced_score', {})
            if adv_score:
                st.subheader("🎯 Advanced Security Score")
                
                overall = adv_score.get('overall_score', 0)
                grade = adv_score.get('grade', 'F')
                
                # Overall score card
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Overall Score", f"{overall:.1f}/100")
                with col2:
                    if grade in ['A+', 'A', 'A-']:
                        st.metric("Grade", f"🟢 {grade}")
                    elif grade in ['B+', 'B', 'B-']:
                        st.metric("Grade", f"🟡 {grade}")
                    elif grade in ['C+', 'C', 'C-']:
                        st.metric("Grade", f"🟠 {grade}")
                    else:
                        st.metric("Grade", f"🔴 {grade}")
                with col3:
                    risk_level = results.get('risk_assessment', {}).get('level', 'UNKNOWN')
                    st.metric("Risk Level", risk_level)
                
                # Grade explanation
                with st.expander("📖 What does my grade mean?"):
                    st.markdown("""
                    **Security Grade Scale:**
                    
                    - **A+ / A / A-** (90-100): 🟢 **Excellent** - Industry-leading security posture with comprehensive protections
                    - **B+ / B / B-** (80-89): 🟡 **Good** - Strong security with minor improvements possible
                    - **C+ / C / C-** (70-79): 🟠 **Fair** - Basic security present but significant gaps exist
                    - **D+ / D / D-** (60-69): 🟠 **Poor** - Weak security with multiple vulnerabilities
                    - **F** (0-59): 🔴 **Critical** - Severe security deficiencies requiring immediate attention
                    
                    **Score is calculated from 10 categories:**
                    HTTPS encryption, SSL/TLS quality, security headers, certificate validation, domain reputation, 
                    redirect safety, cookie security, content security, DNS security, and response security.
                    """)
                
                # Category breakdown
                st.subheader("📊 Category Scores")
                st.caption("Each category is scored 0-100%. Higher scores indicate better security.")
                categories = adv_score.get('category_scores', {})
                
                if categories:
                    # Define what 0% means for each category
                    zero_explanations = {
                        'https': '❌ Site uses HTTP - no encryption',
                        'ssl_quality': '❌ No SSL certificate available',
                        'security_headers': '❌ All security headers missing',
                        'certificate_validation': '❌ No certificate to validate',
                        'domain_reputation': '⚠️ Suspicious domain characteristics',
                        'redirect_safety': '⚠️ Redirect analysis unavailable',
                        'cookie_security': '⚠️ No secure cookies detected',
                        'content_security': '⚠️ Content analysis limited/failed',
                        'dns_security': '⚠️ DNS information incomplete',
                        'response_security': '⚠️ Server response issues'
                    }
                    
                    for category, score in categories.items():
                        # Format category name
                        display_name = category.replace('_', ' ').title()
                        
                        # Determine color
                        if score >= 80:
                            color = "#4CAF50"  # Green
                        elif score >= 60:
                            color = "#FFC107"  # Yellow
                        elif score >= 40:
                            color = "#FF9800"  # Orange
                        else:
                            color = "#F44336"  # Red
                        
                        # Progress bar with custom color and explanation
                        st.markdown(f"**{display_name}**")
                        
                        if score == 0:
                            explanation = zero_explanations.get(category, '❌ Feature not implemented or unavailable')
                            st.markdown(f"""
                            <div style="background-color: #f0f0f0; border-radius: 5px; height: 25px; position: relative; margin: 5px 0 5px 0;">
                                <div style="background-color: {color}; height: 100%; width: 5%; border-radius: 5px; display: flex; align-items: center; justify-content: center;">
                                    <span style="color: white; font-weight: bold; font-size: 12px;">0%</span>
                                </div>
                            </div>
                            <div style="margin: 0 0 15px 0; padding: 5px; background-color: rgba(244, 67, 54, 0.1); border-radius: 3px;">
                                <small style="color: #d32f2f;">{explanation}</small>
                            </div>
                            """, unsafe_allow_html=True)
                        else:
                            st.markdown(f"""
                            <div style="background-color: #f0f0f0; border-radius: 5px; height: 25px; position: relative; margin: 5px 0 15px 0;">
                                <div style="background-color: {color}; height: 100%; width: {score}%; border-radius: 5px; display: flex; align-items: center; justify-content: center;">
                                    <span style="color: white; font-weight: bold; font-size: 12px;">{score:.1f}%</span>
                                </div>
                            </div>
                            """, unsafe_allow_html=True)
                
                st.markdown("---")
            
            # SSL Certificate
            st.subheader("🔒 SSL/TLS Certificate")
            cert = results.get('ssl_certificate', {})
            url_info = results.get('url_info', {})
            
            if not url_info.get('https_enabled'):
                st.error("❌ **No HTTPS - Site uses unencrypted HTTP**")
                st.markdown("""
                <div style="padding: 10px; background-color: rgba(244, 67, 54, 0.1); border-left: 4px solid #f44336; border-radius: 4px; margin: 10px 0;">
                    <strong>🚨 Critical Security Risk</strong><br>
                    • All traffic is transmitted in <strong>plain text</strong><br>
                    • Passwords, credit cards, and personal data can be <strong>intercepted</strong><br>
                    • No certificate = No identity verification<br>
                    • Modern browsers show "Not Secure" warning<br>
                    <br>
                    <strong>⚠️ This is a MAJOR red flag for malicious sites!</strong>
                </div>
                """, unsafe_allow_html=True)
            elif cert and not cert.get('error'):
                issuer = cert.get('issuer', {})
                st.success("✅ **Valid SSL/TLS Certificate Found**")
                st.write(f"**Issuer:** {issuer.get('organizationName', issuer.get('commonName', 'N/A'))}")
                st.write(f"**Valid Until:** {cert.get('not_after', 'N/A')}")
                
                if cert.get('is_expired'):
                    st.error("⚠️ Certificate is EXPIRED!")
                elif cert.get('days_until_expiry') is not None:
                    days = cert['days_until_expiry']
                    if days < 30:
                        st.warning(f"⚠️ Certificate expires in {days} days")
                    else:
                        st.success(f"✅ Certificate valid for {days} days")
            else:
                st.error("❌ **No valid SSL certificate found**")
                error_msg = cert.get('error', 'Unknown error') if cert else 'Certificate information unavailable'
                st.markdown(f"""
                <div style="padding: 10px; background-color: rgba(244, 67, 54, 0.1); border-left: 4px solid #f44336; border-radius: 4px; margin: 10px 0;">
                    <strong>Error:</strong> {error_msg}<br><br>
                    <strong>Possible reasons:</strong><br>
                    • Self-signed certificate (not trusted)<br>
                    • Expired certificate<br>
                    • Certificate mismatch<br>
                    • Connection blocked/refused
                </div>
                """, unsafe_allow_html=True)
            
            st.markdown("---")
            
            # Security Headers
            st.subheader("🛡️ Security Headers")
            headers = results.get('security_headers', {})
            
            if headers and headers.get('score', 0) > 0:
                score = headers.get('score', 0)
                st.progress(score / 100)
                st.write(f"**Score:** {score}%")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**✅ Present:**")
                    present = headers.get('present', [])
                    if present:
                        for header in present:
                            st.write(f"- {header}")
                    else:
                        st.write("- None")
                
                with col2:
                    st.write("**❌ Missing:**")
                    missing = headers.get('missing', [])
                    if missing:
                        for header in missing:
                            st.write(f"- {header}")
                    else:
                        st.write("- All present!")

                # CSP findings
                csp_findings = headers.get('csp_findings', [])
                if csp_findings:
                    st.subheader("🔍 CSP Analysis")
                    for f in csp_findings:
                        st.warning(f)

                # Cookie findings
                cookie_findings = headers.get('cookie_findings', [])
                if cookie_findings:
                    st.subheader("🍪 Cookie Flags")
                    for f in cookie_findings:
                        st.warning(f)
            else:
                st.error("❌ **No security headers detected**")
                st.markdown("""
                <div style="padding: 10px; background-color: rgba(244, 67, 54, 0.1); border-left: 4px solid #f44336; border-radius: 4px; margin: 10px 0;">
                    <strong>🚨 Missing ALL security headers</strong><br><br>
                    The site is missing critical security headers that protect against:<br><br>
                    <strong>Missing Headers:</strong><br>
                    • <strong>Content-Security-Policy</strong> - Prevents XSS attacks<br>
                    • <strong>X-Frame-Options</strong> - Prevents clickjacking<br>
                    • <strong>X-Content-Type-Options</strong> - Prevents MIME sniffing<br>
                    • <strong>Strict-Transport-Security</strong> - Forces HTTPS<br>
                    • <strong>Referrer-Policy</strong> - Controls referrer information<br>
                    • <strong>Permissions-Policy</strong> - Controls browser features<br>
                    <br>
                    <strong>⚠️ Legitimate sites implement these headers for user protection!</strong>
                </div>
                """, unsafe_allow_html=True)
            
            # HTML Security Issues
            html_issues = results.get('html_security_issues', [])
            if html_issues:
                st.subheader("⚠️ HTML Security Issues")
                for issue in html_issues:
                    st.warning(issue)
        
        # Tab 4: Page Content
        with tab4:
            st.header("Page Content Analysis")
            
            page = results.get('page_info', {})
            
            if page and not page.get('error'):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("Metadata")
                    if page.get('title'):
                        st.write(f"**Title:** {page['title']}")
                    else:
                        st.write("**Title:** No title tag found")
                    
                    if page.get('meta_description'):
                        st.write(f"**Description:** {page['meta_description'][:200]}")
                    else:
                        st.write("**Description:** No meta description")
                    
                    if page.get('language'):
                        st.write(f"**Language:** {page['language']}")
                    
                    if page.get('canonical'):
                        st.write(f"**Canonical:** {page['canonical']}")
                
                with col2:
                    st.subheader("Statistics")
                    st.write(f"**Page Size:** {format_bytes(page.get('page_size', 0))}")
                    st.write(f"**Word Count:** {page.get('word_count', 0):,}")
                    st.write(f"**Internal Links:** {page.get('internal_links', 0)}")
                    st.write(f"**External Links:** {page.get('external_links', 0)}")
                    st.write(f"**Images:** {page.get('image_count', 0)}")
                    st.write(f"**Scripts:** {page.get('script_count', 0)}")
                    st.write(f"**Forms:** {page.get('form_count', 0)}")
                    st.write(f"**H1 Tags:** {page.get('h1_count', 0)}")
                
                # SEO Suggestions
                seo = results.get('seo_suggestions', [])
                if seo:
                    st.subheader("📈 SEO Suggestions")
                    for suggestion in seo:
                        st.info(f"💡 {suggestion}")
                
                # OpenGraph tags
                og_tags = page.get('og_tags', {})
                if og_tags:
                    st.subheader("🌐 OpenGraph Tags")
                    for key, value in og_tags.items():
                        st.write(f"**{key}:** {value}")
            else:
                error_msg = page.get('error', 'Unable to fetch page content') if page else 'No page data available'
                st.warning(f"⚠️ **Page Content Unavailable:** {error_msg}")
                st.markdown("""
                <div style="padding: 10px; background-color: rgba(255, 152, 0, 0.1); border-left: 4px solid #FF9800; border-radius: 4px; margin: 10px 0;">
                    <strong>Possible reasons:</strong><br>
                    • Site requires JavaScript to render content<br>
                    • Connection timeout or refused<br>
                    • Site blocks automated access (bot detection)<br>
                    • Server returned error status code<br>
                    • Network connectivity issues
                </div>
                """, unsafe_allow_html=True)
                st.error(f"⚠️ {error_msg}")
                
                st.info("""
                **Why page content might be unavailable:**
                
                - 🚫 **Connection refused** - Server blocked the request
                - ⏱️ **Timeout** - Server didn't respond in time
                - 🔒 **Access denied** - Site requires authentication or blocks scanners
                - ❌ **Site offline** - Domain not resolving or server down
                - 🛡️ **Anti-bot protection** - Cloudflare, reCAPTCHA, or similar blocking access
                
                For malicious sites, this is common as they:
                - Are frequently taken down
                - Block automated scanners
                - Have unstable infrastructure
                """)
        
        # Tab 5: WHOIS
        with tab5:
            st.header("WHOIS Information")
            
            whois = results.get('whois', {})
            
            if whois and not whois.get('error'):
                col1, col2 = st.columns(2)
                
                with col1:
                    if whois.get('registrar'):
                        st.write(f"**Registrar:** {whois['registrar']}")
                    st.write(f"**Created:** {format_date(whois.get('creation_date'))}")
                    st.write(f"**Expires:** {format_date(whois.get('expiration_date'))}")
                    st.write(f"**Updated:** {format_date(whois.get('updated_date'))}")
                    if whois.get('domain_age'):
                        st.write(f"**Domain Age:** {whois['domain_age']}")
                
                with col2:
                    if whois.get('name_servers'):
                        st.write("**Name Servers:**")
                        for ns in whois['name_servers'][:5]:
                            st.write(f"- {ns}")
                    
                    if whois.get('status'):
                        st.write("**Status:**")
                        for status in whois['status'][:3]:
                            st.write(f"- {status}")
            else:
                error_msg = whois.get('error', 'Unknown error')
                
                # Check if it's the VeriSign error (too much text)
                if 'VeriSign' in error_msg or len(error_msg) > 200:
                    st.error("⚠️ **WHOIS lookup failed**")
                    st.markdown("""
                    <div style="padding: 10px; background-color: rgba(244, 67, 54, 0.1); border-left: 4px solid #f44336; border-radius: 4px; margin: 10px 0;">
                        <strong>Error:</strong> WHOIS query returned an error or terms of service message<br><br>
                        <strong>Common reason:</strong> Domain not found or WHOIS server blocking automated queries
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.error(f"⚠️ **WHOIS lookup failed:** {error_msg}")
                
                # Explain why WHOIS might fail
                st.markdown("""
                <div style="padding: 15px; background-color: rgba(33, 150, 243, 0.1); border-left: 4px solid #2196F3; border-radius: 4px; margin: 15px 0;">
                    <strong>Why WHOIS data might be unavailable:</strong><br><br>
                    🚨 <strong>Malicious/suspicious domains</strong> - Often have blocked or invalid WHOIS records<br>
                    🛡️ <strong>Privacy protection</strong> - Services hide registrant information<br>
                    ⚠️ <strong>Suspicious TLDs</strong> - (.tk, .ml, .ga, .cf, .gq) have unreliable WHOIS servers<br>
                    ❌ <strong>Inactive/expired domains</strong> - May no longer have WHOIS data<br>
                    🔒 <strong>Rate limiting</strong> - WHOIS servers may block automated requests<br>
                    📛 <strong>Domain doesn't exist</strong> - Not registered or deleted<br><br>
                    <strong style="color: #d32f2f;">⚠️ This is often a red flag for potentially malicious sites!</strong>
                </div>
                """, unsafe_allow_html=True)
                
                # Show domain info we DO have
                domain_info = results.get('domain_info', {})
                if domain_info:
                    st.subheader("📋 Available Domain Information")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if domain_info.get('domain'):
                            st.write(f"**Full Domain:** {domain_info['domain']}")
                        if domain_info.get('registrable_domain'):
                            st.write(f"**Registrable Domain:** {domain_info['registrable_domain']}")
                        if domain_info.get('subdomain'):
                            st.write(f"**Subdomain:** {domain_info['subdomain']}")
                    
                    with col2:
                        if domain_info.get('tld'):
                            tld = domain_info['tld']
                            # Check if suspicious TLD
                            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
                            if tld in suspicious_tlds:
                                st.error(f"**TLD:** {tld}")
                                st.markdown("⚠️ **Highly suspicious TLD!**")
                            else:
                                st.write(f"**TLD:** {tld}")
                        
                        if domain_info.get('suffix'):
                            st.write(f"**Public Suffix:** {domain_info['suffix']}")

        
        # Tab 6: Recommendations
        with tab6:
            st.header("💡 Security Recommendations")
            recommendations = results.get('recommendations', [])

            if recommendations:
                # Group by priority
                critical = [r for r in recommendations if r.get('priority') == 'CRITICAL']
                high = [r for r in recommendations if r.get('priority') == 'HIGH']
                medium = [r for r in recommendations if r.get('priority') == 'MEDIUM']
                low = [r for r in recommendations if r.get('priority') == 'LOW']

                if critical:
                    st.error(f"### 🔴 Critical Priority ({len(critical)} issues)")
                    for rec in critical:
                        with st.expander(f"**{rec['issue']}**"):
                            st.markdown(f"**Impact:** {rec['impact']}")
                            st.markdown(f"**Fix:** {rec['fix']}")
                            if rec.get('references'):
                                st.markdown("**References:**")
                                for ref in rec['references']:
                                    st.markdown(f"- {ref}")

                if high:
                    st.warning(f"### 🟠 High Priority ({len(high)} issues)")
                    for rec in high:
                        with st.expander(f"**{rec['issue']}**"):
                            st.markdown(f"**Impact:** {rec['impact']}")
                            st.markdown(f"**Fix:** {rec['fix']}")
                            if rec.get('references'):
                                st.markdown("**References:**")
                                for ref in rec['references']:
                                    st.markdown(f"- {ref}")

                if medium:
                    st.info(f"### 🟡 Medium Priority ({len(medium)} issues)")
                    for rec in medium:
                        with st.expander(f"**{rec['issue']}**"):
                            st.markdown(f"**Impact:** {rec['impact']}")
                            st.markdown(f"**Fix:** {rec['fix']}")
                            if rec.get('references'):
                                st.markdown("**References:**")
                                for ref in rec['references']:
                                    st.markdown(f"- {ref}")

                if low:
                    st.success(f"### 🟢 Low Priority ({len(low)} issues)")
                    for rec in low:
                        with st.expander(f"**{rec['issue']}**"):
                            st.markdown(f"**Impact:** {rec['impact']}")
                            st.markdown(f"**Fix:** {rec['fix']}")
                            if rec.get('references'):
                                st.markdown("**References:**")
                                for ref in rec['references']:
                                    st.markdown(f"- {ref}")

                rec_text = format_recommendations_text(recommendations)
                st.download_button(
                    label="📥 Download Recommendations",
                    data=rec_text,
                    file_name=f"{url_info.get('domain', 'scan')}_recommendations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )
            else:
                st.info("No recommendations available")

        # Tab 7: Compliance
        with tab7:
            st.header("✅ Compliance Report")
            compliance = results.get('compliance', {})

            if compliance:
                overall_score = compliance.get('overall_score', 0)

                st.metric("Overall Compliance Score", f"{overall_score}%")
                st.progress(overall_score / 100)

                st.markdown("---")

                st.subheader("🔐 OWASP Top 10 (2021)")
                owasp = compliance.get('owasp_top10', {})
                if owasp:
                    score = owasp.get('score', 0)
                    st.metric("OWASP Score", f"{score}%")

                    for check in owasp.get('checks', []):
                        status = "✅" if check['status'] == 'PASS' else "❌"
                        with st.expander(f"{status} {check['category']} - {check['name']}"):
                            st.markdown(check['description'])

                st.markdown("---")

                st.subheader("💳 PCI-DSS Web Requirements")
                pci = compliance.get('pci_dss', {})
                if pci:
                    score = pci.get('score', 0)
                    st.metric("PCI-DSS Score", f"{score}%")

                    for check in pci.get('checks', []):
                        status = "✅" if check['status'] == 'PASS' else "❌"
                        with st.expander(f"{status} Requirement {check['requirement']} - {check['name']}"):
                            st.markdown(check['description'])

                st.markdown("---")

                st.subheader("🇪🇺 GDPR Article 32 - Security")
                gdpr = compliance.get('gdpr_security', {})
                if gdpr:
                    score = gdpr.get('score', 0)
                    st.metric("GDPR Security Score", f"{score}%")

                    for check in gdpr.get('checks', []):
                        status = "✅" if check['status'] == 'PASS' else "❌"
                        with st.expander(f"{status} {check['article']} - {check['name']}"):
                            st.markdown(check['description'])

                st.markdown("---")

                st.subheader("🏛️ NIST Cybersecurity Framework")
                nist = compliance.get('nist_csf', {})
                if nist:
                    score = nist.get('score', 0)
                    st.metric("NIST CSF Score", f"{score}%")

                    for check in nist.get('checks', []):
                        status = "✅" if check['status'] == 'PASS' else "❌"
                        with st.expander(f"{status} {check['category']} - {check['name']}"):
                            st.markdown(check['description'])

                comp_text = format_compliance_report(compliance)
                st.download_button(
                    label="📥 Download Compliance Report",
                    data=comp_text,
                    file_name=f"{url_info.get('domain', 'scan')}_compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )
            else:
                st.info("No compliance data available")

        # Tab 8: Export
        with tab8:
            st.header("Export Results")

            st.subheader("📄 JSON Format")
            json_str = json.dumps(results, indent=2, default=str)
            st.download_button(
                label="Download JSON",
                data=json_str,
                file_name=f"{url_info.get('domain', 'scan')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )

            with st.expander("View JSON"):
                st.code(json_str, language='json')

            st.subheader("📝 Summary Report")
            summary = f"""Website Security Scan Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

URL: {url_info.get('original_url')}
Domain: {url_info.get('domain')}
HTTPS: {'Yes' if url_info.get('https_enabled') else 'No'}

Risk Level: {risk.get('level')} (Score: {risk.get('score')})

Risk Factors:
"""
            for factor in risk.get('factors', []):
                summary += f"- {factor}\n"

            st.download_button(
                label="Download Summary",
                data=summary,
                file_name=f"{url_info.get('domain', 'scan')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )
    
    elif scan_button:
        st.error("Please enter a URL to scan.")
    
    # Sidebar
    with st.sidebar:
        st.header("About")
        st.markdown("""
        **Website Security Scanner** performs passive analysis of websites including:
        
        - 🌐 Network analysis
        - 🔒 SSL/TLS certificate checks
        - 🛡️ Security headers
        - 📄 Page content analysis
        - 🔍 WHOIS information
        - 📊 Risk assessment
        
        All checks are **non-intrusive** and legal.
        """)
        
        st.header("Tips")
        st.markdown("""
        - Enter full URLs (e.g., https://example.com)
        - Scans may take 5-15 seconds
        - Export results for record keeping
        - Compare scans over time
        """)
        
        st.markdown("---")
        
        # History viewer
        st.header("📜 Recent History")
        history = read_history(limit=10)
        if history:
            for h in history:
                with st.expander(f"{h.get('domain', 'Unknown')} - {h.get('created_at', '')}"):
                    st.write(f"**URL:** {h.get('url', 'N/A')}")
                    risk = h.get('risk_level', 'UNKNOWN')
                    if risk == 'HIGH':
                        st.error(f"Risk: {risk}")
                    elif risk == 'MEDIUM':
                        st.warning(f"Risk: {risk}")
                    else:
                        st.success(f"Risk: {risk}")
                    st.write(f"Status: {h.get('status_code', 'N/A')}")
                    st.write(f"File: `{h.get('file', 'N/A')}`")
        else:
            st.info("No scan history yet")
        
        st.markdown("---")
        st.markdown("Made with ❤️ using Python & Streamlit")


if __name__ == '__main__':
    main()
