"""
UI utilities for displaying scan results.
"""

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

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


def display_report_rich(scan_results: dict):
    """
    Display scan results using rich formatting.
    
    Args:
        scan_results: Complete scan results dictionary
    """
    if not RICH_AVAILABLE:
        display_report_plain(scan_results)
        return
    
    console = Console()
    
    # Header
    console.print("\n")
    console.print(Panel.fit(
        "[bold cyan]Website Information & Security Scanner[/bold cyan]\n"
        "[dim]Passive analysis tool - Non-intrusive checks only[/dim]",
        border_style="cyan"
    ))
    
    # URL Summary
    console.print("\n[bold]━━━ URL Summary ━━━[/bold]")
    url_info = scan_results.get('url_info', {})
    table = Table(show_header=False, box=box.SIMPLE)
    table.add_column("Property", style="cyan")
    table.add_column("Value")
    
    table.add_row("Original URL", url_info.get('original_url', 'N/A'))
    table.add_row("Final URL", url_info.get('final_url', 'N/A'))
    table.add_row("Domain", url_info.get('domain', 'N/A'))
    table.add_row("HTTPS Enabled", "✓ Yes" if url_info.get('https_enabled') else "✗ No")
    
    if url_info.get('redirect_count', 0) > 0:
        table.add_row("Redirects", str(url_info.get('redirect_count')))
    
    console.print(table)
    
    # Network Information
    console.print("\n[bold]━━━ Network Information ━━━[/bold]")
    network_info = scan_results.get('network_info', {})
    table = Table(show_header=False, box=box.SIMPLE)
    table.add_column("Property", style="cyan")
    table.add_column("Value")
    
    if network_info.get('ip_address'):
        table.add_row("IP Address", network_info['ip_address'])
    
    table.add_row("Response Time", f"{network_info.get('response_time', 0):.2f}s")
    table.add_row("Status Code", str(network_info.get('status_code', 'N/A')))
    
    # DNS Records
    dns = network_info.get('dns_records', {})
    if dns.get('A'):
        table.add_row("A Records", ", ".join(dns['A'][:3]))
    if dns.get('MX'):
        table.add_row("MX Records", ", ".join(dns['MX'][:2]))
    if dns.get('NS'):
        table.add_row("Name Servers", ", ".join(dns['NS'][:2]))
    
    console.print(table)
    
    # SSL Certificate
    cert_info = scan_results.get('ssl_certificate', {})
    if cert_info and not cert_info.get('error'):
        console.print("\n[bold]━━━ SSL Certificate ━━━[/bold]")
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        
        issuer = cert_info.get('issuer', {})
        table.add_row("Issuer", issuer.get('organizationName', issuer.get('commonName', 'N/A')))
        table.add_row("Valid Until", cert_info.get('not_after', 'N/A'))
        
        if cert_info.get('is_expired'):
            table.add_row("Status", "[red]EXPIRED[/red]")
        elif cert_info.get('days_until_expiry') is not None:
            days = cert_info['days_until_expiry']
            color = "red" if days < 30 else "yellow" if days < 90 else "green"
            table.add_row("Expires In", f"[{color}]{days} days[/{color}]")
        
        console.print(table)
    
    # WHOIS Information
    whois_info = scan_results.get('whois', {})
    if whois_info and not whois_info.get('error'):
        console.print("\n[bold]━━━ WHOIS Information ━━━[/bold]")
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        
        if whois_info.get('registrar'):
            table.add_row("Registrar", whois_info['registrar'])
        
        table.add_row("Created", format_date(whois_info.get('creation_date')))
        table.add_row("Expires", format_date(whois_info.get('expiration_date')))
        
        if whois_info.get('domain_age'):
            table.add_row("Domain Age", whois_info['domain_age'])
        
        console.print(table)
    
    # Page Metadata
    page_info = scan_results.get('page_info', {})
    if page_info:
        console.print("\n[bold]━━━ Page Metadata ━━━[/bold]")
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        
        if page_info.get('title'):
            table.add_row("Title", page_info['title'][:80])
        if page_info.get('meta_description'):
            table.add_row("Description", page_info['meta_description'][:80])
        
        table.add_row("Page Size", format_bytes(page_info.get('page_size', 0)))
        table.add_row("Word Count", str(page_info.get('word_count', 0)))
        table.add_row("Internal Links", str(page_info.get('internal_links', 0)))
        table.add_row("External Links", str(page_info.get('external_links', 0)))
        table.add_row("Images", str(page_info.get('image_count', 0)))
        table.add_row("Scripts", str(page_info.get('script_count', 0)))
        table.add_row("Forms", str(page_info.get('form_count', 0)))
        
        console.print(table)
    
    # Security Headers
    security = scan_results.get('security_headers', {})
    if security:
        console.print("\n[bold]━━━ Security Headers ━━━[/bold]")
        
        score = security.get('score', 0)
        color = "green" if score >= 70 else "yellow" if score >= 40 else "red"
        console.print(f"Score: [{color}]{score}%[/{color}]\n")
        
        table = Table(show_header=True, box=box.SIMPLE)
        table.add_column("Header", style="cyan")
        table.add_column("Status")
        
        for header in security.get('present', []):
            table.add_row(header, "[green]✓ Present[/green]")
        
        for header in security.get('missing', []):
            table.add_row(header, "[red]✗ Missing[/red]")
        
        console.print(table)
    
    # Risk Assessment
    risk = scan_results.get('risk_assessment', {})
    if risk:
        console.print("\n[bold]━━━ Risk Assessment ━━━[/bold]")
        
        level = risk.get('level', 'UNKNOWN')
        score = risk.get('score', 0)
        
        color = "red" if level == "HIGH" else "yellow" if level == "MEDIUM" else "green"
        console.print(f"\nRisk Level: [{color}]{level}[/{color}] (Score: {score})\n")
        
        console.print("[bold]Risk Factors:[/bold]")
        for factor in risk.get('factors', []):
            console.print(f"  • {factor}")
    
    console.print("\n")


def display_report_plain(scan_results: dict):
    """
    Display scan results using plain text formatting.
    
    Args:
        scan_results: Complete scan results dictionary
    """
    print("\n" + "="*80)
    print("Website Information & Security Scanner")
    print("Passive analysis tool - Non-intrusive checks only")
    print("="*80)
    
    # URL Summary
    print("\n--- URL Summary ---")
    url_info = scan_results.get('url_info', {})
    print(f"Original URL: {url_info.get('original_url', 'N/A')}")
    print(f"Final URL:    {url_info.get('final_url', 'N/A')}")
    print(f"Domain:       {url_info.get('domain', 'N/A')}")
    print(f"HTTPS:        {'Yes' if url_info.get('https_enabled') else 'No'}")
    
    # Network Information
    print("\n--- Network Information ---")
    network_info = scan_results.get('network_info', {})
    if network_info.get('ip_address'):
        print(f"IP Address:     {network_info['ip_address']}")
    print(f"Response Time:  {network_info.get('response_time', 0):.2f}s")
    print(f"Status Code:    {network_info.get('status_code', 'N/A')}")
    
    dns = network_info.get('dns_records', {})
    if dns.get('A'):
        print(f"A Records:      {', '.join(dns['A'][:3])}")
    
    # SSL Certificate
    cert_info = scan_results.get('ssl_certificate', {})
    if cert_info and not cert_info.get('error'):
        print("\n--- SSL Certificate ---")
        issuer = cert_info.get('issuer', {})
        print(f"Issuer:      {issuer.get('organizationName', issuer.get('commonName', 'N/A'))}")
        print(f"Valid Until: {cert_info.get('not_after', 'N/A')}")
        if cert_info.get('days_until_expiry') is not None:
            print(f"Expires In:  {cert_info['days_until_expiry']} days")
    
    # WHOIS Information
    whois_info = scan_results.get('whois', {})
    if whois_info and not whois_info.get('error'):
        print("\n--- WHOIS Information ---")
        if whois_info.get('registrar'):
            print(f"Registrar:   {whois_info['registrar']}")
        print(f"Created:     {format_date(whois_info.get('creation_date'))}")
        print(f"Expires:     {format_date(whois_info.get('expiration_date'))}")
        if whois_info.get('domain_age'):
            print(f"Domain Age:  {whois_info['domain_age']}")
    
    # Page Metadata
    page_info = scan_results.get('page_info', {})
    if page_info:
        print("\n--- Page Metadata ---")
        if page_info.get('title'):
            print(f"Title:           {page_info['title'][:80]}")
        print(f"Page Size:       {format_bytes(page_info.get('page_size', 0))}")
        print(f"Word Count:      {page_info.get('word_count', 0)}")
        print(f"Internal Links:  {page_info.get('internal_links', 0)}")
        print(f"External Links:  {page_info.get('external_links', 0)}")
        print(f"Images:          {page_info.get('image_count', 0)}")
        print(f"Scripts:         {page_info.get('script_count', 0)}")
    
    # Security Headers
    security = scan_results.get('security_headers', {})
    if security:
        print("\n--- Security Headers ---")
        print(f"Score: {security.get('score', 0)}%")
        print(f"Present: {len(security.get('present', []))}")
        print(f"Missing: {len(security.get('missing', []))}")
    
    # Risk Assessment
    risk = scan_results.get('risk_assessment', {})
    if risk:
        print("\n--- Risk Assessment ---")
        print(f"Risk Level: {risk.get('level', 'UNKNOWN')} (Score: {risk.get('score', 0)})")
        print("\nRisk Factors:")
        for factor in risk.get('factors', []):
            print(f"  - {factor}")
    
    print("\n" + "="*80 + "\n")
