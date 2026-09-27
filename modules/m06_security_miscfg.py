# modules/m06_security_miscfg.py
from core.colors import C
from core.engine import Engine

def run(url, reporter, engine):
    print(f"\n  {C.B}[*] A05: Checking Security Misconfigurations...{C.E}")
    r = engine.get(url)
    if not r: return

    headers = r.headers

    # Server banner disclosure
    if "Server" in headers:
        server = headers["Server"]
        reporter.add_vuln(
            "A05", "Server Version Disclosure",
            "LOW",
            f"Web server reveals identity: '{server}'.",
            f"Server: {server}"
        )

    if "X-Powered-By" in headers:
        reporter.add_vuln(
            "A05", "Technology Stack Disclosure (X-Powered-By)",
            "LOW",
            f"Backend technology exposed: '{headers['X-Powered-By']}'.",
            f"X-Powered-By: {headers['X-Powered-By']}"
        )

    # Debug/Trace methods
    try:
        import requests
        resp = requests.options(url, timeout=8)
        allow = resp.headers.get("Allow", "")
        if "TRACE" in allow.upper():
            reporter.add_vuln(
                "A05", "HTTP TRACE Method Enabled",
                "MEDIUM",
                "TRACE method allowed. Cross-Site Tracing (XST) attacks possible.",
                f"Allow: {allow}"
            )
    except:
        pass

    # Verbose error pages
    error_urls = [f"{url}/nonexistent-page-xyz-123", f"{url}/%00"]
    for eu in error_urls:
        r2 = engine.get(eu, timeout=6)
        if r2 and r2.status_code in [404, 500]:
            body = r2.text.lower()
            if any(e in body for e in ["stack trace", "exception", "traceback", "error on line", "debug"]):
                reporter.add_vuln(
                    "A05", "Verbose Error Messages",
                    "MEDIUM",
                    "Detailed error/stack trace exposed to end user.",
                    f"URL: {eu}"
                )
                break

    # Default pages
    defaults = ["/readme.html", "/info.php", "/phpinfo.php", "/test.php", "/default.aspx"]
    for d in defaults:
        r3 = engine.check_path(url, d)
        if r3 and r3.status_code == 200 and len(r3.content) > 100:
            reporter.add_vuln(
                "A05", "Default/Test Page Exposed",
                "LOW",
                f"Default or test page accessible at '{d}'.",
                f"Path: {d}"
            )

    print(f"  {C.G}[✓] Misconfiguration check complete.{C.E}")
