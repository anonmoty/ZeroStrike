# modules/m11_ssrf.py
from core.colors import C
from core.engine import Engine

def run(url, reporter, engine):
    print(f"\n  {C.B}[*] A10: Checking SSRF Indicators...{C.E}")
    r = engine.get(url)
    if not r: return

    # Check for URL parameters that might be SSRF vectors
    import re
    url_params = re.findall(r'[?&](url|uri|link|href|redirect|dest|next|target|path|page|site|to|out|view|load|open|request|host|site|port|callback|return|continue|window|data|reference|file|document|folder|root|pg|style|pdf|template|php_path|doc|feed|host|url|uri|port|next|dest|redirect|view|dir|show|navigation|open|window|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir|reference|site|html|data|domain|path|pg|file|document|folder|root|style|pdf|template|php_path|doc)=', r.text.lower())

    if url_params:
        reporter.add_vuln(
            "A10", "Potential SSRF Parameter Detected",
            "MEDIUM",
            f"URL parameters that may accept external URLs found: {', '.join(set(url_params[:5]))}",
            f"Parameters: {', '.join(set(url_params[:5]))}"
        )

    # Open redirect check
    redirect_params = [f"{url}?redirect=http://evil.com", f"{url}?url=http://evil.com", f"{url}?next=http://evil.com"]
    for rp in redirect_params:
        resp = engine.get(rp, timeout=6, allow_redirects=False)
        if resp and resp.status_code in [301, 302]:
            loc = resp.headers.get("Location", "")
            if "evil.com" in loc:
                reporter.add_vuln(
                    "A10", "Open Redirect Vulnerability",
                    "MEDIUM",
                    f"Application redirects to user-supplied URL without validation.",
                    f"Redirect to: {loc}"
                )
                break

    print(f"  {C.G}[✓] SSRF check complete.{C.E}")
