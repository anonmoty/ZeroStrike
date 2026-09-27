# modules/m02_broken_auth.py
from core.colors import C
from core.engine import Engine

def run(url, reporter, engine):
    print(f"\n  {C.B}[*] A07: Checking Authentication & Session Issues...{C.E}")
    r = engine.get(url)
    if not r: return

    cookies = r.cookies
    headers = r.headers

    # Check session cookie flags
    for cookie in cookies:
        if not cookie.secure:
            reporter.add_vuln(
                "A07", "Session Cookie Missing 'Secure' Flag",
                "MEDIUM",
                f"Cookie '{cookie.name}' transmitted over unencrypted channel.",
                f"Cookie: {cookie.name}"
            )
        if "session" in cookie.name.lower() or "auth" in cookie.name.lower():
            if not cookie.has_nonstandard_attr("HttpOnly"):
                reporter.add_vuln(
                    "A07", "Session Cookie Missing 'HttpOnly' Flag",
                    "MEDIUM",
                    f"Session cookie '{cookie.name}' accessible via JavaScript (XSS risk).",
                    f"Cookie: {cookie.name}"
                )

    # Check for common auth pages without protection
    auth_paths = ["/login", "/admin", "/signin", "/wp-login.php", "/administrator"]
    for p in auth_paths:
        resp = engine.check_path(url, p)
        if resp and resp.status_code == 200:
            if "csrf" not in resp.text.lower() and "token" not in resp.text.lower():
                reporter.add_vuln(
                    "A07", "Login Page Without CSRF Protection",
                    "MEDIUM",
                    f"Authentication page at '{p}' has no visible CSRF token.",
                    f"Path: {p}"
                )

    print(f"  {C.G}[✓] Auth check complete.{C.E}")
