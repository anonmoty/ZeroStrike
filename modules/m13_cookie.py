# modules/m13_cookie.py
from core.colors import C
from core.engine import Engine

def run(url, reporter, engine):
    print(f"\n  {C.B}[*] X02: Checking Cookie Security...{C.E}")
    r = engine.get(url)
    if not r: return

    cookies = r.cookies
    if not cookies:
        print(f"  {C.GR}[i] No cookies set by server.{C.E}")
        return

    for cookie in cookies:
        issues = []
        if not cookie.secure:
            issues.append("Missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("Missing HttpOnly flag")
        if not cookie.has_nonstandard_attr("SameSite"):
            issues.append("Missing SameSite flag")

        if issues:
            sev = "HIGH" if "session" in cookie.name.lower() else "LOW"
            reporter.add_vuln(
                "X02", f"Cookie Security: {cookie.name}",
                sev,
                f"Cookie '{cookie.name}' has issues: {', '.join(issues)}",
                f"Cookie: {cookie.name}"
            )

    print(f"  {C.G}[✓] Cookie check complete.{C.E}")
