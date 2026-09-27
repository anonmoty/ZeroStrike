# modules/m05_broken_access.py
from core.colors import C
from core.engine import Engine

def run(url, reporter, engine):
    print(f"\n  {C.B}[*] A01: Checking Broken Access Control...{C.E}")

    # Admin panels accessible without auth
    admin_paths = [
        "/admin", "/admin/", "/administrator", "/dashboard",
        "/wp-admin", "/cpanel", "/phpmyadmin", "/manager",
        "/console", "/controlpanel", "/admin/login"
    ]

    for p in admin_paths:
        r = engine.check_path(url, p)
        if r and r.status_code == 200:
            body = r.text.lower()
            if any(kw in body for kw in ["login", "password", "sign in", "admin panel", "dashboard"]):
                reporter.add_vuln(
                    "A01", "Admin Panel Publicly Accessible",
                    "HIGH",
                    f"Administrative interface found at '{p}' with 200 OK response.",
                    f"Path: {url}{p} | Status: {r.status_code}"
                )

    # Directory listing
    test_dirs = ["/uploads/", "/images/", "/files/", "/backup/", "/logs/", "/assets/"]
    for d in test_dirs:
        r = engine.check_path(url, d)
        if r and r.status_code == 200:
            if "index of" in r.text.lower() or "parent directory" in r.text.lower():
                reporter.add_vuln(
                    "A01", "Directory Listing Enabled",
                    "MEDIUM",
                    f"Directory listing exposed at '{d}'. Files can be browsed publicly.",
                    f"Path: {url}{d}"
                )

    print(f"  {C.G}[✓] Access control check complete.{C.E}")
