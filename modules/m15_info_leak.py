# modules/m15_info_leak.py
from core.colors import C
from core.engine import Engine

def run(url, reporter, engine):
    print(f"\n  {C.B}[*] X03: Checking Information Disclosure...{C.E}")

    sensitive_files = {
        "/.git/config": ("Git Repository Exposed", "CRITICAL"),
        "/.env": ("Environment Variables Exposed", "CRITICAL"),
        "/.htaccess": ("Apache Config Exposed", "HIGH"),
        "/wp-config.php": ("WordPress Config Exposed", "CRITICAL"),
        "/config.php": ("PHP Config Exposed", "HIGH"),
        "/database.yml": ("Database Config Exposed", "CRITICAL"),
        "/.DS_Store": ("macOS Metadata Exposed", "LOW"),
        "/sitemap.xml": ("Sitemap Public", "INFO"),
        "/crossdomain.xml": ("Flash Cross-Domain Policy", "LOW"),
        "/.well-known/security.txt": ("Security Contact Info", "INFO"),
        "/server-status": ("Apache Server Status", "HIGH"),
        "/server-info": ("Apache Server Info", "HIGH"),
        "/.svn/entries": ("SVN Repository Exposed", "CRITICAL"),
        "/backup.sql": ("Database Backup Exposed", "CRITICAL"),
        "/dump.sql": ("Database Dump Exposed", "CRITICAL"),
        "/.aws/credentials": ("AWS Credentials Exposed", "CRITICAL"),
    }

    for path, (vuln_name, severity) in sensitive_files.items():
        r = engine.check_path(url, path)
        if r and r.status_code == 200 and len(r.content) > 10:
            reporter.add_vuln(
                "X03", vuln_name,
                severity,
                f"Sensitive file accessible at '{path}'.",
                f"URL: {url}{path} | Size: {len(r.content)} bytes"
            )

    print(f"  {C.G}[✓] Info leak check complete.{C.E}")
