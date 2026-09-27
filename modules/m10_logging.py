# modules/m10_logging.py
from core.colors import C
from core.engine import Engine

def run(url, reporter, engine):
    print(f"\n  {C.B}[*] A09: Checking Logging & Monitoring...{C.E}")
    r = engine.get(url)
    if not r: return

    # CSP with report-uri
    csp = r.headers.get("Content-Security-Policy", "")
    if csp and "report-uri" not in csp and "report-to" not in csp:
        reporter.add_vuln(
            "A09", "CSP Without Reporting Endpoint",
            "LOW",
            "CSP header present but no report-uri/report-to configured. Violations go unlogged.",
            f"CSP: {csp[:80]}"
        )

    # Exposed log files
    log_paths = ["/error.log", "/access.log", "/debug.log", "/app.log", "/logs/", "/log/"]
    for p in log_paths:
        resp = engine.check_path(url, p)
        if resp and resp.status_code == 200 and len(resp.content) > 50:
            ct = resp.headers.get("Content-Type", "")
            if "text" in ct or "log" in ct:
                reporter.add_vuln(
                    "A09", "Log File Publicly Accessible",
                    "HIGH",
                    f"Server log file exposed at '{p}'.",
                    f"Path: {p}"
                )

    print(f"  {C.G}[✓] Logging check complete.{C.E}")
