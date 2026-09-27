# modules/m01_injection.py
from core.engine import Engine
from core.reporter import Reporter

def run(url, reporter, engine):
    print(f"\n  \033[1;34m[*] A03: Checking Injection Vulnerabilities...{C.E}")

    # SQL Error patterns
    sql_errors = [
        "sql syntax", "mysql", "ora-", "postgresql", "sqlite",
        "microsoft sql", "unclosed quotation", "quoted string",
        "syntax error", "sql error", "database error",
        "you have an error in your sql", "supplied argument is not"
    ]

    # Check common params for error-based detection
    test_urls = [
        f"{url}?id=1'",
        f"{url}?id=1\"",
        f"{url}?search=test'",
        f"{url}?q=1'",
        f"{url}?page=1'",
        f"{url}?category=1'",
    ]

    for turl in test_urls:
        r = engine.get(turl, timeout=8)
        if r and r.status_code == 200:
            body = r.text.lower()
            for err in sql_errors:
                if err in body:
                    reporter.add_vuln(
                        "A03", "SQL Injection (Error-Based)",
                        "HIGH",
                        f"Database error message exposed in response.",
                        f"URL: {turl} | Pattern: '{err}'"
                    )
                    break

    # NoSQL error patterns
    nosql_errors = ["mongodb", "mongoerror", "nosql", "bson", "objectid"]
    for turl in [f"{url}?id[$gt]=", f"{url}?id[$ne]=1"]:
        r = engine.get(turl, timeout=8)
        if r and r.status_code == 200:
            body = r.text.lower()
            for err in nosql_errors:
                if err in body:
                    reporter.add_vuln(
                        "A03", "NoSQL Injection Indicator",
                        "MEDIUM",
                        f"NoSQL database error pattern detected.",
                        f"URL: {turl}"
                    )
                    break

    print(f"  \033[1;32m[✓] Injection check complete.{C.E}")

from core.colors import C
