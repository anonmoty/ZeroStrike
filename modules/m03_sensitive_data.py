# modules/m03_sensitive_data.py
from core.colors import C
from core.engine import Engine

def run(url, reporter, engine):
    print(f"\n  {C.B}[*] A02: Checking Cryptographic & Data Exposure...{C.E}")

    # HTTP without TLS
    if url.startswith("http://"):
        reporter.add_vuln(
            "A02", "Unencrypted HTTP Connection",
            "HIGH",
            "Website uses plain HTTP. All data transmitted in cleartext.",
            url
        )

    r = engine.get(url)
    if not r: return

    # HSTS missing
    if "Strict-Transport-Security" not in r.headers:
        reporter.add_vuln(
            "A02", "Missing HSTS Header",
            "MEDIUM",
            "No Strict-Transport-Security header. Downgrade attacks possible.",
            "Header absent"
        )

    # Check for sensitive data in HTML
    sensitive_patterns = {
        "API Key Exposure": ["api_key=", "apikey=", "api-key=", "access_token="],
        "Private Key Exposure": ["-----BEGIN RSA PRIVATE KEY", "-----BEGIN PRIVATE KEY"],
        "AWS Key Exposure": ["AKIAIOSFODNN7", "aws_access_key_id"],
        "Database Connection String": ["mysql://", "postgres://", "mongodb://", "jdbc:"],
    }

    for vuln_name, patterns in sensitive_patterns.items():
        for p in patterns:
            if p.lower() in r.text.lower():
                reporter.add_vuln(
                    "A02", vuln_name,
                    "CRITICAL",
                    f"Sensitive credential or key pattern found in page source.",
                    f"Pattern: {p}"
                )
                break

    print(f"  {C.G}[✓] Crypto check complete.{C.E}")
