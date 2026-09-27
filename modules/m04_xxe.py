# modules/m04_xxe.py
from core.colors import C
from core.engine import Engine

def run(url, reporter, engine):
    print(f"\n  {C.B}[*] A05: Checking XXE Indicators...{C.E}")
    r = engine.get(url)
    if not r: return

    ct = r.headers.get("Content-Type", "").lower()

    # Check if server accepts XML
    if "xml" in ct or "soap" in r.text.lower()[:2000]:
        reporter.add_vuln(
            "A05", "XML Processing Endpoint Detected",
            "LOW",
            "Server processes XML content. XXE may be possible if DTD processing is enabled.",
            f"Content-Type: {ct}"
        )

    # Check for SOAP endpoints
    soap_paths = ["/wsdl", "/soap", "/api/soap", "/services"]
    for p in soap_paths:
        resp = engine.check_path(url, p)
        if resp and resp.status_code == 200 and "xml" in resp.headers.get("Content-Type", "").lower():
            reporter.add_vuln(
                "A05", "SOAP/XML Endpoint Exposed",
                "LOW",
                f"SOAP endpoint found at '{p}'. Test for XXE with external entity payloads.",
                f"Path: {p}"
            )

    print(f"  {C.G}[✓] XXE check complete.{C.E}")
