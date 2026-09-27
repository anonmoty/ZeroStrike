# modules/m14_ssl.py
import socket, ssl
from urllib.parse import urlparse
from core.colors import C
from core.engine import Engine

def run(url, reporter, engine):
    print(f"\n  {C.B}[*] A02: Checking SSL/TLS Configuration...{C.E}")

    if url.startswith("http://"):
        reporter.add_vuln(
            "A02", "No SSL/TLS (HTTP Only)",
            "CRITICAL",
            "Website does not use HTTPS. All data in plaintext.",
            url
        )
        return

    parsed = urlparse(url)
    hostname = parsed.hostname or url.replace("https://", "").split("/")[0]

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_ver = ssock.version()
                cipher = ssock.cipher()

                if tls_ver in ["TLSv1", "TLSv1.1", "SSLv3"]:
                    reporter.add_vuln(
                        "A02", f"Deprecated TLS Version: {tls_ver}",
                        "HIGH",
                        f"Server supports deprecated protocol {tls_ver}.",
                        f"Protocol: {tls_ver}"
                    )
                else:
                    print(f"  {C.G}[✓] TLS Version: {tls_ver}{C.E}")

                if cipher and cipher[2] < 128:
                    reporter.add_vuln(
                        "A02", "Weak Cipher Suite",
                        "HIGH",
                        f"Cipher strength only {cipher[2]} bits.",
                        f"Cipher: {cipher[0]}"
                    )
    except ssl.SSLCertVerificationError as e:
        reporter.add_vuln(
            "A02", "Invalid SSL Certificate",
            "CRITICAL",
            f"Certificate verification failed: {e.verify_message}",
            str(e)
        )
    except Exception as e:
        print(f"  {C.GR}[i] SSL check skipped: {e}{C.E}")

    print(f"  {C.G}[✓] SSL check complete.{C.E}")
