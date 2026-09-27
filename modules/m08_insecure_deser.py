# modules/m08_insecure_deser.py
from core.colors import C
from core.engine import Engine

def run(url, reporter, engine):
    print(f"\n  {C.B}[*] A08: Checking Insecure Deserialization Indicators...{C.E}")
    r = engine.get(url)
    if not r: return

    # Check for serialized data in cookies
    for cookie in r.cookies:
        val = cookie.value
        if val.startswith(("O:", "a:", "s:", "rO0AB", "eyJ")):
            reporter.add_vuln(
                "A08", "Serialized Data in Cookie",
                "HIGH",
                f"Cookie '{cookie.name}' contains serialized object data.",
                f"Cookie: {cookie.name}={val[:50]}"
            )

    # Check for Java/PHP serialization indicators in headers
    headers_str = str(r.headers).lower()
    if "java" in headers_str and "serialized" in headers_str:
        reporter.add_vuln(
            "A08", "Java Serialization Indicator",
            "MEDIUM",
            "Response headers suggest Java object serialization.",
            "Header analysis"
        )

    print(f"  {C.G}[✓] Deserialization check complete.{C.E}")
