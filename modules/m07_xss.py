# modules/m07_xss.py
from core.colors import C
from core.engine import Engine

def run(url, reporter, engine):
    print(f"\n  {C.B}[*] A03: Checking Cross-Site Scripting (XSS)...{C.E}")

    # Reflected XSS indicators
    xss_indicators = [
        "<script>", "onerror=", "onload=", "javascript:",
        "alert(", "document.cookie", "eval("
    ]

    test_params = [
        f"{url}?q=<test>",
        f"{url}?search=<test>",
        f"{url}?name=<test>",
        f"{url}?id=<test>",
    ]

    for turl in test_params:
        r = engine.get(turl, timeout=8)
        if r and r.status_code == 200:
            # Check if input is reflected without encoding
            if "<test>" in r.text:
                reporter.add_vuln(
                    "A03", "Reflected Input Without Encoding (XSS Risk)",
                    "MEDIUM",
                    "User input reflected in page without HTML encoding.",
                    f"URL: {turl}"
                )
                break

    # Check for DOM-based XSS indicators in JS
    r = engine.get(url)
    if r:
        dom_sinks = ["document.write(", "innerHTML", "outerHTML", "eval(", "setTimeout("]
        for sink in dom_sinks:
            if sink in r.text:
                reporter.add_vuln(
                    "A03", "DOM-Based XSS Sink Detected",
                    "LOW",
                    f"JavaScript sink '{sink}' found in page source. Manual review recommended.",
                    f"Sink: {sink}"
                )
                break

    print(f"  {C.G}[✓] XSS check complete.{C.E}")
