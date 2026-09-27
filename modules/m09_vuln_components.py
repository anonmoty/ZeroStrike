# modules/m09_vuln_components.py
import re
from core.colors import C
from core.engine import Engine

def run(url, reporter, engine):
    print(f"\n  {C.B}[*] A06: Checking Vulnerable & Outdated Components...{C.E}")
    r = engine.get(url)
    if not r: return

    html = r.text.lower()

    # Known vulnerable library patterns
    checks = {
        "jQuery < 3.5.0 (XSS)": [r"jquery[.-](1\.\d|2\.\d|3\.[0-4])", "jquery-1.", "jquery-2."],
        "AngularJS < 1.8.0": ["angularjs", "angular-1.", "ng-app"],
        "Bootstrap < 4.0": ["bootstrap/3.", "bootstrap-3.", "bootstrap.min.css"],
        "WordPress (Check Version)": ["wp-content", "wp-includes", "wordpress"],
        "Drupal": ["drupal", "sites/default/files"],
        "Joomla": ["joomla", "/media/jui/"],
        "Laravel Debug": ["laravel", "ignition"],
        "React (Dev Mode)": ["react.development.js", "react-dom.development"],
        "Old PHP": ["php/5.", "php/7.0", "php/7.1"],
        "Apache Struts": ["struts", ".action", ".do"],
        "Log4j Indicator": ["log4j", "jndi:", "x-api-version"],
    }

    for vuln_name, patterns in checks.items():
        for p in patterns:
            if re.search(p, html) or p in html:
                reporter.add_vuln(
                    "A06", f"Component Detected: {vuln_name}",
                    "MEDIUM",
                    f"Potentially outdated or vulnerable component detected in page source.",
                    f"Pattern: {p}"
                )
                break

    print(f"  {C.G}[✓] Component check complete.{C.E}")
