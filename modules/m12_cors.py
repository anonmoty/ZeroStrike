# modules/m12_cors.py
from core.colors import C
from core.engine import Engine
import requests

def run(url, reporter, engine):
    print(f"\n  {C.B}[*] X01: Checking CORS Configuration...{C.E}")

    try:
        r = requests.get(url, headers={"Origin": "http://evil-attacker.com"}, timeout=10)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            reporter.add_vuln(
                "X01", "CORS Wildcard Origin",
                "MEDIUM",
                "Access-Control-Allow-Origin set to '*'. Any domain can make cross-origin requests.",
                f"ACAO: {acao}"
            )
        elif "evil-attacker.com" in acao:
            reporter.add_vuln(
                "X01", "CORS Reflects Arbitrary Origin",
                "HIGH",
                "Server reflects attacker-controlled origin. Full CORS bypass possible.",
                f"ACAO: {acao} | ACAC: {acac}"
            )

        if acac.lower() == "true" and acao == "*":
            reporter.add_vuln(
                "X01", "CORS Wildcard with Credentials",
                "CRITICAL",
                "Wildcard origin with credentials allowed. Severe data theft risk.",
                f"ACAO: * | ACAC: true"
            )
    except:
        pass

    print(f"  {C.G}[✓] CORS check complete.{C.E}")
