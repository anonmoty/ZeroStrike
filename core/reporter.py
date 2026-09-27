# core/reporter.py
import os
import json
import datetime
from core.colors import C
from core.owasp_db import OWASP_TOP_10, EXTRA_CHECKS

class Reporter:
    def __init__(self, target):
        self.target = target
        self.vulns = []
        self.ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    def add_vuln(self, owasp_id, vuln_name, severity, detail, evidence=""):
        """Vulnerability add karo report me"""
        v = {
            "owasp_id": owasp_id,
            "vuln_name": vuln_name,
            "severity": severity,
            "detail": detail,
            "evidence": evidence
        }
        self.vulns.append(v)

        # Terminal output
        sev_colors = {
            "CRITICAL": f"{C.BG_R}{C.W}",
            "HIGH": C.R,
            "MEDIUM": C.Y,
            "LOW": C.CY,
            "INFO": C.GR
        }
        sc = sev_colors.get(severity, C.W)

        print(f"\n  {sc} [{severity}] {C.E}{C.BO}{vuln_name}{C.E}")
        print(f"  {C.GR}  OWASP: {owasp_id} | {self._get_owasp_name(owasp_id)}{C.E}")
        print(f"  {C.GR}  Detail: {detail}{C.E}")
        if evidence:
            print(f"  {C.GR}  Evidence: {evidence[:120]}{C.E}")

    def _get_owasp_name(self, oid):
        if oid in OWASP_TOP_10:
            return OWASP_TOP_10[oid]["name"]
        if oid in EXTRA_CHECKS:
            return EXTRA_CHECKS[oid]["name"]
        return "Custom Check"

    def summary(self):
        """Final summary dikhao"""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in self.vulns:
            counts[v["severity"]] = counts.get(v["severity"], 0) + 1

        print(f"\n  {C.GR}{'═'*65}{C.E}")
        print(f"  {C.BO}{C.R}⚡ VULNERABILITY SUMMARY{C.E}")
        print(f"  {C.GR}{'─'*65}{C.E}")
        print(f"  {C.BG_R}{C.W} CRITICAL : {counts['CRITICAL']} {C.E}")
        print(f"  {C.R} HIGH     : {counts['HIGH']} {C.E}")
        print(f"  {C.Y} MEDIUM   : {counts['MEDIUM']} {C.E}")
        print(f"  {C.CY} LOW      : {counts['LOW']} {C.E}")
        print(f"  {C.GR} INFO     : {counts['INFO']} {C.E}")
        print(f"  {C.GR}{'─'*65}{C.E}")
        print(f"  {C.BO} TOTAL    : {len(self.vulns)} vulnerabilities found{C.E}")
        print(f"  {C.GR}{'═'*65}{C.E}")

        # OWASP category breakdown
        print(f"\n  {C.BO}{C.CY}📊 OWASP Category Breakdown:{C.E}")
        cats = {}
        for v in self.vulns:
            oid = v["owasp_id"]
            name = self._get_owasp_name(oid)
            if name not in cats:
                cats[name] = 0
            cats[name] += 1
        for name, count in sorted(cats.items(), key=lambda x: -x[1]):
            print(f"    {C.Y}▸ {name}: {count} issue(s){C.E}")

    def save(self):
        """JSON report save karo"""
        os.makedirs("reports", exist_ok=True)
        domain = self.target.replace("https://","").replace("http://","").split("/")[0]
        fname = f"reports/zerostrike_{domain}_{self.ts}.json"
        with open(fname, "w") as f:
            json.dump({
                "framework": "ZeroStrike v2.0",
                "target": self.target,
                "timestamp": self.ts,
                "total_vulnerabilities": len(self.vulns),
                "vulnerabilities": self.vulns
            }, f, indent=4)
        print(f"\n  {C.G}[✓] Report saved: {fname}{C.E}")
