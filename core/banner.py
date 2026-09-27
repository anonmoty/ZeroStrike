# core/banner.py
import sys, time, random, os, shutil
from core.colors import C

def show():
    os.system("clear" if os.name != "nt" else "cls")
    cols, _ = shutil.get_terminal_size((80, 24))

    # Matrix rain 2 sec
    chars = "01{}[]<>|=+-*&^%$#@!░▓█☠💀"
    sys.stdout.write("\033[?25l")
    end = time.time() + 2
    while time.time() < end:
        for _ in range(15):
            line = "".join(random.choice(chars) if random.random() > 0.5 else " " for _ in range(cols))
            c = C.R if random.random() > 0.5 else C.G
            sys.stdout.write(f"\r{c}{line}{C.E}")
            sys.stdout.flush()
            time.sleep(0.04)
    sys.stdout.write("\033[?25h")
    os.system("clear" if os.name != "nt" else "cls")

    print(f"""
{C.R}  ███████╗███████╗██████╗  ██████╗ {C.CY}███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
{C.R}  ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗{C.CY}██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
{C.R}    ███╔╝ █████╗  ██████╔╝██║   ██║{C.CY}███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
{C.R}   ███╔╝  ██╔══╝  ██╔══██╗██║   ██║{C.CY}╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
{C.R}  ███████╗███████╗██║  ██║╚██████╔╝{C.CY}███████║   ██║   ██║  ██║██║██║  ██╗███████╗
{C.R}  ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ {C.CY}╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝""")

    for t in [
        f"  {C.R}[+] ZeroStrike v2.0 | OWASP Top 10 Vulnerability Detector{C.E}",
        f"  {C.G}[+] Passive Scan Only | No Exploitation | Detection + Report{C.E}",
        f"  {C.CY}[+] 15 Audit Modules | Full OWASP Coverage{C.E}"
    ]:
        for c in t: sys.stdout.write(c); sys.stdout.flush(); time.sleep(0.015)
        print()
    print(f"\n  {C.GR}{'═'*68}{C.E}\n")
