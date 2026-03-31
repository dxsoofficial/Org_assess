import os
import argparse
from pathlib import Path

def run_browser_security(output_dir="dxso_reports/5_Browser_Security"):
    os.makedirs(output_dir, exist_ok=True)
    print("\n=== PHASE 5: Internet & Browser Security ===")
    print("[*] Analyzing browser configurations across endpoints.")
    print("[*] In an active implementation, PowerShell scripts will extract proxy configs.")
    print("    e.g. Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | Select-Object ProxyServer, ProxyEnable")
    print(f"[+] Phase 5 expected results in {output_dir}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 5: Internet & Browser Security")
    args = parser.parse_args()
    
    run_browser_security()
