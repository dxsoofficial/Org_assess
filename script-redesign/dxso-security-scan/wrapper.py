import os
import subprocess
import argparse
import datetime
import sys
import getpass
from pathlib import Path

# Lock Execution to Script Directory (Fixes relative path generation for dxso_reports)
script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)

# DXSO Security Assessment - Wrapper Script
# Executes the 7 distinct phase scripts sequentially or individually

PHASES = {
    1: "phase1_network_discovery.py",
    2: "phase2_endpoint_audit.py",
    3: "phase3_wireless_assessment.py",
    4: "phase4_traffic_analysis.py",
    6: "phase6_email_security.py",
    7: "phase7_vulnerability_scan.py"
}

def verify_scripts():
    print("[*] Verifying all phase scripts exist...")
    missing = []
    for num, script in PHASES.items():
        if not os.path.exists(script):
            missing.append(script)
    if missing:
        print("[!] Error: The following scripts are missing in the current directory:")
        for m in missing:
            print(f"    - {m}")
        sys.exit(1)
    print("[+] All phase scripts are present.\n")

def get_live_ips_from_phase1():
    base_dir = Path("dxso_reports/1_Network_Discovery")
    if not base_dir.exists():
        return []
    
    ips = []
    # Traverse reports to find collated IP lists
    for root, dirs, files in os.walk(base_dir):
        if "collated_live_hosts.txt" in files:
            with open(os.path.join(root, "collated_live_hosts.txt"), "r") as f:
                for line in f:
                    line = line.strip()
                    # Skip headers and empty lines
                    if line and not line.startswith("=") and not line.startswith("Target") and not line.startswith("Total") and not line.startswith("Tools"):
                        ips.append(line)
    return list(set(ips))

def run_script(script_name, args=None):
    cmd = [sys.executable, script_name]
    if args:
        cmd.extend(args)
    try:
        print(f"[*] Running {script_name}...")
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Warning: {script_name} exited with status {e.returncode}")
        
def main():
    parser = argparse.ArgumentParser(description="DXSO Security Assessment Wrapper")
    parser.add_argument("--all", action="store_true", help="Run all 7 phases")
    parser.add_argument("--phase", type=int, choices=range(1, 8), help="Run a specific phase (1-7)")
    
    # Phase 1 & General Network Args
    parser.add_argument("-t", "--target", help="Target subnet for Phase 1 (e.g., 192.168.1.0/24)")
    
    # Phase 2 Args
    parser.add_argument("--ips", help="Comma-separated list of target IPs for Phase 2")
    parser.add_argument("-u", "--user", help="Admin username for Phase 2")
    parser.add_argument("-p", "--password", help="Admin password for Phase 2")
    
    # Phase 3 Args
    parser.add_argument("-i", "--interface", help="Network/Wireless interface for Phases 3 & 4 (e.g., wlan0)")
    parser.add_argument("-g", "--gateway", help="Router/Gateway IP for Phase 3 Authenticated Checks")

    # Phases 6 & 7 Args
    parser.add_argument("-d", "--domain", help="Company domain for Email/Phishing scans in Phase 6 (e.g., company.com)")
    parser.add_argument("--url", help="Target internal IP or URL for Phase 7 Vuln Scans")

    args = parser.parse_args()
    
    phases_to_run = []
    
    if args.all:
        phases_to_run = list(PHASES.keys())
    elif args.phase:
        phases_to_run = [args.phase]
    else:
        # Interactive Mode Fallback
        print("\n=== DXSO Security Assessment Orchestrator ===")
        print("Available Modules:")
        for num, path in PHASES.items():
            name = path.replace('.py', '').replace('phase' + str(num) + '_', '').replace('_', ' ').title()
            print(f"  [{num}] - {name}")
        print("  [A] - Run ALL modules")
        
        choice = input("\nEnter modules to run (comma-separated, e.g., 1,2,7 or A for all): ").strip().upper()
        if not choice:
            print("    [!] No selection made. Exiting.")
            sys.exit(0)
            
        if choice == 'A':
            phases_to_run = list(PHASES.keys())
        else:
            try:
                # Parse comma-separated string into integers
                selected = [int(x.strip()) for x in choice.split(',')]
                for p in selected:
                    if p in PHASES.keys():
                        phases_to_run.append(p)
                    else:
                        print(f"    [!] Warning: Phase {p} is not a valid module. Skipping.")
            except ValueError:
                print("    [!] Invalid input. Please enter comma-separated numbers (e.g., 1,2,3).")
                sys.exit(1)
                
        if not phases_to_run:
            print("    [!] No valid modules selected to run. Exiting.")
            sys.exit(0)

    # Sort to ensure sequential execution
    phases_to_run.sort()

    verify_scripts()
    
    print("=" * 50)
    print(f"DXSO Security Assessment Sequence Started @ {datetime.datetime.now()}")
    print("=" * 50)

    for p in phases_to_run:
        script = PHASES[p]
        script_args = []
        
        if p == 1:
            if args.target:
                script_args.extend(["-t", args.target])
            # If no target provided, it will rely on the new auto-discovery logic
            
        elif p == 2:
            target_ips = args.ips
            if not target_ips:
                auto_ips = get_live_ips_from_phase1()
                if auto_ips:
                    target_ips = ",".join(auto_ips)
                    print(f"[*] Phase 2 Auto-Loaded {len(auto_ips)} IPs from Phase 1.")
                else:
                    print("[!] Skipping Phase 2: Missing --ips argument and no Phase 1 results found.")
                    continue
                
            user_arg = args.user or input("Enter Admin Username for Phase 2: ")
            pass_arg = args.password or getpass.getpass("Enter Admin Password for Phase 2: ")
            
            script_args.extend(["--ips", target_ips, "-u", user_arg, "-p", pass_arg])
            run_script(script, script_args)
            
        elif p == 3:
            if args.interface:
                script_args.extend(["-i", args.interface])
            if args.gateway:
                script_args.extend(["-g", args.gateway])
            
            run_script(script, script_args)
            
        elif p == 4:
            if not args.interface:
                print("[!] Skipping Phase 4: Missing --interface argument")
                continue
            script_args.extend(["-i", args.interface])
            run_script(script, script_args)

        elif p == 6:
            if not args.domain:
                print("[!] Skipping Phase 6: Missing --domain argument")
                continue
            script_args.extend(["-d", args.domain])
            run_script(script, script_args)

        elif p == 7:
            targets = []
            if args.url:
                targets = args.url.split(",")
            else:
                targets = get_live_ips_from_phase1()
                if targets:
                    print(f"[*] Phase 7 Auto-Loaded {len(targets)} targets from Phase 1.")
                else:
                    print("[!] Skipping Phase 7: Missing --url argument and no Phase 1 results found.")
                    continue
            
            # Phase 7 attacks targets individually, so we loop the run_script for each Target IP
            for target in targets:
                print(f"\n[>>>] Triggering Phase 7 Exploit Chain against: {target}")
                run_script(script, ["--url", target])
            
        print("-" * 50)

    print("\n[+] DXSO Assessment Sequence Completed.")

if __name__ == "__main__":
    main()
