import os
import sys
import subprocess
import xml.etree.ElementTree as ET
import argparse
from datetime import datetime

def setup_output_dir(scan_type="out_scan"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_out_dir = os.path.abspath(os.path.join(script_dir, "output", "Individual_Scan", scan_type))
    os.makedirs(base_out_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(base_out_dir, f"results_{timestamp}")
    os.makedirs(out_dir, exist_ok=True)
    try:
        os.chmod(out_dir, 0o777)
    except:
        pass
    return out_dir

ASSESSMENT_FOCUS = [
    "CVE Discovery", 
    "Default Credential Detection", 
    "Insecure Service Configurations", 
    "Vulnerability Scripting Engine (NSE) Probing"
]

def log(msg, level="INFO"):
    colors = {
        "INFO": "\033[94m",   # Blue
        "SUCCESS": "\033[92m",# Green
        "WARN": "\033[93m",   # Yellow
        "ERROR": "\033[91m",  # Red
        "RESET": "\033[0m"    # Reset
    }
    color = colors.get(level, colors["INFO"])
    print(f"{color}[{level}] {msg}{colors['RESET']}")

def run_nmap(out_dir, target, max_hours, exclude_ips=None):
    host_timeout = int(max_hours * 60)
    log(f"Starting Phased Controlled Nmap Loop against: {target} (Max timeout: {host_timeout}m per host)...", "INFO")
    if exclude_ips:
        log(f"Excluding IPs: {exclude_ips}", "WARN")
    
    vuln_report = os.path.join(out_dir, "nmap_vulnerability_report.txt")
    
    try:
        with open(vuln_report, "w") as f_out:
            f_out.write("==========================================================\n")
            f_out.write("             NMAP CONTROLLED LOOP RAW OUTPUT              \n")
            f_out.write("==========================================================\n\n")
            f_out.flush()
            
            # PHASE 1: Host Discovery
            log("Phase 1/3: Running Ping Sweep Discovery...", "INFO")
            discover_cmd = ["nmap", "-sn", "-T4", "-oG", "-", target]
            if exclude_ips:
                discover_cmd.extend(["--exclude", exclude_ips])
                
            proc_discover = subprocess.run(discover_cmd, capture_output=True, text=True)
            live_hosts = []
            for line in proc_discover.stdout.split('\n'):
                if "Status: Up" in line:
                    parts = line.split()
                    if len(parts) > 1 and parts[0] == "Host:":
                        live_hosts.append(parts[1])
                        
            f_out.write(f"--- PHASE 1: HOST DISCOVERY ---\nDiscovered {len(live_hosts)} live hosts on the network.\n\n")
            f_out.flush()
            
            if not live_hosts:
                log("No live hosts discovered! Scan aborted.", "ERROR")
                f_out.write("No live external/internal hosts visibly discovered. Aborting.\n")
                return
                
            log(f"Discovered {len(live_hosts)} live target(s). Proceeding to safe scan.", "SUCCESS")
            
            # PHASE 2: Service & Safe Scan
            log("Phase 2/3: Running Targeted Service & Safe Scan...", "INFO")
            f_out.write("--- PHASE 2: SERVICE & SAFE SCAN ---\n")
            f_out.flush()
            
            safe_cmd = ["nmap", "-T3", "-sV", "-sC", "-Pn", f"--host-timeout={host_timeout}m"] + live_hosts
            subprocess.run(safe_cmd, stdout=f_out, stderr=subprocess.STDOUT)
            
            # PHASE 3: Isolated Vulnerability Loop
            log(f"Phase 3/3: Running Isolated Vulnerability Loop on {len(live_hosts)} hosts...", "INFO")
            f_out.write("\n\n--- PHASE 3: ISOLATED VULNERABILITY LOOP ---\n")
            f_out.flush()
            
            for ip in live_hosts:
                log(f"Scanning deep vulnerabilities exclusively on {ip}...", "INFO")
                f_out.write(f"\n>>>> VULN SCAN: {ip} <<<<\n")
                f_out.flush()
                
                vuln_cmd = ["nmap", "-T3", "--script", "vuln", "-Pn", f"--host-timeout={host_timeout}m", ip]
                try:
                    subprocess.run(vuln_cmd, stdout=f_out, stderr=subprocess.STDOUT)
                except Exception as e:
                    f_out.write(f"CRITICAL ERROR looping {ip}: {e}\n")
                    f_out.flush()
                    
        log(f"Controlled Loop Completed! Raw output successfully appended to: {vuln_report}", "SUCCESS")
            
    except FileNotFoundError:
        log("Nmap is not installed. Skipping step.", "ERROR")
    except Exception as e:
        log(f"Error executing Nmap loop: {e}", "ERROR")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Nmap vulnerability scan.")
    parser.add_argument("--out-dir", required=False, help="Output directory (auto-generated if not provided)")
    parser.add_argument("--target", required=False, help="Target IP or CIDR")
    parser.add_argument("--exclude", required=False, help="IPs to exclude (comma separated)")
    parser.add_argument("--max-hours", type=float, required=False, help="Max duration in hours per host timeout")
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        print("\n--- Nmap Vulnerability Scan (Interactive Mode) ---")
        val = input("Enter target IP or CIDR for Nmap (e.g., 192.168.1.0/24) [default: 192.168.1.0/24]: ").strip()
        args.target = val if val else "192.168.1.0/24"
        
        excl = input("Enter any IPs to exclude (e.g., 192.168.1.112) or leave blank: ").strip()
        args.exclude = excl if excl else None
        
        try:
            val2 = input("Enter maximum hours of monitoring for Nmap scan [default: 1.0]: ").strip()
            args.max_hours = float(val2) if val2 else 1.0
        except ValueError:
            args.max_hours = 1.0
            log("Invalid input, defaulting to 1.0 hours.", "WARN")
    else:
        if not args.target:
            parser.error("--target is required when using command-line arguments.")
        if args.max_hours is None:
            args.max_hours = 1.0
            
    if not args.out_dir:
        args.out_dir = setup_output_dir(scan_type="out_wifi_nmap")
    else:
        os.makedirs(args.out_dir, exist_ok=True)
        
    run_nmap(args.out_dir, args.target, args.max_hours, args.exclude)
