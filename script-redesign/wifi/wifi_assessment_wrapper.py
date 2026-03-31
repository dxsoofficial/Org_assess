import os
import sys
import time
import subprocess
from datetime import datetime

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

def setup_output_dir(org_name):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_out_dir = os.path.abspath(os.path.join(script_dir, "output", org_name, "out_wifi"))
    os.makedirs(base_out_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(base_out_dir, f"assessment_results_{timestamp}")
    try:
        os.makedirs(out_dir, exist_ok=True)
        os.chmod(out_dir, 0o777)
        log(f"Created output directory: {out_dir}", "SUCCESS")
        return out_dir
    except Exception as e:
        log(f"Failed to create directory '{out_dir}': {e}", "ERROR")
        sys.exit(1)

def check_monitor_interface():
    log("Checking for monitor mode interfaces...", "INFO")
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        current_iface = None
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line.startswith("Interface"):
                current_iface = line.split()[1]
            elif "type monitor" in line and current_iface:
                log(f"Detected monitor mode interface: {current_iface}", "SUCCESS")
                return current_iface
                
        log("No monitor mode interface detected.", "WARN")
        return None
    except FileNotFoundError:
        log("'iw' command not found. Cannot determine interface mode.", "ERROR")
        return None
    except Exception as e:
        log(f"Error checking interfaces: {e}", "ERROR")
        return None

def aggregate_reports(out_dir):
    master_report = os.path.join(out_dir, "master_vulnerability_report.txt")
    reports_to_merge = [
        "kismet_vulnerability_report.txt",
        "tshark_vulnerability_report.txt",
        "nmap_vulnerability_report.txt"
    ]
    
    log("Aggregating individual vulnerability reports...", "INFO")
    
    with open(master_report, "w") as master:
        master.write("==========================================================\n")
        master.write("           MASTER WI-FI VULNERABILITY ASSESSMENT          \n")
        master.write("==========================================================\n\n")
        
        for rep_name in reports_to_merge:
            rep_path = os.path.join(out_dir, rep_name)
            if os.path.exists(rep_path):
                master.write(f"--- Included from: {rep_name} ---\n")
                with open(rep_path, "r") as f:
                    master.write(f.read())
                master.write("\n\n")
                
        # The Required Final One-Line Answer
        master.write("==========================================================\n")
        master.write("FINAL CONCLUSION:\n")
        master.write("The script must integrate WiFi discovery, encryption and authentication analysis, traffic inspection, network exposure scanning, and convert all findings into validated security vulnerabilities with severity classification.\n")
        master.write("==========================================================\n")
        
    log(f"Master Vulnerability Report generated at: {master_report}", "SUCCESS")
    
    # Also print the conclusion to the console as requested
    print("\n" + "="*58)
    print("FINAL CONCLUSION:")
    print("The script must integrate WiFi discovery, encryption and authentication analysis, traffic inspection, network exposure scanning, and convert all findings into validated security vulnerabilities with severity classification.")
    print("="*58 + "\n")

def main():
    print("==========================================================")
    print("        Wi-Fi & Network Security Assessment Wrapper       ")
    print("==========================================================")
    
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        log("WARNING: This script typically must be run as root (sudo).", "WARN")
        time.sleep(2)
        
    try:
        org_name = input("\nEnter the organization name in which the assessment is performed: ").strip().replace(" ", "_")
        if not org_name:
            org_name = "Unknown_Org"
            
        target = input("\nEnter target IP or CIDR for Nmap (e.g., 192.168.1.0/24) [default: 192.168.1.0/24]: ").strip()
        if not target:
            target = "192.168.1.0/24"
            log(f"No target provided, defaulting to {target}", "INFO")
            
        exclude_ips = input("\nEnter any IPs to exclude from Nmap (e.g., 192.168.1.112) [Leave blank for none]: ").strip()

        # Get monitoring hours
        try:
            kismet_hours = float(input("\nEnter hours of monitoring for Kismet [default: 0.1]: ").strip() or 0.1)
        except ValueError:
            kismet_hours = 0.1
            log("Invalid input, defaulting to 0.1 hours.", "WARN")
            
        try:
            tshark_hours = float(input("\nEnter hours of monitoring for TShark [default: 0.1]: ").strip() or 0.1)
        except ValueError:
            tshark_hours = 0.1
            log("Invalid input, defaulting to 0.1 hours.", "WARN")
            
        try:
            nmap_hours = float(input("\nEnter maximum hours of monitoring for Nmap scan [default: 1.0]: ").strip() or 1.0)
        except ValueError:
            nmap_hours = 1.0
            log("Invalid input, defaulting to 1.0 hours.", "WARN")

        out_dir = setup_output_dir(org_name)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Phase 1: Wi-Fi Scans
        print("\n--- Phase 1: Wi-Fi Assessment ---")
        monitor_interface = check_monitor_interface()
        
        if monitor_interface:
            kismet_script = os.path.join(script_dir, "kismet_scan.py")
            if os.path.exists(kismet_script):
                subprocess.run([sys.executable, kismet_script, "--out-dir", out_dir, "--interface", monitor_interface, "--duration-hours", str(kismet_hours)])
            else:
                log("kismet_scan.py not found.", "ERROR")
                
            tshark_script = os.path.join(script_dir, "tshark_scan.py")
            if os.path.exists(tshark_script):
                subprocess.run([sys.executable, tshark_script, "--out-dir", out_dir, "--interface", monitor_interface, "--duration-hours", str(tshark_hours)])
            else:
                log("tshark_scan.py not found.", "ERROR")
        else:
            log("Skipping Wi-Fi assessment (Kismet/TShark). No monitor mode interface found.", "WARN")
            log("Hint: Use 'sudo airmon-ng start <interface>' to put a card into monitor mode.", "INFO")
            
        # Phase 2: Internal/Network Scans
        print("\n--- Phase 2: Network Assessment ---")
        nmap_script = os.path.join(script_dir, "nmap_scan.py")
        if os.path.exists(nmap_script):
            nmap_cmd = [sys.executable, nmap_script, "--out-dir", out_dir, "--target", target, "--max-hours", str(nmap_hours)]
            if exclude_ips:
                nmap_cmd.extend(["--exclude", exclude_ips])
            subprocess.run(nmap_cmd)
        else:
            log("nmap_scan.py not found.", "ERROR")
        
        print("\n--- Phase 3: Vulnerability Aggregation ---")
        aggregate_reports(out_dir)
        
        print("\n==========================================================")
        log(f"Assessment complete! Results are stored in '{os.path.abspath(out_dir)}'", "SUCCESS")
        
    except KeyboardInterrupt:
        print("\n")
        log("Assessment forcefully interrupted by user. Exiting...", "WARN")
        sys.exit(0)

if __name__ == "__main__":
    main()
