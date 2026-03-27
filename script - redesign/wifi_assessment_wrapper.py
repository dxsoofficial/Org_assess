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
    base_out_dir = os.path.abspath(os.path.join(script_dir, "..", "output", org_name, "out_wifi"))
    os.makedirs(base_out_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(base_out_dir, f"assessment_results_{timestamp}")
    try:
        os.makedirs(out_dir, exist_ok=True)
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
            subprocess.run([sys.executable, nmap_script, "--out-dir", out_dir, "--target", target, "--max-hours", str(nmap_hours)])
        else:
            log("nmap_scan.py not found.", "ERROR")
        
        print("\n==========================================================")
        log(f"Assessment complete! Results are stored in '{os.path.abspath(out_dir)}'", "SUCCESS")
        
    except KeyboardInterrupt:
        print("\n")
        log("Assessment forcefully interrupted by user. Exiting...", "WARN")
        sys.exit(0)

if __name__ == "__main__":
    main()
